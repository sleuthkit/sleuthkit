/*
 ** The Sleuth Kit 
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2010 Brian Carrier.  All Rights reserved
 **
 ** This software is distributed under the Common Public License 1.0
 **
 */
#include "tsk_auto.h"
#include "sqlite3.h"

#define TSK_SCHEMA_VER 1

TskAutoDb::TskAutoDb()
{
    m_db = NULL;
    m_curFsId = 0;
    m_curVsId = 0;
}

TskAutoDb::~TskAutoDb()
{
    
}


uint8_t 
TskAutoDb::openImage(int num, const TSK_TCHAR * const images[],
                          TSK_IMG_TYPE_ENUM type, unsigned int a_ssize)
{
    char foo[1024];
    
    uint8_t retval = TskAuto::openImage(num, images, type, a_ssize);
    // open the DB
    if (retval != 0) {
        return retval;
    }
    
    if (m_db) {
        sqlite3_close(m_db);
        m_db = NULL;
    }
    
#if TSK_WIN32
    CONVERT to UTF-8
#else
    snprintf(foo, 1024, "%s.db", images[0]);
#endif
    // @@@ TEST IF IT EXISTS...
    
    if (sqlite3_open(foo, &m_db)) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(m_db));
        sqlite3_close(m_db);
        return 1;
    }
    
    char *errmsg;
    if (sqlite3_exec(m_db, "CREATE TABLE tsk_db_info (schema_ver INTEGER, tsk_ver INTEGER);", NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "Error creating tsk_db_info table: %s\n", errmsg);
        sqlite3_free(errmsg);
        return 1;
    }
    
    snprintf(foo, 1024, "INSERT INTO tsk_db_info (schema_ver, tsk_ver) VALUES (%d, %d);", TSK_SCHEMA_VER, TSK_VERSION_NUM);
    if (sqlite3_exec(m_db, foo, NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "Error adding data to tsk_db_info table: %s\n", errmsg);
        sqlite3_free(errmsg);
        return 1;
    }
    
    if (sqlite3_exec(m_db, "CREATE TABLE tsk_image_info (type INTEGER, ssize INTEGER);", NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "Error creating tsk_image_info table: %s\n", errmsg);
        sqlite3_free(errmsg);
        return 1;
    }
    
    snprintf(foo, 1024, "INSERT INTO tsk_image_info (type, ssize) VALUES (%d, %u);", (int)type, m_img_info->sector_size);
    if (sqlite3_exec(m_db, foo, NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "Error adding data to tsk_image_info table: %s\n", errmsg);
        sqlite3_free(errmsg);
        return 1;
    }
     
    if (sqlite3_exec(m_db, "CREATE TABLE tsk_image_names (name TEXT);", NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "Error creating tsk_image_names table: %s\n", errmsg);
        sqlite3_free(errmsg);
        return 1;
    }
    
    for (int i = 0; i < num; i++) {
        int a;
        for (a = strlen(images[i])-1; a > 0; a--) {
            if ((images[i][a] == '/') || (images[i][a] == '\\')) {
                a++;
                break;
            }
        }
        snprintf(foo, 1024, "INSERT INTO tsk_image_names (name) VALUES ('%s')", &images[i][a]);
        if (sqlite3_exec(m_db, foo, NULL, NULL, &errmsg) != SQLITE_OK) {
            fprintf(stderr, "Error adding data to tsk_image_names table: %s\n", errmsg);
            sqlite3_free(errmsg);
            return 1;
        }
    }
    
    
    if (sqlite3_exec(m_db, "CREATE TABLE tsk_vol_info (vol_id INTEGER PRIMARY KEY, start INTEGER NOT NULL, length INTEGER NOT NULL, desc TEXT, flags INTEGER);", NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "Error creating tsk_vol_info table: %s\n", errmsg);
        sqlite3_free(errmsg);
        return 1;
    }
    
    if (sqlite3_exec(m_db, "CREATE TABLE tsk_fs_info (fs_id INTEGER PRIMARY KEY, img_offset INTEGER, vol_id INTEGER NOT NULL, fs_type INTEGER, block_size INTEGER);", NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "Error creating tsk_fs_info table: %s\n", errmsg);
        sqlite3_free(errmsg);
        return 1;
    }
    
    if (sqlite3_exec(m_db, "CREATE TABLE tsk_fs_files (fs_id INTEGER NOT NULL, file_id INTEGER NOT NULL, name TEXT NOT NULL, par_file_id INTEGER, dir_type INTEGER, meta_type INTEGER, dir_flags INTEGER, meta_flags INTEGER, size INTEGER, ctime INTEGER, crtime INTEGER, atime INTEGER, mtime INTEGER, mode INTEGER);", NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "Error creating tsk_fs_files table: %s\n", errmsg);
        sqlite3_free(errmsg);
        return 1;
    }
    
    return 0;
}

void 
TskAutoDb::closeImage()
{
    TskAuto::closeImage();
    if (m_db) {
        sqlite3_close(m_db);
        m_db = NULL;
    }
}


uint8_t 
TskAutoDb::filterVol(const TSK_VS_PART_INFO * vs_part)
{
    char foo[1024];
    char *errmsg;
    
    snprintf(foo, 1024, "INSERT INTO tsk_vol_info (vol_id, start, length, desc, flags) VALUES (%d,%"PRIuOFF",%"PRIuOFF",'%s',%d)", 
             (int)vs_part->addr, vs_part->start, vs_part->len, vs_part->desc, vs_part->flags);
    
    if (sqlite3_exec(m_db, foo, NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "Error adding data to tsk_vol_info table: %s\n", errmsg);
        sqlite3_free(errmsg);
        return 1;
    }
    
    m_curVsId = vs_part->addr;
    
    return 0;
}


uint8_t
TskAutoDb::filterFs(TSK_FS_INFO * fs_info)
{
    char foo[1024];
    char *errmsg;

    m_curFsId++;

    snprintf(foo, 1024, "INSERT INTO tsk_fs_info (fs_id, img_offset, vol_id, fs_type, block_size) VALUES (%d,%"PRIuOFF",%d,'%d',%d)", 
             m_curFsId, fs_info->offset, m_curVsId, (int)fs_info->ftype, fs_info->block_size);
        
    if (sqlite3_exec(m_db, foo, NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "Error adding data to tsk_fs_info table: %s\n", errmsg);
        sqlite3_free(errmsg);
        return 1;
    }
    
    // make sure that flags are set to get all files -- we need this to find parent directory
    setFileFilterFlags((TSK_FS_DIR_WALK_FLAG_ENUM)(TSK_FS_DIR_WALK_FLAG_ALLOC | TSK_FS_DIR_WALK_FLAG_UNALLOC));
    
    return 0;
}


// TODO:
// - save root directory addr in fs_info
// - add logic to keep track of parent directory based on ".." entries
uint8_t 
TskAutoDb::processFile(TSK_FS_FILE * fs_file, const char *path)
{
    char foo[1024];
    char *errmsg;
    int mtime = 0;
    int crtime = 0;
    int ctime = 0;
    int atime = 0;
    TSK_OFF_T size = 0;
    int meta_type = 0;
    int meta_flags = 0;
    int meta_mode = 0;
    
    if (fs_file->name == NULL) 
        return 0;
    
    if (fs_file->meta) {
        mtime = fs_file->meta->mtime;
        atime = fs_file->meta->atime;
        ctime = fs_file->meta->ctime;
        crtime = fs_file->meta->crtime;
        size = fs_file->meta->size;
        meta_type = fs_file->meta->type;
        meta_flags = fs_file->meta->flags;
        meta_mode = fs_file->meta->mode;
    }
    
    
    // @@@ need par_file_id
    snprintf(foo, 1024, "INSERT INTO tsk_fs_files (fs_id, file_id, name, par_file_id, dir_type, meta_type, dir_flags, meta_flags, size, crtime, ctime, atime, mtime, mode) VALUES (%d,%"PRIuINUM",'%s',%"PRIuINUM",%d,%d,%d,%d,%"PRIuOFF",%d,%d,%d,%d,%d)", 
             m_curFsId, fs_file->name->meta_addr, fs_file->name->name, (TSK_INUM_T)0, fs_file->name->type, meta_type, fs_file->name->flags, meta_flags, size, crtime, ctime, atime, mtime, meta_mode);
    
    if (sqlite3_exec(m_db, foo, NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "Error adding data to tsk_fs_info table: %s\n", errmsg);
        sqlite3_free(errmsg);
        return 1;
    }
    
    return 0;
}
