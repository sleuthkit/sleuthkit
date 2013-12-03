/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

#include <string>
#include <sstream>
#include <string.h>

#include "TskAutoImpl.h"
#include "tsk/framework/services/TskServices.h"

#define TSK_SCHEMA_VER 1

TSKAutoImpl::TSKAutoImpl() : m_db(TskServices::Instance().getImgDB()), m_numFilesSeen(0)
{
    m_curFsId = 0;
    m_curVsId = 0;
    m_vsSeen = false;
    m_lastUpdateMsg = 0;

    setVolFilterFlags((TSK_VS_PART_FLAG_ENUM)(TSK_VS_PART_FLAG_ALLOC | TSK_VS_PART_FLAG_UNALLOC));
    setFileFilterFlags((TSK_FS_DIR_WALK_FLAG_ENUM)(TSK_FS_DIR_WALK_FLAG_ALLOC|TSK_FS_DIR_WALK_FLAG_UNALLOC));

    // add the version to the DB
    m_db.addToolInfo("Sleuth Kit", tsk_version_get_str()); 
}

TSKAutoImpl::~TSKAutoImpl()
{
}

uint8_t TSKAutoImpl::openImage(TSK_IMG_INFO *a_img_info)
{
    m_curFsId = 0;
    m_curVsId = 0;

    return TskAuto::openImageHandle(a_img_info);
}

void
 TSKAutoImpl::closeImage()
{
    TskAuto::closeImage();
}


/**
 * Main method to call for this class after image has been opened as it takes care of the transactions.
 */
uint8_t TSKAutoImpl::extractFiles() 
{
    m_db.begin();
    uint8_t retval = findFilesInImg();  
    commitAndSchedule();
    return retval;
}

/**
* Scan the image for file systems creating allocated volumes for file systems found
* and unallocated volumes for areas in the image that do not contain file systems.
* Will initially look for file system in first sect_count sectors. If a file system
* is found then it will continue to process the remainder of the image for other
* file systems.
* 
* @param sect_start Start looking for file systems starting at this sector.
* @param sect_count The initial number of sectors to scan for file systems.
* @return 0 on success, 1 on failure 
*/
uint8_t TSKAutoImpl::scanImgForFs(const uint64_t sect_start, const uint64_t sect_count)
{
    if (m_img_info == NULL)
    {
        LOGERROR(L"TSKAutoImpl::scanImgForFs - Image not open.");
        return 1;
    }

    LOGINFO(L"TSKAutoImpl::scanImgForFs - Starting file system scan.");

    // Initialize current offset to our starting byte location.
    TSK_OFF_T current_offset = sect_start * m_img_info->sector_size;

    TSK_OFF_T end_offset = current_offset + (sect_count * m_img_info->sector_size);

    // Last offset keeps track of byte location where we last saw file system
    // data. It gets initialized to our starting location.
    TSK_OFF_T last_offset = current_offset;

    while (current_offset < end_offset)
    {
        TSK_FS_INFO * fs_info;

        if ((fs_info = tsk_fs_open_img(m_img_info, 
                                       current_offset, 
                                       TSK_FS_TYPE_DETECT)) == NULL)
        {
            // We didn't find a file system so we move on to the next sector.
            current_offset += m_img_info->sector_size;
        }
        else
        {
            // We found a file system so we will continue to search for file
            // systems beyond the initial sectors.
            end_offset = m_img_info->size;

            // If there is a gap between the location of this file system and
            // where we last saw file system data, an unallocated volume entry
            // needs to be created for the gap.
            if (fs_info->offset > last_offset)
            {
                createDummyVolume(last_offset / m_img_info->sector_size,
                                  (fs_info->offset - last_offset) / m_img_info->sector_size,
                                  "Dummy volume for carving purposes",
                                  TSK_VS_PART_FLAG_UNALLOC);
            }

            /* The call to findFilesInFs will take care of creating a
             * dummy volume for the file system.*/
            /* errors encountered during this phase will have been
             * logged. */
            findFilesInFs(fs_info);

            // Move the current offset past the file system we just found.
            current_offset += ((fs_info->block_count + 1) * fs_info->block_size);

            // Update the last location we saw file system data.
            last_offset = current_offset;

            tsk_fs_close(fs_info);
        }
    }

    // Finally, create a dummy unallocated volume for the area between the
    // last offset and the end of the image.
   if (last_offset < m_img_info->size)
    {
        createDummyVolume(last_offset / m_img_info->sector_size,
            (m_img_info->size - last_offset) / m_img_info->sector_size,
            "Dummy volume for carving purposes",
            TSK_VS_PART_FLAG_UNALLOC);
    }

    LOGINFO(L"TSKAutoImpl::scanImgForFs - File system scan complete.");

    return 0;
}

TSK_FILTER_ENUM TSKAutoImpl::filterVol(const TSK_VS_PART_INFO * a_vsPart)
{
    // flag that this image has a volume system
    m_vsSeen = true;
    m_db.addVolumeInfo(a_vsPart);

    m_curVsId = a_vsPart->addr;

    std::wstringstream msg;
    msg << L"TSKAutoImpl::filterVol - Discovered " << a_vsPart->desc 
        << L" partition (sectors " << a_vsPart->start << L"-" 
        << ((a_vsPart->start + a_vsPart->len) - 1) << L")";
    LOGINFO(msg.str());

    // we only want to process the allocated volumes
    if ((a_vsPart->flags & TSK_VS_PART_FLAG_ALLOC) == 0)
        return TSK_FILTER_SKIP;

    return TSK_FILTER_CONT;
}


TSK_FILTER_ENUM TSKAutoImpl::filterFs(TSK_FS_INFO * a_fsInfo)
{
    // add a volume entry if there is no file system
    if (m_vsSeen == false) 
    {
        TSK_DADDR_T start_sect = a_fsInfo->offset / a_fsInfo->img_info->sector_size;
        TSK_DADDR_T end_sect = start_sect + 
            ((a_fsInfo->block_count * a_fsInfo->block_size) / a_fsInfo->img_info->sector_size);

        createDummyVolume(start_sect, (end_sect - start_sect) + 1,
                          "Dummy volume for file system",
                          TSK_VS_PART_FLAG_ALLOC);
    }

    m_curFsId++;
    m_db.addFsInfo(m_curVsId, m_curFsId, a_fsInfo);

    /* Process the root directory so that its contents are added to
     * the DB.  We won't see it during the dir_walk. */
    TSK_FS_FILE *fs_file = tsk_fs_file_open(a_fsInfo, NULL, "/");
    if (fs_file != NULL)
    {
        processFile(fs_file, "\\");
    }

    // make sure that flags are set to get all files -- we need this to
    // find parent directory
    setFileFilterFlags((TSK_FS_DIR_WALK_FLAG_ENUM)
        (TSK_FS_DIR_WALK_FLAG_ALLOC | TSK_FS_DIR_WALK_FLAG_UNALLOC));

    std::wstringstream msg;
    msg << L"TSKAutoImpl::filterFs - Discovered " << tsk_fs_type_toname(a_fsInfo->ftype) 
        << L" file system at offset " << a_fsInfo->offset << L" with Id : " << m_curFsId;
    LOGINFO(msg.str());

    return TSK_FILTER_CONT;
}

/* Insert the file data into the file table.
 * @returns OK on success, COR on error because of the data (and we should keep on processing more files), 
 * and ERR because of system error (and we shoudl proabably stop processing)
 */
TSK_RETVAL_ENUM TSKAutoImpl::insertFileData(TSK_FS_FILE * a_fsFile,
    const TSK_FS_ATTR * a_fsAttr, const char * a_path, uint64_t & fileId)
{
    int type = TSK_FS_ATTR_TYPE_NOT_FOUND;
    int idx = 0;
    fileId = 0;

    if (a_fsFile->name == NULL) {
        LOGERROR(L"TSKAutoImpl::insertFileData name value is NULL");
        return TSK_COR;
    }

    size_t attr_len = 0;
    if (a_fsAttr) {
        type = a_fsAttr->type;
        idx = a_fsAttr->id;
        if (a_fsAttr->name)
        {
            if ((a_fsAttr->type != TSK_FS_ATTR_TYPE_NTFS_IDXROOT) ||
                (strcmp(a_fsAttr->name, "$I30") != 0))
            {
                attr_len = strlen(a_fsAttr->name);
            }
        }
    }

    // clean up special characters in name before we insert
    size_t len = strlen(a_fsFile->name->name);
    char *name;
    size_t nlen = 2 * (len + attr_len);
    if ((name = (char *) malloc(nlen + 1)) == NULL)
    {
        LOGERROR(L"Error allocating memory");
        return TSK_ERR;
    }
    memset(name, 0, nlen+1);

    size_t j = 0;
    for (size_t i = 0; i < len && j < nlen; i++)
    {
        // ' is special in SQLite
        if (a_fsFile->name->name[i] == '\'')
        {
            name[j++] = '\'';
            name[j++] = '\'';
        }
        else
        {
            name[j++] = a_fsFile->name->name[i];
        }
    }

    // Add the attribute name
    if (attr_len > 0) {
        name[j++] = ':';

        for (unsigned i = 0; i < attr_len && j < nlen; i++) {
            // ' is special in SQLite
            if (a_fsAttr->name[i] == '\'')
            {
                name[j++] = '\'';
                name[j++] = '\'';
            }
            else
            {
                name[j++] = a_fsAttr->name[i];
            }
        }
    }

    int result = m_db.addFsFileInfo(m_curFsId, a_fsFile, name, type, idx, fileId, a_path);
    free(name);

    // Message was already logged
    if (result) {
        return TSK_COR;
    }
    
    Scheduler::task_struct task;
    task.task = Scheduler::FileAnalysis;
    task.id = fileId;
    m_filesToSchedule.push(task);

    return TSK_OK;
}


/* Based on the error handling design, we only return OK or STOP.  All
 * other errors have been handled, so we don't return ERROR to TSK. */
TSK_RETVAL_ENUM TSKAutoImpl::processFile(TSK_FS_FILE * a_fsFile, const char * a_path)
{
    // skip the . and .. dirs
    if (isDotDir(a_fsFile) == 1)
    {
        return TSK_OK;
    }

    TSK_RETVAL_ENUM retval;
    // process the attributes if there are more than 1
    if (tsk_fs_file_attr_getsize(a_fsFile) == 0)
    {
        uint64_t fileId;
        // If COR is returned, then keep on going. 
        if (insertFileData(a_fsFile, NULL, a_path, fileId) == TSK_ERR) {
            retval = TSK_STOP;
        }
        else {
            m_numFilesSeen++;
            retval = TSK_OK;
        }
    }
    else
    {
        retval = processAttributes(a_fsFile, a_path);
    }

    time_t timeNow = time(NULL);
    if ((timeNow - m_lastUpdateMsg) > 3600)
    {
        m_lastUpdateMsg = timeNow;
        std::wstringstream msg;
        msg << L"TSKAutoImpl::processFile : Processed " << m_numFilesSeen << " files.";
        LOGINFO(msg.str());
    }

    if (m_filesToSchedule.size() > m_numOfFilesToQueue) {
        commitAndSchedule();
        m_db.begin();
    }

    return retval;
}

/**
 * commits the open transaction and schedules the files that
 * were queued up as being part of that transaction.
 * Does not create a new transaction.
 */
void TSKAutoImpl::commitAndSchedule()
{
    m_db.commit();

    while (m_filesToSchedule.size() > 0) {
        Scheduler::task_struct &task = m_filesToSchedule.front();
        if (TskServices::Instance().getScheduler().schedule(task)) {
            LOGERROR(L"Error adding file for scheduling");
        }
        m_filesToSchedule.pop();
    }
}

uint8_t TSKAutoImpl::handleError()
{
    const char * tskMsg = tsk_error_get();

    // @@@ Possibly test tsk_errno to determine how the message should be logged.
    if (tskMsg != NULL)
    {
        std::wstringstream msg;
        msg << L"TskAutoImpl::handleError " << tsk_error_get();

        LOGWARN(msg.str());
    }
    return 0;
}



/* Based on the error handling design, we only return OK or STOP.  All
 * other errors have been handled, so we don't return ERROR to TSK. */
TSK_RETVAL_ENUM TSKAutoImpl::processAttribute(TSK_FS_FILE * a_fsFile,
    const TSK_FS_ATTR * a_fsAttr, const char * a_path)
{
    uint64_t mFileId = 0;

    // add the file metadata for the default attribute type
    if (isDefaultType(a_fsFile, a_fsAttr))
    {
        // if COR is returned, then keep on going.
        if (insertFileData(a_fsAttr->fs_file, a_fsAttr, a_path, mFileId) == TSK_ERR)
            return TSK_STOP;
    }

    // add the block map, if the file is non-resident
    if (isNonResident(a_fsAttr))
    {
        TSK_FS_ATTR_RUN *run;
        int count = 0;
        for (run = a_fsAttr->nrd.run; run != NULL; run = run->next)
        {
            // ignore sparse blocks
            if (run->flags & TSK_FS_ATTR_RUN_FLAG_SPARSE)
                continue;
            
            if (m_db.addFsBlockInfo(m_curFsId, mFileId, count++, run->addr, run->len))
            {
                // this error should have been logged.
                // we'll continue to try processing the file
            }
        }
    }
     
    return TSK_OK;
}

void TSKAutoImpl::createDummyVolume(const TSK_DADDR_T sect_start, const TSK_DADDR_T sect_len, 
                                    const char * desc, TSK_VS_PART_FLAG_ENUM flags)
{
    m_curVsId++;

    TSK_VS_PART_INFO part;
    part.addr = m_curVsId;
    part.len = sect_len;
    part.start = sect_start;
    part.flags = flags;
    part.desc = (char *)desc; // remove the cast when TSK_VS_PART_INFO.desc is const char *

    if (m_db.addVolumeInfo(&part))
    {
        LOGERROR(L"TSKAutoImpl::createDummyVolume - Error creating volume.");
    }
}
