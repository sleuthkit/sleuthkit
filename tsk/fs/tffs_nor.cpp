/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
**
** TASK
** Copyright (c) 2002-2003 Brian Carrier, @stake Inc.  All rights reserved
**
** Copyright (c) 1997,1998,1999, International Business Machines
** Corporation and others. All Rights Reserved.
*/

/**
*\file tffs_nor.cpp
* Contains the internal TSK TFFS NOR file system functions.
*/

/* TCT
* LICENSE
*	This software is distributed under the Common Public License version 1.0
* AUTHOR(S)
*	David Langsam
*	Hochschule Albstadt-Sigmaringen
*	Poststraße 6
*   72458 Albstadt
*   Deutschland
--*/


#include "tsk_fs_i.h"
#include "tsk_tffs_nor.h"
#include <algorithm>
#include <map>
#include <new>
#include <string>
#include <vector>

static const size_t TFFS_NOR_SCAN_BUFFER_SIZE = 64 * 1024;
static const size_t TFFS_NOR_MAX_ZERO_LENGTH_DELETED_RUN = 64;
static const size_t TFFS_NOR_MAX_ENTRY_COUNT = 1024 * 1024;

struct TFFS_NOR_ENTRY {
    TSK_OFF_T m_offset;
    TSK_OFF_T m_dataOffset;
    TSK_OFF_T m_paddedEnd;
    uint16_t m_fileId;
    uint16_t m_dataSize;
};

struct TFFS_NOR_STATE {
    std::vector<TFFS_NOR_ENTRY> m_entries;
    std::map<uint32_t, std::string> m_names;
    TSK_OFF_T m_usedBytes;
};

static TFFS_NOR_STATE *
tffsNorState(TSK_FS_INFO *a_fs)
{
    return (TFFS_NOR_STATE *)a_fs->impl;
}

static uint8_t
tffsNorError(uint32_t a_errno, const char *a_message)
{
    tsk_error_reset();
    tsk_error_set_errno(a_errno);
    tsk_error_set_errstr("tffs_nor: %s", a_message);
    return 1;
}

static uint8_t
tffsNorRead(TSK_FS_INFO *a_fs, TSK_OFF_T a_offset, void *a_buffer,
    size_t a_length)
{
    ssize_t bytesRead = tsk_img_read(a_fs->img_info,
        a_fs->offset + a_offset, (char *)a_buffer, a_length);
    if (bytesRead != (ssize_t)a_length)
        return tffsNorError(TSK_ERR_FS_READ, "could not read image data");
    return 0;
}

static uint8_t
tffsNorLoadNameTable(TSK_FS_INFO *a_fs, TFFS_NOR_STATE *a_state)
{
    for (size_t entryIndex = 0; entryIndex < a_state->m_entries.size();
        ++entryIndex) {
        const TFFS_NOR_ENTRY &entry = a_state->m_entries[entryIndex];
        if (entry.m_fileId != TFFS_NOR_NAME_TABLE_ID)
            continue;

        std::vector<uint8_t> data(entry.m_dataSize);
        if (entry.m_dataSize != 0 && tffsNorRead(a_fs, entry.m_dataOffset,
            data.data(), data.size()) != 0)
            return 1;

        a_state->m_names.clear();
        size_t cursor = 0;
        while (cursor + sizeof(uint32_t) <= data.size()) {
            uint32_t fileId = tsk_getu32(TSK_BIG_ENDIAN, &data[cursor]);
            cursor += sizeof(uint32_t);
            if (fileId == 0 || fileId == UINT32_MAX)
                break;

            size_t nameEnd = cursor;
            while (nameEnd < data.size() && data[nameEnd] != 0)
                ++nameEnd;
            if (nameEnd == data.size())
                break;

            if (fileId <= UINT16_MAX && nameEnd > cursor) {
                a_state->m_names[fileId] = std::string(
                    (const char *)&data[cursor], nameEnd - cursor);
            }
            cursor = (nameEnd + 1 + TFFS_NOR_ENTRY_ALIGNMENT - 1) &
                ~(TFFS_NOR_ENTRY_ALIGNMENT - 1);
        }
    }
    return 0;
}

static const TFFS_NOR_ENTRY *
tffsNorGetEntry(TSK_FS_INFO *a_fs, TSK_INUM_T a_addr)
{
    TFFS_NOR_STATE *state = tffsNorState(a_fs);
    if (state == NULL || a_addr == 0 || a_addr > state->m_entries.size())
        return NULL;
    return &state->m_entries[(size_t)a_addr - 1];
}

static std::string
tffsNorEntryName(const TFFS_NOR_STATE *a_state,
    const TFFS_NOR_ENTRY &a_entry, size_t a_index)
{
    if (a_entry.m_fileId == TFFS_NOR_DELETED_ID)
        return "deleted_" + std::to_string(a_entry.m_offset);
    if (a_entry.m_fileId == TFFS_NOR_NAME_TABLE_ID)
        return "$TFFS_NameTable";
    std::map<uint32_t, std::string>::const_iterator name =
        a_state->m_names.find(a_entry.m_fileId);
    if (name != a_state->m_names.end())
        return name->second;
    (void)a_index;
    return "file_" + std::to_string(a_entry.m_fileId);
}

static TSK_FS_BLOCK_FLAG_ENUM
tffsNorBlockGetFlags(TSK_FS_INFO *a_fs, TSK_DADDR_T a_addr)
{
    TFFS_NOR_STATE *state = tffsNorState(a_fs);
    if (state == NULL || a_addr >= a_fs->block_count)
        return (TSK_FS_BLOCK_FLAG_ENUM)0;

    TSK_OFF_T byteOffset = (TSK_OFF_T)a_addr * a_fs->block_size;
    std::vector<TFFS_NOR_ENTRY>::const_iterator entry =
        std::upper_bound(state->m_entries.begin(), state->m_entries.end(), byteOffset,
            [](TSK_OFF_T a_value, const TFFS_NOR_ENTRY &a_candidate) {
                return a_value < a_candidate.m_offset;
            });
    if (entry != state->m_entries.begin())
        --entry;
    else
        return (TSK_FS_BLOCK_FLAG_ENUM)(TSK_FS_BLOCK_FLAG_CONT |
            TSK_FS_BLOCK_FLAG_UNALLOC);

    if (byteOffset < entry->m_offset || byteOffset >= entry->m_paddedEnd)
        return (TSK_FS_BLOCK_FLAG_ENUM)(TSK_FS_BLOCK_FLAG_CONT |
            TSK_FS_BLOCK_FLAG_UNALLOC);

    TSK_FS_BLOCK_FLAG_ENUM allocFlag = entry->m_fileId == TFFS_NOR_DELETED_ID
        ? TSK_FS_BLOCK_FLAG_UNALLOC : TSK_FS_BLOCK_FLAG_ALLOC;
    TSK_FS_BLOCK_FLAG_ENUM typeFlag = byteOffset < entry->m_dataOffset
        ? TSK_FS_BLOCK_FLAG_META : TSK_FS_BLOCK_FLAG_CONT;
    return (TSK_FS_BLOCK_FLAG_ENUM)(allocFlag | typeFlag);
}

static uint8_t
tffsNorBlockWalk(TSK_FS_INFO *a_fs, TSK_DADDR_T a_start_blk,
    TSK_DADDR_T a_end_blk, TSK_FS_BLOCK_WALK_FLAG_ENUM a_flags,
    TSK_FS_BLOCK_WALK_CB a_callback, void *a_ptr)
{
    if (a_start_blk < a_fs->first_block || a_end_blk > a_fs->last_block ||
        a_end_blk < a_start_blk) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("tffsNorBlockWalk: invalid block range");
        return 1;
    }
    if ((a_flags & (TSK_FS_BLOCK_WALK_FLAG_ALLOC |
        TSK_FS_BLOCK_WALK_FLAG_UNALLOC)) == 0)
        a_flags = (TSK_FS_BLOCK_WALK_FLAG_ENUM)(a_flags |
            TSK_FS_BLOCK_WALK_FLAG_ALLOC | TSK_FS_BLOCK_WALK_FLAG_UNALLOC);
    if ((a_flags & (TSK_FS_BLOCK_WALK_FLAG_META |
        TSK_FS_BLOCK_WALK_FLAG_CONT)) == 0)
        a_flags = (TSK_FS_BLOCK_WALK_FLAG_ENUM)(a_flags |
            TSK_FS_BLOCK_WALK_FLAG_META | TSK_FS_BLOCK_WALK_FLAG_CONT);

    TSK_FS_BLOCK *fsBlock = tsk_fs_block_alloc(a_fs);
    if (fsBlock == NULL)
        return 1;
    for (TSK_DADDR_T addr = a_start_blk; addr <= a_end_blk; ++addr) {
        TSK_FS_BLOCK_FLAG_ENUM flags = tffsNorBlockGetFlags(a_fs, addr);
        if (((flags & TSK_FS_BLOCK_FLAG_ALLOC) != 0 &&
            (a_flags & TSK_FS_BLOCK_WALK_FLAG_ALLOC) == 0) ||
            ((flags & TSK_FS_BLOCK_FLAG_UNALLOC) != 0 &&
            (a_flags & TSK_FS_BLOCK_WALK_FLAG_UNALLOC) == 0) ||
            ((flags & TSK_FS_BLOCK_FLAG_META) != 0 &&
            (a_flags & TSK_FS_BLOCK_WALK_FLAG_META) == 0) ||
            ((flags & TSK_FS_BLOCK_FLAG_CONT) != 0 &&
            (a_flags & TSK_FS_BLOCK_WALK_FLAG_CONT) == 0))
            continue;

        if (tsk_fs_block_get_flag(a_fs, fsBlock, addr, flags) == NULL) {
            tsk_fs_block_free(fsBlock);
            return 1;
        }
        TSK_WALK_RET_ENUM result = a_callback(fsBlock, a_ptr);
        if (result == TSK_WALK_STOP)
            break;
        if (result == TSK_WALK_ERROR) {
            tsk_fs_block_free(fsBlock);
            return 1;
        }
    }
    tsk_fs_block_free(fsBlock);
    return 0;
}

static uint8_t
tffsNorFileAddMeta(TSK_FS_INFO *a_fs, TSK_FS_FILE *a_file,
    TSK_INUM_T a_addr)
{
    const TFFS_NOR_ENTRY *entry = tffsNorGetEntry(a_fs, a_addr);
    if (entry == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
        tsk_error_set_errstr("tffsNorFileAddMeta: invalid entry address");
        return 1;
    }
    if (a_file->meta == NULL) {
        a_file->meta = tsk_fs_meta_alloc(0);
        if (a_file->meta == NULL)
            return 1;
    }
    else {
        tsk_fs_meta_reset(a_file->meta);
    }

    TSK_FS_META *meta = a_file->meta;
    meta->addr = a_addr;
    meta->type = TSK_FS_META_TYPE_REG;
    meta->mode = TSK_FS_META_MODE_UNSPECIFIED;
    meta->nlink = 1;
    meta->size = entry->m_dataSize;
    meta->uid = 0;
    meta->gid = 0;
    meta->mtime = 0;
    meta->seq = entry->m_fileId;
    meta->flags = (TSK_FS_META_FLAG_ENUM)(TSK_FS_META_FLAG_USED |
        (entry->m_fileId == TFFS_NOR_DELETED_ID ? TSK_FS_META_FLAG_UNALLOC :
        TSK_FS_META_FLAG_ALLOC));
    meta->attr_state = TSK_FS_META_ATTR_EMPTY;
    return 0;
}

static TSK_FS_ATTR_TYPE_ENUM
tffsNorGetDefaultAttrType(const TSK_FS_FILE *)
{
    return TSK_FS_ATTR_TYPE_DEFAULT;
}

static uint8_t
tffsNorLoadAttrs(TSK_FS_FILE *a_file)
{
    if (a_file == NULL || a_file->fs_info == NULL || a_file->meta == NULL)
        return tffsNorError(TSK_ERR_FS_ARG, "invalid file handle");
    TSK_FS_META *meta = a_file->meta;
    if (meta->attr_state == TSK_FS_META_ATTR_STUDIED)
        return 0;
    if (meta->attr_state == TSK_FS_META_ATTR_ERROR)
        return 1;
    const TFFS_NOR_ENTRY *entry = tffsNorGetEntry(a_file->fs_info,
        meta->addr);
    if (entry == NULL)
        return tffsNorError(TSK_ERR_FS_INODE_NUM, "invalid entry address");

    if (meta->attr == NULL)
        meta->attr = tsk_fs_attrlist_alloc();
    else
        tsk_fs_attrlist_markunused(meta->attr);
    if (meta->attr == NULL)
        return 1;
    TSK_FS_ATTR *attr = tsk_fs_attrlist_getnew(meta->attr, TSK_FS_ATTR_RES);
    if (attr == NULL)
        return 1;

    std::vector<uint8_t> data(entry->m_dataSize);
    uint8_t emptyData = 0;
    if (entry->m_dataSize != 0 && tffsNorRead(a_file->fs_info,
        entry->m_dataOffset, data.data(), data.size()) != 0) {
        meta->attr_state = TSK_FS_META_ATTR_ERROR;
        return 1;
    }
    if (tsk_fs_attr_set_str(a_file, attr, NULL, TSK_FS_ATTR_TYPE_DEFAULT,
        TSK_FS_ATTR_ID_DEFAULT,
        entry->m_dataSize == 0 ? (void *)&emptyData : data.data(),
        entry->m_dataSize)) {
        meta->attr_state = TSK_FS_META_ATTR_ERROR;
        return 1;
    }
    meta->attr_state = TSK_FS_META_ATTR_STUDIED;
    return 0;
}

static TSK_RETVAL_ENUM
tffsNorDirOpenMeta(TSK_FS_INFO *a_fs, TSK_FS_DIR **a_fs_dir,
    TSK_INUM_T a_addr, int a_recursion_depth)
{
    (void)a_recursion_depth;
    if (a_fs == NULL || a_fs->tag != TSK_FS_INFO_TAG || a_fs_dir == NULL ||
        a_addr != a_fs->root_inum)
        return (TSK_RETVAL_ENUM)tffsNorError(TSK_ERR_FS_ARG,
            "invalid root directory request");
    TFFS_NOR_STATE *state = tffsNorState(a_fs);
    if (state == NULL)
        return (TSK_RETVAL_ENUM)tffsNorError(TSK_ERR_FS_CORRUPT,
            "missing parser state");

    TSK_FS_DIR *fsDir = *a_fs_dir;
    if (fsDir != NULL) {
        tsk_fs_dir_reset(fsDir);
        fsDir->addr = a_addr;
    }
    else if ((*a_fs_dir = fsDir = tsk_fs_dir_alloc(a_fs, a_addr, 128)) == NULL) {
        return TSK_ERR;
    }
    fsDir->fs_file = NULL;

    for (size_t index = 0; index < state->m_entries.size(); ++index) {
        const TFFS_NOR_ENTRY &entry = state->m_entries[index];
        if (entry.m_fileId == TFFS_NOR_NAME_TABLE_ID)
            continue;
        std::string name = tffsNorEntryName(state, entry, index);
        TSK_FS_NAME *fsName = tsk_fs_name_alloc(name.size() + 1, 0);
        if (fsName == NULL)
            return TSK_ERR;
        memcpy(fsName->name, name.c_str(), name.size() + 1);
        fsName->meta_addr = index + 1;
        fsName->par_addr = a_addr;
        fsName->type = TSK_FS_NAME_TYPE_REG;
        fsName->flags = entry.m_fileId == TFFS_NOR_DELETED_ID
            ? TSK_FS_NAME_FLAG_UNALLOC : TSK_FS_NAME_FLAG_ALLOC;
        if (tsk_fs_dir_add(fsDir, fsName)) {
            tsk_fs_name_free(fsName);
            return TSK_ERR;
        }
        tsk_fs_name_free(fsName);
    }
    return TSK_OK;
}

static uint8_t
tffsNorIstat(TSK_FS_INFO *a_fs, TSK_FS_ISTAT_FLAG_ENUM a_flags,
    FILE *a_file, TSK_INUM_T a_addr, TSK_DADDR_T a_numblock,
    int32_t a_sec_skew)
{
    (void)a_numblock;
    (void)a_sec_skew;
    if ((a_flags & ~TSK_FS_ISTAT_RUNLIST) != 0)
        return tffsNorError(TSK_ERR_FS_ARG, "unsupported istat flags");
    const TFFS_NOR_ENTRY *entry = tffsNorGetEntry(a_fs, a_addr);
    if (entry == NULL || a_file == NULL)
        return tffsNorError(TSK_ERR_FS_INODE_NUM, "invalid entry address");
    TFFS_NOR_STATE *state = tffsNorState(a_fs);
    std::string name = tffsNorEntryName(state, *entry, (size_t)a_addr - 1);
    tsk_fprintf(a_file, "NOR TFFS Entry: %" PRIuINUM "\n", a_addr);
    tsk_fprintf(a_file, "Name: %s\n", name.c_str());
    tsk_fprintf(a_file, "State: %s\n", entry->m_fileId == 0 ? "Deleted" : "Allocated");
    tsk_fprintf(a_file, "File ID: %u\n", entry->m_fileId);
    tsk_fprintf(a_file, "Data Size: %u bytes\n", entry->m_dataSize);
    tsk_fprintf(a_file, "Header Offset: %" PRIdOFF " bytes\n",
        a_fs->offset + entry->m_offset);
    tsk_fprintf(a_file, "Data Offset: %" PRIdOFF " bytes\n",
        a_fs->offset + entry->m_dataOffset);
    tsk_fprintf(a_file, "Padding: %" PRIdOFF " bytes\n",
        entry->m_paddedEnd - (entry->m_dataOffset + entry->m_dataSize));
    return 0;
}

static uint8_t
tffsNorFsstat(TSK_FS_INFO *a_fs, FILE *a_file)
{
    if (a_fs == NULL || a_fs->tag != TSK_FS_INFO_TAG || a_file == NULL)
        return tffsNorError(TSK_ERR_FS_ARG, "invalid fsstat arguments");
    TFFS_NOR_STATE *state = tffsNorState(a_fs);
    TSK_DADDR_T active = 0;
    TSK_DADDR_T deleted = 0;
    TSK_DADDR_T nameTables = 0;
    for (size_t index = 0; index < state->m_entries.size(); ++index) {
        uint16_t fileId = state->m_entries[index].m_fileId;
        if (fileId == TFFS_NOR_NAME_TABLE_ID)
            ++nameTables;
        else if (fileId == TFFS_NOR_DELETED_ID)
            ++deleted;
        else
            ++active;
    }
    const TSK_OFF_T imageSize = a_fs->img_info->size;
    const TFFS_NOR_ENTRY &lastEntry = state->m_entries.back();
    const TSK_OFF_T usedBytes = lastEntry.m_offset +
        TFFS_NOR_ENTRY_HEADER_SIZE + lastEntry.m_dataSize;
    tsk_fprintf(a_file, "FILE SYSTEM INFORMATION\n");
    tsk_fprintf(a_file, "File System Type: TFFS NOR\n");
    tsk_fprintf(a_file, "Image Offset: %" PRIdOFF " bytes\n", a_fs->offset);
    tsk_fprintf(a_file, "Image Size: %" PRIdOFF " bytes\n", imageSize);
    tsk_fprintf(a_file, "Used Bytes (last entry end): %" PRIdOFF " bytes\n",
        usedBytes);
    tsk_fprintf(a_file, "Unused Image Bytes: %" PRIdOFF "\n",
        a_fs->img_info->size - (a_fs->offset + state->m_usedBytes));
    tsk_fprintf(a_file, "Entry Count: %" PRIuSIZE "\n", state->m_entries.size());
    tsk_fprintf(a_file, "Active Files: %" PRIuDADDR "\n", active);
    tsk_fprintf(a_file, "Deleted Entries (ID=0): %" PRIuDADDR "\n", deleted);
    tsk_fprintf(a_file, "Name Table Entries (ID=511): %" PRIuDADDR "\n",
        nameTables);
    return 0;
}

static uint8_t
tffsNorFscheck(TSK_FS_INFO *, FILE *)
{
    return tffsNorError(TSK_ERR_FS_UNSUPFUNC, "fscheck is not implemented");
}

static void
tffsNorClose(TSK_FS_INFO *a_fs)
{
    if (a_fs == NULL)
        return;
    delete tffsNorState(a_fs);
    a_fs->impl = NULL;
    a_fs->tag = 0;
    tsk_fs_free(a_fs);
}

TSK_FS_INFO *
tffs_nor_open(TSK_IMG_INFO *a_img_info, TSK_OFF_T a_offset,
    TSK_FS_TYPE_ENUM a_ftype, const char *a_pass, uint8_t a_test)
{
    (void)a_pass;
    (void)a_test;
    if (a_img_info == NULL || a_offset < 0 || a_offset > a_img_info->size ||
        !TSK_FS_TYPE_ISTFFS(a_ftype) ||
        a_img_info->size - a_offset < TFFS_NOR_ENTRY_HEADER_SIZE) {
        tffsNorError(TSK_ERR_FS_ARG, "invalid image, byteOffset, or file system type");
        return NULL;
    }

    TSK_FS_INFO *fs = tsk_fs_malloc(sizeof(TSK_FS_INFO));
    TFFS_NOR_STATE *state = new (std::nothrow) TFFS_NOR_STATE();
    if (fs == NULL || state == NULL) {
        if (fs != NULL)
            tsk_fs_free(fs);
        delete state;
        return NULL;
    }

    const TSK_OFF_T imageBytes = a_img_info->size - a_offset;
    const size_t maxEntryCount = (size_t)std::min<TSK_OFF_T>(
        imageBytes / TFFS_NOR_ENTRY_HEADER_SIZE,
        (TSK_OFF_T)TFFS_NOR_MAX_ENTRY_COUNT);
    std::vector<uint8_t> scanBuffer(TFFS_NOR_SCAN_BUFFER_SIZE);
    TSK_OFF_T scanBufferOffset = -1;
    size_t scanBufferBytes = 0;
    size_t zeroLengthDeletedRun = 0;
    TSK_OFF_T entryOffset = 0;
    while (entryOffset <= imageBytes - TFFS_NOR_ENTRY_HEADER_SIZE) {
        if (scanBufferOffset < 0 || entryOffset < scanBufferOffset ||
            entryOffset - scanBufferOffset + TFFS_NOR_ENTRY_HEADER_SIZE >
                (TSK_OFF_T)scanBufferBytes) {
            scanBufferOffset = entryOffset;
            scanBufferBytes = (size_t)std::min<TSK_OFF_T>(
                TFFS_NOR_SCAN_BUFFER_SIZE, imageBytes - entryOffset);
            ssize_t bytesRead = tsk_img_read(a_img_info,
                a_offset + scanBufferOffset, (char *)scanBuffer.data(),
                scanBufferBytes);
            if (bytesRead < (ssize_t)TFFS_NOR_ENTRY_HEADER_SIZE) {
                tffsNorError(TSK_ERR_FS_READ, "could not read entry scan buffer");
                goto onError;
            }
            scanBufferBytes = (size_t)bytesRead;
        }

        const uint8_t *header = scanBuffer.data() +
            (size_t)(entryOffset - scanBufferOffset);
        uint16_t fileId = ((uint16_t)header[0] << 8) | header[1];
        uint16_t dataSize = ((uint16_t)header[2] << 8) | header[3];
        if (fileId == TFFS_NOR_ERASED_VALUE &&
            dataSize == TFFS_NOR_ERASED_VALUE) {
            state->m_usedBytes = entryOffset;
            break;
        }
        if (fileId == TFFS_NOR_ERASED_VALUE || dataSize >
            imageBytes - entryOffset - TFFS_NOR_ENTRY_HEADER_SIZE) {
            tffsNorError(TSK_ERR_FS_CORRUPT, "invalid NOR entry bounds");
            goto onError;
        }

        if (fileId == TFFS_NOR_DELETED_ID && dataSize == 0) {
            if (++zeroLengthDeletedRun >
                TFFS_NOR_MAX_ZERO_LENGTH_DELETED_RUN) {
                tffsNorError(TSK_ERR_FS_CORRUPT,
                    "excessive run of zero-length deleted entries");
                goto onError;
            }
        }
        else {
            zeroLengthDeletedRun = 0;
        }

        TSK_OFF_T dataOffset = entryOffset + TFFS_NOR_ENTRY_HEADER_SIZE;
        TSK_OFF_T dataEnd = dataOffset + dataSize;
        TSK_OFF_T paddedEnd = (dataEnd + TFFS_NOR_ENTRY_ALIGNMENT - 1) &
            ~((TSK_OFF_T)TFFS_NOR_ENTRY_ALIGNMENT - 1);
        if (paddedEnd > imageBytes) {
            tffsNorError(TSK_ERR_FS_CORRUPT, "invalid NOR entry padding");
            goto onError;
        }
        if (state->m_entries.size() >= maxEntryCount) {
            tffsNorError(TSK_ERR_FS_CORRUPT,
                "excessive number of NOR entries");
            goto onError;
        }
        TFFS_NOR_ENTRY entry = { entryOffset, dataOffset, paddedEnd,
            fileId, dataSize };
        state->m_entries.push_back(entry);
        entryOffset = paddedEnd;
        state->m_usedBytes = entryOffset;
    }
    if (state->m_entries.empty()) {
        tffsNorError(TSK_ERR_FS_MAGIC, "no NOR TFFS entries found");
        goto onError;
    }

    fs->tag = TSK_FS_INFO_TAG;
    fs->ftype = a_ftype;
    fs->duname = "4-byte unit";
    fs->flags = (TSK_FS_INFO_FLAG_ENUM)0;
    fs->img_info = a_img_info;
    fs->offset = a_offset;
    fs->endian = TSK_BIG_ENDIAN;
    fs->impl = state;
    fs->root_inum = 0;
    fs->first_inum = 1;
    fs->last_inum = state->m_entries.size();
    fs->inum_count = state->m_entries.size() + 1;
    fs->first_block = 0;
    fs->block_size = TFFS_NOR_ENTRY_ALIGNMENT;
    fs->block_count = (imageBytes + fs->block_size - 1) / fs->block_size;
    fs->last_block = fs->block_count - 1;
    fs->last_block_act = fs->last_block;
    fs->dev_bsize = a_img_info->sector_size;

    if (tffsNorLoadNameTable(fs, state) != 0)
        goto onError;

    fs->block_walk = tffsNorBlockWalk;
    fs->block_getflags = tffsNorBlockGetFlags;
    fs->inode_walk = tsk_fs_nofs_inode_walk;
    fs->file_add_meta = tffsNorFileAddMeta;
    fs->get_default_attr_type = tffsNorGetDefaultAttrType;
    fs->load_attrs = tffsNorLoadAttrs;
    fs->istat = tffsNorIstat;
    fs->dir_open_meta = tffsNorDirOpenMeta;
    fs->jopen = tsk_fs_nofs_jopen;
    fs->jblk_walk = tsk_fs_nofs_jblk_walk;
    fs->jentry_walk = tsk_fs_nofs_jentry_walk;
    fs->fsstat = tffsNorFsstat;
    fs->fscheck = tffsNorFscheck;
    fs->name_cmp = tsk_fs_unix_name_cmp;
    fs->close = tffsNorClose;
    return fs;

onError:
    delete state;
    tsk_fs_free(fs);
    return NULL;
}