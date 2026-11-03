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
*\file tffs_nand.cpp
* Contains the internal TSK TFFS NAND file system functions.
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
#include "tsk_tffs_nand.h"
#include "tsk_tffs_nor.h"
#include "tsk_fs.h"
#include <string.h>
#include <algorithm>
#include <map>
#include <new>
#include <string>
#include <vector>

struct TFFS_NAND_STATE {
    std::map<uint32_t, uint32_t> m_latestVersionByFileId;
};

static uint8_t readHeader(TSK_FS_INFO *a_fs, TSK_OFF_T a_offset,
    TFFS_HEADER *a_head);
static TSK_RETVAL_ENUM
    tffsfsReadNameMap(TSK_FS_INFO *a_fs,
    const std::vector<TFFS_HEADER> &a_pageHeaders,
    const std::vector<uint8_t> &a_pageValid,
    std::map<uint32_t, std::string> &a_namesByFileId);
    static uint8_t tffsfsBuildVersionIndex(TSK_FS_INFO *a_fs,
        TFFS_NAND_STATE *a_state);

static uint8_t
tffsfsDetectGeometry(TSK_IMG_INFO *a_img_info, TSK_OFF_T a_offset,
    uint32_t *a_pageSize, TSK_DADDR_T *a_pageCount)
{
    const TSK_OFF_T imageBytes = a_img_info->size - a_offset;
    const size_t chunkSize = 1024 * 1024;
    std::vector<char> buffer(chunkSize + TFFS_MAGIC_LEN - 1);
    TSK_OFF_T nextMagicOffset = 0;
    TSK_OFF_T lastMagicOffset = 0;
    bool firstMagicFound = false;

    for (TSK_OFF_T scanOffset = 0; scanOffset < imageBytes;) {
        const TSK_OFF_T remaining = imageBytes - scanOffset;
        const size_t chunkBytes = (size_t)std::min<TSK_OFF_T>(
            chunkSize, remaining);
        const size_t readBytes = (size_t)std::min<TSK_OFF_T>(
            chunkBytes + TFFS_MAGIC_LEN - 1, remaining);
        ssize_t bytesRead = tsk_img_read(a_img_info, a_offset + scanOffset,
            buffer.data(), readBytes);
        if (bytesRead != (ssize_t)readBytes) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_READ);
            tsk_error_set_errstr("tffs_open: could not scan image for TFFS magic");
            return 1;
        }

        for (size_t byteIndex = 0; byteIndex < chunkBytes &&
            byteIndex + TFFS_MAGIC_LEN <= readBytes; ++byteIndex) {
            if (memcmp(buffer.data() + byteIndex, TFFS_MAGIC,
                TFFS_MAGIC_LEN) != 0)
                continue;

            const TSK_OFF_T magicOffset = scanOffset + byteIndex;
            if (magicOffset == 0) {
                firstMagicFound = true;
            }
            else if (nextMagicOffset == 0) {
                nextMagicOffset = magicOffset;
                lastMagicOffset = magicOffset;
            }
            else if (magicOffset % nextMagicOffset == 0) {
                lastMagicOffset = magicOffset;
            }
        }

        scanOffset += chunkBytes;
    }

    if (!firstMagicFound) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("tffs_open: TFFS magic not found at image offset");
        return 1;
    }
    if (nextMagicOffset == 0 ||
        nextMagicOffset % TFFS_PAGES_PER_BLOCK != 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("tffs_open: could not determine TFFS page size");
        return 1;
    }

    const TSK_OFF_T detectedPageSize =
        nextMagicOffset / TFFS_PAGES_PER_BLOCK;
    if (detectedPageSize < (TSK_OFF_T)sizeof(TFFS_HEADER) ||
        detectedPageSize > UINT32_MAX ||
        lastMagicOffset > imageBytes - nextMagicOffset) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_CORRUPT);
        tsk_error_set_errstr("tffs_open: invalid TFFS geometry");
        return 1;
    }

    *a_pageSize = (uint32_t)detectedPageSize;
    *a_pageCount = (TSK_DADDR_T)(lastMagicOffset / nextMagicOffset + 1) *
        TFFS_PAGES_PER_BLOCK;
    return 0;
}

/* Set TSK's unsupported-function error for callbacks not yet implemented. */
static uint8_t
tffsfsNotImplemented(const char *a_functionName)
{
    if (tsk_verbose)
        tsk_fprintf(stderr, "tffsfsNotImplemented: called\n");
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
    tsk_error_set_errstr("%s is not implemented for TFFS", a_functionName);
    return 1;
}

static uint8_t
tffsfsFsstatBlockHeaders(TSK_FS_INFO *a_fs, FILE *a_hfile)
{
    uint8_t header[0x40];

    TSK_OFF_T imageBytes = a_fs->img_info->size - a_fs->offset;
    TSK_DADDR_T pageCount = imageBytes / a_fs->block_size;
    if (pageCount > a_fs->block_count)
        pageCount = a_fs->block_count;
    TSK_DADDR_T eraseBlockCount =
        (pageCount + TFFS_PAGES_PER_BLOCK - 1) / TFFS_PAGES_PER_BLOCK;

    tsk_fprintf(a_hfile, "\nERASE BLOCK HEADERS\n");
    tsk_fprintf(a_hfile,
        "+------+-------+------------+----------+------------+------------+----------+--------+----------+-------+\n");
    tsk_fprintf(a_hfile,
        "| %-4s | %-5s | %-10s | %-8s | %-10s | %-10s | %-8s | %-6s | %-8s | %-5s |\n",
        "Blk", "Page", "Image Off", "Magic", "TFFS Ver", "Header Ver",
        "Logical", "Erase", "Sec/Page", "Bad");
    tsk_fprintf(a_hfile,
        "+------+-------+------------+----------+------------+------------+----------+--------+----------+-------+\n");
    for (TSK_DADDR_T block = 0; block < eraseBlockCount; ++block) {
        TSK_DADDR_T page = block * TFFS_PAGES_PER_BLOCK;
        TSK_OFF_T pageOffset = (TSK_OFF_T)page * a_fs->block_size;
        TSK_OFF_T imageOffset = a_fs->offset + pageOffset;
        ssize_t bytesRead = tsk_img_read(a_fs->img_info, imageOffset,
            (char *)header, sizeof(header));
        if (bytesRead != (ssize_t)sizeof(header)) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_READ);
            tsk_error_set_errstr("tffsfsFsstatBlockHeaders: could not read erase-block header at page %" PRIuDADDR,
                page);
            return 1;
        }

        bool magicValid = memcmp(header, TFFS_MAGIC, TFFS_MAGIC_LEN) == 0;

        tsk_fprintf(a_hfile,
            "| %-4" PRIuDADDR " | %-5" PRIuDADDR " | %-10" PRIdOFF
            " | %-8s | 0x%08" PRIx32 " | 0x%08" PRIx32 " | %-8" PRIu32
            " | %-6" PRIu32 " | %-8" PRIu32 " | %-5" PRIu32 " |\n",
            block, page, imageOffset, magicValid ? TFFS_MAGIC : "INVALID",
            tsk_getu32(a_fs->endian, &header[0x08]),
            tsk_getu32(a_fs->endian, &header[0x0C]),
            tsk_getu32(a_fs->endian, &header[0x10]),
            tsk_getu32(a_fs->endian, &header[0x14]),
            tsk_getu32(a_fs->endian, &header[0x18]),
            tsk_getu32(a_fs->endian, &header[0x1C]));
    }
    tsk_fprintf(a_hfile,
        "+------+-------+------------+----------+------------+------------+----------+--------+----------+-------+\n");

    tsk_fprintf(a_hfile, "\nRESERVE PAGE ADDRESSES\n");
    tsk_fprintf(a_hfile,
        "+------+--------------------+--------------------+--------------------+--------------------+\n");
    tsk_fprintf(a_hfile,
        "| %-4s | %-18s | %-18s | %-18s | %-18s |\n",
        "Blk", "Reserve Page 0", "Reserve Page 1", "Reserve Page 2",
        "Reserve Page 3");
    tsk_fprintf(a_hfile,
        "+------+--------------------+--------------------+--------------------+--------------------+\n");
    for (TSK_DADDR_T block = 0; block < eraseBlockCount; ++block) {
        TSK_DADDR_T page = block * TFFS_PAGES_PER_BLOCK;
        TSK_OFF_T imageOffset = a_fs->offset +
            (TSK_OFF_T)page * a_fs->block_size;
        ssize_t bytesRead = tsk_img_read(a_fs->img_info, imageOffset,
            (char *)header, sizeof(header));
        if (bytesRead != (ssize_t)sizeof(header)) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_READ);
            tsk_error_set_errstr("tffsfsFsstatBlockHeaders: could not read reserve pages for block %" PRIuDADDR,
                block);
            return 1;
        }
        tsk_fprintf(a_hfile,
            "| %-4" PRIuDADDR " | 0x%016" PRIx64 " | 0x%016" PRIx64
            " | 0x%016" PRIx64 " | 0x%016" PRIx64 " |\n",
            block,
            tsk_getu64(a_fs->endian, &header[0x20]),
            tsk_getu64(a_fs->endian, &header[0x28]),
            tsk_getu64(a_fs->endian, &header[0x30]),
            tsk_getu64(a_fs->endian, &header[0x38]));
    }
    tsk_fprintf(a_hfile,
        "+------+--------------------+--------------------+--------------------+--------------------+\n");

    return 0;
}

/* Print validated TFFS geometry, layout, and metadata/allocation ranges. */
static uint8_t
tffsfsFsstat(TSK_FS_INFO *a_fs, FILE *a_hfile)
{
    if (tsk_verbose)
        tsk_fprintf(stderr, "tffsfsFsstat: called\n");
    if (a_fs == NULL || a_fs->tag != TSK_FS_INFO_TAG || a_hfile == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("tffsfsFsstat: invalid argument");
        return 1;
    }
    if (a_fs->block_size < sizeof(TFFS_HEADER) || a_fs->offset < 0 ||
        a_fs->offset > a_fs->img_info->size) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_CORRUPT);
        tsk_error_set_errstr("tffsfsFsstat: invalid TFFS geometry");
        return 1;
    }

    tsk_error_reset();
    TSK_OFF_T imageBytes = a_fs->img_info->size - a_fs->offset;
    TSK_DADDR_T pageCount = imageBytes / a_fs->block_size;
    if (pageCount > a_fs->block_count)
        pageCount = a_fs->block_count;

    TSK_DADDR_T eraseHeaderPages = 0;
    TSK_DADDR_T emptyPages = 0;
    TSK_DADDR_T erasedPages = 0;
    TSK_DADDR_T namePages = 0;
    TSK_DADDR_T dataPages = 0;
    TSK_DADDR_T fileStartPages = 0;
    std::map<uint32_t, uint32_t> latestVersionByFileId;

    for (TSK_DADDR_T page = 0; page < pageCount; ++page) {
        if (page % TFFS_PAGES_PER_BLOCK == 0) {
            ++eraseHeaderPages;
            continue;
        }

        TFFS_HEADER header;
        if (readHeader(a_fs, (TSK_OFF_T)page * a_fs->block_size, &header) != 0) {
            tsk_error_set_errstr2("tffsfsFsstat: page %" PRIuDADDR, page);
            return 1;
        }

        if (header.file_id == 0) {
            ++emptyPages;
            continue;
        }
        if (header.file_id == UINT32_MAX) {
            ++erasedPages;
            continue;
        }
        if (header.size > a_fs->block_size - sizeof(TFFS_HEADER)) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_CORRUPT);
            tsk_error_set_errstr("tffsfsFsstat: invalid data size on page %" PRIuDADDR,
                page);
            return 1;
        }
        if (header.file_id == TFFS_NAME_DIRECTORY_ID) {
            ++namePages;
            continue;
        }

        ++dataPages;
        if (header.part == 0) {
            ++fileStartPages;
            std::map<uint32_t, uint32_t>::iterator latest =
                latestVersionByFileId.find(header.file_id);
            if (latest == latestVersionByFileId.end()) {
                latestVersionByFileId[header.file_id] = header.version;
            }
            else if (header.version > latest->second) {
                latest->second = header.version;
            }
        }
    }
    TSK_DADDR_T obsoleteVersions = fileStartPages -
        (TSK_DADDR_T)latestVersionByFileId.size();

    tsk_fprintf(a_hfile, "FILE SYSTEM INFORMATION\n");
    tsk_fprintf(a_hfile, "--------------------------------------------\n");
    tsk_fprintf(a_hfile, "File System Type: TFFS\n");
    tsk_fprintf(a_hfile, "Magic: %s\n", TFFS_MAGIC);
    tsk_fprintf(a_hfile, "Image Offset: %" PRIdOFF " bytes\n", a_fs->offset);
    tsk_fprintf(a_hfile, "Byte Order: Big-endian\n");
    tsk_fprintf(a_hfile, "Page Size: %u bytes\n", a_fs->block_size);
    tsk_fprintf(a_hfile, "Header Size: %" PRIuSIZE " bytes\n", sizeof(TFFS_HEADER));
    tsk_fprintf(a_hfile, "Page Data Size: %u bytes\n",
        a_fs->block_size - (unsigned int)sizeof(TFFS_HEADER));
    tsk_fprintf(a_hfile, "Pages per Erase Block: %u\n", TFFS_PAGES_PER_BLOCK);
    tsk_fprintf(a_hfile, "Erase Blocks: %" PRIuDADDR "\n",
        a_fs->block_count / TFFS_PAGES_PER_BLOCK);
    tsk_fprintf(a_hfile, "Pages in Image: %" PRIuDADDR "\n", pageCount);
    tsk_fprintf(a_hfile, "Erase-Block Header Pages: %" PRIuDADDR " (ignored)\n",
        eraseHeaderPages);

    tsk_fprintf(a_hfile, "\nPAGE INFORMATION\n");
    tsk_fprintf(a_hfile, "--------------------------------------------\n");
    tsk_fprintf(a_hfile, "Empty Pages: %" PRIuDADDR "\n", emptyPages);
    tsk_fprintf(a_hfile, "Erased Pages: %" PRIuDADDR "\n", erasedPages);
    tsk_fprintf(a_hfile, "File Data Page: %" PRIuDADDR "\n", dataPages);
    tsk_fprintf(a_hfile, "Name Pages: %" PRIuDADDR "\n", namePages );

    tsk_fprintf(a_hfile, "\nFILE INFORMATION\n");
    tsk_fprintf(a_hfile, "--------------------------------------------\n");
    tsk_fprintf(a_hfile, "Files: %" PRIuSIZE "\n", latestVersionByFileId.size());
    tsk_fprintf(a_hfile, "Deleted Files: %" PRIuDADDR "\n", obsoleteVersions);

    if (tffsfsFsstatBlockHeaders(a_fs, a_hfile))
        return 1;

    return 0;
}

/* Resolve an inode/object and populate its TSK_FS_META fields, including
 * type, allocation state, ownership, timestamps, name, size, and link target.
 * Leave data mapping to tffsfsLoadAttrs(). */
static uint8_t
tffsfsFileAddMeta(TSK_FS_INFO *a_fs, TSK_FS_FILE *a_fs_file,
    TSK_INUM_T a_addr)
{
    if (tsk_verbose)
        tsk_fprintf(stderr, "tffsfsFileAddMeta: called\n");
    if (a_fs == NULL || a_fs->tag != TSK_FS_INFO_TAG || a_fs_file == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("tffsfsFileAddMeta: invalid argument");
        return 1;
    }
    if (a_addr < a_fs->first_inum || a_addr > a_fs->last_inum ||
        a_addr >= a_fs->block_count || a_addr % TFFS_PAGES_PER_BLOCK == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
        tsk_error_set_errstr("tffsfsFileAddMeta: invalid file page: %" PRIuINUM,
            a_addr);
        return 1;
    }

    if (a_fs_file->meta == NULL) {
        if ((a_fs_file->meta = tsk_fs_meta_alloc(TFFS_FILE_CONTENT_LEN)) == NULL)
            return 1;
    }
    else {
        tsk_fs_meta_reset(a_fs_file->meta);
    }

    TFFS_HEADER first;
    TSK_OFF_T firstOffset = (TSK_OFF_T)a_addr * a_fs->block_size;
    if (readHeader(a_fs, firstOffset, &first) != 0)
        return 1;
    if (first.file_id == 0 || first.file_id == UINT32_MAX ||
        first.file_id == TFFS_NAME_DIRECTORY_ID || first.part != 0 ||
        first.size > a_fs->block_size - sizeof(TFFS_HEADER)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_CORRUPT);
        tsk_error_set_errstr("tffsfsFileAddMeta: invalid file header at page %" PRIuINUM,
            a_addr);
        return 1;
    }

    TSK_OFF_T totalSize = first.size;
    TSK_DADDR_T page = a_addr;
    TSK_DADDR_T partsFound = 1;
    uint32_t expectedPart = first.nextpart;
    while (expectedPart != 0 && partsFound < a_fs->block_count) {
        TSK_DADDR_T nextPage = page + 1;
        if (nextPage % TFFS_PAGES_PER_BLOCK == 0)
            ++nextPage;
        if (nextPage >= a_fs->block_count) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_CORRUPT);
            tsk_error_set_errstr("tffsfsFileAddMeta: page chain exceeds the image");
            return 1;
        }

        TFFS_HEADER next;
        if (readHeader(a_fs, (TSK_OFF_T)nextPage * a_fs->block_size, &next) != 0)
            return 1;
        if (next.file_id != first.file_id || next.version != first.version ||
            next.part != expectedPart ||
            next.size > a_fs->block_size - sizeof(TFFS_HEADER)) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_CORRUPT);
            tsk_error_set_errstr("tffsfsFileAddMeta: invalid page chain");
            return 1;
        }

        totalSize += next.size;
        page = nextPage;
        expectedPart = next.nextpart;
        ++partsFound;
    }
    if (expectedPart != 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_CORRUPT);
        tsk_error_set_errstr("tffsfsFileAddMeta: page chain contains a loop");
        return 1;
    }

    uint32_t latestVersion = first.version;
    bool isLatest = true;
    if (a_fs_file->name != NULL) {
        isLatest = (a_fs_file->name->flags & TSK_FS_NAME_FLAG_ALLOC) != 0;
    }
    else {
        for (TSK_DADDR_T candidatePage = 1;
            candidatePage < a_fs->block_count; ++candidatePage) {
            if (candidatePage % TFFS_PAGES_PER_BLOCK == 0)
                continue;

            TFFS_HEADER candidate;
            if (readHeader(a_fs,
                (TSK_OFF_T)candidatePage * a_fs->block_size, &candidate) != 0)
                return 1;
            if (candidate.file_id == first.file_id && candidate.part == 0 &&
                candidate.version > latestVersion) {
                latestVersion = candidate.version;
            }
        }
        isLatest = first.version == latestVersion;
    }

    TSK_FS_META *meta = a_fs_file->meta;
    meta->addr = a_addr;
    meta->type = TSK_FS_META_TYPE_REG;
    meta->mode = TSK_FS_META_MODE_UNSPECIFIED;
    meta->nlink = 1;
    meta->size = totalSize;
    meta->uid = 0;
    meta->gid = 0;
    meta->mtime = first.timestamp;
    meta->flags = (TSK_FS_META_FLAG_ENUM)(TSK_FS_META_FLAG_USED |
        (isLatest ? TSK_FS_META_FLAG_ALLOC : TSK_FS_META_FLAG_UNALLOC));
    meta->attr_state = TSK_FS_META_ATTR_EMPTY;

    return 0;
}


/* Read a directory's entries into TSK_FS_DIR with their names, inode numbers,
 * types, and allocation states. Validate each entry and honor TSK's directory
 * recursion and return-value conventions. */
static TSK_RETVAL_ENUM
tffsfsDirOpenMeta(TSK_FS_INFO *a_fs, TSK_FS_DIR **a_fs_dir,
    TSK_INUM_T a_addr, int a_recursion_depth)
{
    if (tsk_verbose)
        tsk_fprintf(stderr, "tffsfsDirOpenMeta: called\n");

    if (a_fs == NULL || a_fs->tag != TSK_FS_INFO_TAG) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("tffsfsDirOpenMeta: invalid file system handle");
        return TSK_ERR;
    }
    if (a_addr < a_fs->first_inum || a_addr > a_fs->last_inum) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("tffsfsDirOpenMeta: invalid metadata address: %"
            PRIuINUM, a_addr);
        return TSK_ERR;
    }
    if (a_fs_dir == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("tffsfsDirOpenMeta: NULL fsDir argument");
        return TSK_ERR;
    }

    if (a_addr != a_fs->root_inum) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("tffsfsDirOpenMeta: TFFS only has a root directory");
        return TSK_ERR;
    }
    (void)a_recursion_depth;

    TSK_FS_DIR *fsDir = *a_fs_dir;
    if (fsDir != NULL) {
        tsk_fs_dir_reset(fsDir);
        fsDir->addr = a_addr;
    }
    else if ((*a_fs_dir = fsDir = tsk_fs_dir_alloc(a_fs, a_addr, 128)) == NULL) {
        return TSK_ERR;
    }
    fsDir->fs_file = NULL;

    if (a_fs->block_size < sizeof(TFFS_HEADER) || a_fs->offset < 0 ||
        a_fs->offset > a_fs->img_info->size) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_CORRUPT);
        tsk_error_set_errstr("tffsfsDirOpenMeta: invalid TFFS page geometry");
        return TSK_ERR;
    }

    TSK_OFF_T imageBytes = a_fs->img_info->size - a_fs->offset;
    TSK_DADDR_T pageCount = imageBytes / a_fs->block_size;
    if (pageCount > a_fs->block_count)
        pageCount = a_fs->block_count;

    std::vector<TFFS_HEADER> pageHeaders((size_t)pageCount);
    std::vector<uint8_t> pageValid((size_t)pageCount, 0);
    std::map<uint32_t, uint32_t> latestVersionByFileId;
    std::map<uint32_t, std::string> namesByFileId;

    for (TSK_DADDR_T page = 0; page < pageCount; ++page) {
        if (page % TFFS_PAGES_PER_BLOCK == 0)
            continue;

        TSK_OFF_T pageOffset = (TSK_OFF_T)page * a_fs->block_size;
        if (readHeader(a_fs, pageOffset, &pageHeaders[page]) != 0)
            return TSK_ERR;
        pageValid[page] = 1;

        const TFFS_HEADER &header = pageHeaders[page];
        if (header.file_id == 0 || header.file_id == UINT32_MAX ||
            header.file_id == TFFS_NAME_DIRECTORY_ID || header.part != 0)
            continue;

        std::map<uint32_t, uint32_t>::iterator latest =
            latestVersionByFileId.find(header.file_id);
        if (latest == latestVersionByFileId.end() ||
            header.version > latest->second) {
            latestVersionByFileId[header.file_id] = header.version;
        }
    }

    if (tffsfsReadNameMap(a_fs, pageHeaders, pageValid,
        namesByFileId) != TSK_OK) {
        return TSK_ERR;
    }

    for (TSK_DADDR_T page = 0; page < pageCount; ++page) {
        const TFFS_HEADER &first = pageHeaders[page];
        if (!pageValid[page] || first.file_id == 0 ||
            first.file_id == UINT32_MAX ||
            first.file_id == TFFS_NAME_DIRECTORY_ID || first.part != 0)
            continue;

        TSK_OFF_T totalSize = first.size;
        TSK_DADDR_T partPage = page;
        uint32_t expectedPart = first.nextpart;
        TSK_DADDR_T partsFound = 1;
        while (expectedPart != 0 && partsFound < pageCount) {
            TSK_DADDR_T nextPage = partPage + 1;
            if (nextPage % TFFS_PAGES_PER_BLOCK == 0)
                ++nextPage;
            if (nextPage >= pageCount || !pageValid[nextPage])
                break;

            const TFFS_HEADER &next = pageHeaders[nextPage];
            if (next.file_id != first.file_id || next.version != first.version ||
                next.part != expectedPart)
                break;

            totalSize += next.size;
            partPage = nextPage;
            expectedPart = next.nextpart;
            ++partsFound;
        }

        if (expectedPart != 0 && tsk_verbose) {
            tsk_fprintf(stderr,
                "tffsfsDirOpenMeta: incomplete page chain for file %" PRIu32
                " version %" PRIu32 "\n", first.file_id, first.version);
        }
        if (tsk_verbose) {
            tsk_fprintf(stderr,
                "tffsfsDirOpenMeta: file %" PRIu32 " version %" PRIu32
                " starts at page %" PRIuDADDR ", %" PRIuDADDR
                " parts, %" PRIdOFF " data bytes\n", first.file_id,
                first.version, page, partsFound, totalSize);
        }

        std::string fileName;
        std::map<uint32_t, std::string>::const_iterator name =
            namesByFileId.find(first.file_id);
        if (name == namesByFileId.end())
            fileName = "file_" + std::to_string(first.file_id);
        else
            fileName = name->second;

        bool allocated = latestVersionByFileId[first.file_id] == first.version;
        if (!allocated) {
            fileName += "#" + std::to_string(first.file_id) + "," +
                std::to_string(first.version);
        }

        TSK_FS_NAME *fsName = tsk_fs_name_alloc(fileName.size() + 1, 0);
        if (fsName == NULL)
            return TSK_ERR;
        memcpy(fsName->name, fileName.c_str(), fileName.size() + 1);
        fsName->meta_addr = page;
        fsName->par_addr = a_addr;
        fsName->type = TSK_FS_NAME_TYPE_REG;
        fsName->flags = allocated ? TSK_FS_NAME_FLAG_ALLOC : TSK_FS_NAME_FLAG_UNALLOC;

        if (tsk_fs_dir_add(fsDir, fsName)) {
            tsk_fs_name_free(fsName);
            return TSK_ERR;
        }
        tsk_fs_name_free(fsName);
    }

    return TSK_OK;
}

/* Select the TSK attribute type used for ordinary TFFS file content. */
static TSK_FS_ATTR_TYPE_ENUM
tffsfsGetDefaultAttrType(const TSK_FS_FILE *a_file)
{
    if (tsk_verbose)
        tsk_fprintf(stderr, "tffsfsGetDefaultAttrType: called\n");
    return TSK_FS_ATTR_TYPE_DEFAULT;
}

/* Read each TFFS page's data area into the file's resident default attribute,
 * omitting the per-page header and validating the complete part chain. */
static uint8_t
tffsfsLoadAttrs(TSK_FS_FILE *a_file)
{
    if (tsk_verbose)
        tsk_fprintf(stderr, "tffsfsLoadAttrs: called\n");
    if (a_file == NULL || a_file->fs_info == NULL || a_file->meta == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("tffsfsLoadAttrs: invalid file handle");
        return 1;
    }

    TSK_FS_INFO *a_fs = a_file->fs_info;
    TSK_FS_META *meta = a_file->meta;
    if (meta->attr_state == TSK_FS_META_ATTR_STUDIED)
        return 0;
    if (meta->attr_state == TSK_FS_META_ATTR_ERROR)
        return 1;
    if (meta->size < 0 || a_fs->block_size <= sizeof(TFFS_HEADER) ||
        meta->size > (TSK_OFF_T)a_fs->block_count *
            (TSK_OFF_T)(a_fs->block_size - sizeof(TFFS_HEADER))) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_CORRUPT);
        tsk_error_set_errstr("tffsfsLoadAttrs: invalid file size");
        meta->attr_state = TSK_FS_META_ATTR_ERROR;
        return 1;
    }

    if (meta->attr == NULL) {
        meta->attr = tsk_fs_attrlist_alloc();
        if (meta->attr == NULL) {
            meta->attr_state = TSK_FS_META_ATTR_ERROR;
            return 1;
        }
    }
    else {
        tsk_fs_attrlist_markunused(meta->attr);
    }

    TSK_FS_ATTR *attr = tsk_fs_attrlist_getnew(meta->attr, TSK_FS_ATTR_RES);
    if (attr == NULL) {
        meta->attr_state = TSK_FS_META_ATTR_ERROR;
        return 1;
    }

    size_t dataSize = (size_t)meta->size;
    uint8_t emptyData = 0;
    char *data = (char *)tsk_malloc(dataSize == 0 ? 1 : dataSize);
    if (data == NULL) {
        meta->attr_state = TSK_FS_META_ATTR_ERROR;
        return 1;
    }

    TSK_DADDR_T page = meta->addr;
    size_t dataRead = 0;
    uint32_t expectedPart = 0;
    uint32_t file_id = 0;
    uint32_t version = 0;
    TSK_DADDR_T partsRead = 0;
    while (partsRead < a_fs->block_count) {
        if (page >= a_fs->block_count || page % TFFS_PAGES_PER_BLOCK == 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_CORRUPT);
            tsk_error_set_errstr("tffsfsLoadAttrs: invalid page in file chain");
            goto onError;
        }

        TFFS_HEADER header;
        TSK_OFF_T pageOffset = (TSK_OFF_T)page * a_fs->block_size;
        if (readHeader(a_fs, pageOffset, &header) != 0)
            goto onError;

        if (partsRead == 0) {
            file_id = header.file_id;
            version = header.version;
            if (header.part != 0 || file_id == 0 || file_id == UINT32_MAX ||
                file_id == TFFS_NAME_DIRECTORY_ID) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_CORRUPT);
                tsk_error_set_errstr("tffsfsLoadAttrs: invalid first page");
                goto onError;
            }
        }
        else if (header.file_id != file_id || header.version != version ||
            header.part != expectedPart) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_CORRUPT);
            tsk_error_set_errstr("tffsfsLoadAttrs: page chain does not match");
            goto onError;
        }

        if (header.size > a_fs->block_size - sizeof(TFFS_HEADER) ||
            header.size > dataSize - dataRead) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_CORRUPT);
            tsk_error_set_errstr("tffsfsLoadAttrs: invalid page data size");
            goto onError;
        }

        if (header.size != 0) {
            TSK_OFF_T dataOffset = a_fs->offset + pageOffset + sizeof(TFFS_HEADER);
            ssize_t bytesRead = tsk_img_read(a_fs->img_info, dataOffset,
                data + dataRead, header.size);
            if (bytesRead != (ssize_t)header.size) {
                tsk_error_set_errno(TSK_ERR_FS_READ);
                tsk_error_set_errstr("tffsfsLoadAttrs: could not read page data");
                goto onError;
            }
        }

        dataRead += header.size;
        ++partsRead;
        expectedPart = header.nextpart;
        if (expectedPart == 0)
            break;

        ++page;
        if (page % TFFS_PAGES_PER_BLOCK == 0)
            ++page;
    }

    if (expectedPart != 0 || dataRead != dataSize) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_CORRUPT);
        tsk_error_set_errstr("tffsfsLoadAttrs: incomplete file page chain");
        goto onError;
    }

    if (tsk_fs_attr_set_str(a_file, attr, NULL, TSK_FS_ATTR_TYPE_DEFAULT,
        TSK_FS_ATTR_ID_DEFAULT, dataSize == 0 ? (void *)&emptyData : data,
        dataSize)) {
        goto onError;
    }

    free(data);
    meta->attr_state = TSK_FS_META_ATTR_STUDIED;
    return 0;

onError:
    free(data);
    meta->attr_state = TSK_FS_META_ATTR_ERROR;
    return 1;
}

static uint8_t readHeader(TSK_FS_INFO *a_fs, TSK_OFF_T a_offset,
    TFFS_HEADER *a_head)
{
    if (tsk_verbose)
        tsk_fprintf(stderr, "readHeader: called\n");
    ssize_t bytesRead;

    if (a_fs == NULL || a_fs->img_info == NULL || a_head == NULL) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("readHeader: invalid argument");
        return 1;
    }

    bytesRead = tsk_img_read(a_fs->img_info, a_fs->offset + a_offset, (char *)a_head,
        sizeof(TFFS_HEADER));
    if (bytesRead != (ssize_t)sizeof(TFFS_HEADER)) {
        tsk_error_set_errno(TSK_ERR_FS_READ);
        tsk_error_set_errstr("readHeader: block %" PRIdOFF " - read error", a_offset);
        return 1;
    }
    a_head->file_id = tsk_getu32(a_fs->endian, (uint8_t *)&a_head->file_id);
    a_head->size = tsk_getu32(a_fs->endian, (uint8_t *)&a_head->size);
    a_head->timestamp = tsk_getu32(a_fs->endian, (uint8_t *)&a_head->timestamp);
    a_head->version = tsk_getu32(a_fs->endian, (uint8_t *)&a_head->version);
    a_head->part = tsk_getu32(a_fs->endian, (uint8_t *)&a_head->part);
    a_head->nextpart = tsk_getu32(a_fs->endian, (uint8_t *)&a_head->nextpart);
    return 0;
}

static TSK_RETVAL_ENUM
tffsfsReadNameMap(TSK_FS_INFO *a_fs,
    const std::vector<TFFS_HEADER> &a_pageHeaders,
    const std::vector<uint8_t> &a_pageValid,
    std::map<uint32_t, std::string> &a_namesByFileId)
{
    for (TSK_DADDR_T page = 0; page < a_pageHeaders.size(); ++page) {
        const TFFS_HEADER &header = a_pageHeaders[page];
        if (!a_pageValid[page] || header.file_id != TFFS_NAME_DIRECTORY_ID)
            continue;

        if (header.size > a_fs->block_size - sizeof(TFFS_HEADER)) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_CORRUPT);
            tsk_error_set_errstr("tffsfsReadNameMap: invalid name-page size");
            return TSK_ERR;
        }

        std::vector<uint8_t> data(header.size);
        if (header.size != 0) {
            TSK_OFF_T dataOffset = a_fs->offset +
                (TSK_OFF_T)page * a_fs->block_size + sizeof(TFFS_HEADER);
            ssize_t bytesRead = tsk_img_read(a_fs->img_info, dataOffset,
                (char *)data.data(), data.size());
            if (bytesRead != (ssize_t)data.size()) {
                tsk_error_set_errno(TSK_ERR_FS_READ);
                tsk_error_set_errstr("tffsfsReadNameMap: could not read name page");
                return TSK_ERR;
            }
        }

        size_t cursor = 0;
        while (cursor + sizeof(uint32_t) <= data.size()) {
            uint32_t fileId = tsk_getu32(a_fs->endian, &data[cursor]);
            cursor += sizeof(uint32_t);
            if (fileId == 0 || fileId == UINT32_MAX)
                break;

            size_t nameStart = cursor;
            while (cursor < data.size() && data[cursor] != '\0')
                ++cursor;
            if (cursor == data.size())
                break;

            if (cursor > nameStart) {
                a_namesByFileId[fileId] = std::string(
                    (const char *)&data[nameStart], cursor - nameStart);
            }

            cursor = (cursor + 1 + 3) & ~static_cast<size_t>(3);
        }
    }

    return TSK_OK;
}

static uint8_t
tffsfsBuildVersionIndex(TSK_FS_INFO *a_fs, TFFS_NAND_STATE *a_state)
{
    for (TSK_DADDR_T page = 0; page < a_fs->block_count; ++page) {
        if (page % TFFS_PAGES_PER_BLOCK == 0)
            continue;

        TFFS_HEADER header;
        if (readHeader(a_fs, (TSK_OFF_T)page * a_fs->block_size, &header) != 0) {
            tsk_error_set_errstr2("tffsfsBuildVersionIndex: page %" PRIuDADDR,
                page);
            return 1;
        }
        if (header.file_id == 0 || header.file_id == UINT32_MAX ||
            header.file_id == TFFS_NAME_DIRECTORY_ID || header.part != 0)
            continue;

        std::map<uint32_t, uint32_t>::iterator latest =
            a_state->m_latestVersionByFileId.find(header.file_id);
        if (latest == a_state->m_latestVersionByFileId.end() ||
            header.version > latest->second) {
            a_state->m_latestVersionByFileId[header.file_id] = header.version;
        }
    }
    return 0;
}

/* Classify a block as metadata/content and allocated/unallocated/unused. */
static TSK_FS_BLOCK_FLAG_ENUM
tffsfsBlockGetFlags(TSK_FS_INFO *a_fs, TSK_DADDR_T a_addr)
{
    if (tsk_verbose)
        tsk_fprintf(stderr, "tffsfsBlockGetFlags: called\n");

    if (a_fs == NULL || a_addr >= a_fs->block_count) {
        return TSK_FS_BLOCK_FLAG_UNUSED;
    }
    if (a_addr % TFFS_PAGES_PER_BLOCK == 0) {
        return (TSK_FS_BLOCK_FLAG_ENUM)(TSK_FS_BLOCK_FLAG_META |
            TSK_FS_BLOCK_FLAG_ALLOC);
    }

    TSK_OFF_T byteOffset = (TSK_OFF_T)a_addr * a_fs->block_size;
    TFFS_HEADER header;
    if (readHeader(a_fs, byteOffset, &header) != 0) {
        tsk_error_set_errstr("tffsfsBlockGetFlags: block %" PRIuDADDR, a_addr);
        return (TSK_FS_BLOCK_FLAG_ENUM)(TSK_FS_BLOCK_FLAG_CONT |
            TSK_FS_BLOCK_FLAG_UNALLOC);
    }

    if (header.file_id == 0 || header.file_id == UINT32_MAX) {
        return (TSK_FS_BLOCK_FLAG_ENUM)(TSK_FS_BLOCK_FLAG_CONT |
            TSK_FS_BLOCK_FLAG_UNALLOC);
    }
    if (header.file_id == TFFS_NAME_DIRECTORY_ID) {
        return (TSK_FS_BLOCK_FLAG_ENUM)(TSK_FS_BLOCK_FLAG_META |
            TSK_FS_BLOCK_FLAG_ALLOC);
    }

    TFFS_NAND_STATE *state = (TFFS_NAND_STATE *)a_fs->impl;
    if (state == NULL) {
        return (TSK_FS_BLOCK_FLAG_ENUM)(TSK_FS_BLOCK_FLAG_CONT |
            TSK_FS_BLOCK_FLAG_UNALLOC);
    }
    std::map<uint32_t, uint32_t>::const_iterator latest =
        state->m_latestVersionByFileId.find(header.file_id);
    TSK_FS_BLOCK_FLAG_ENUM allocationFlag =
        latest != state->m_latestVersionByFileId.end() &&
            latest->second == header.version
        ? TSK_FS_BLOCK_FLAG_ALLOC : TSK_FS_BLOCK_FLAG_UNALLOC;
    return (TSK_FS_BLOCK_FLAG_ENUM)(TSK_FS_BLOCK_FLAG_CONT | allocationFlag);
}

/* Validate the requested block range, apply the requested filters, read each
 * selected block, and honor the walk callback's result. */
static uint8_t
tffsfsBlockWalk(TSK_FS_INFO *a_fs, TSK_DADDR_T a_start_blk,
    TSK_DADDR_T a_end_blk, TSK_FS_BLOCK_WALK_FLAG_ENUM a_flags,
    TSK_FS_BLOCK_WALK_CB a_callback, void *a_ptr)
{
    TSK_FS_BLOCK *fsBlock;
    TSK_DADDR_T addr;

    /*
    * Sanity checks.
    */
    if (a_start_blk < a_fs->first_block || a_start_blk > a_fs->last_block) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("tffsfsBlockWalk: start block: %" PRIuDADDR,
            a_start_blk);
        return 1;
    }
    if (a_end_blk < a_fs->first_block || a_end_blk > a_fs->last_block
        || a_end_blk < a_start_blk) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
            tsk_error_set_errstr("tffsfsBlockWalk: end block: %" PRIuDADDR ,
                a_end_blk);
            return 1;
    }

    /* Sanity check on a_flags -- make sure at least one ALLOC is set */
    if (((a_flags & TSK_FS_BLOCK_WALK_FLAG_ALLOC) == 0) &&
        ((a_flags & TSK_FS_BLOCK_WALK_FLAG_UNALLOC) == 0)) {
            a_flags = (TSK_FS_BLOCK_WALK_FLAG_ENUM)
                (a_flags | TSK_FS_BLOCK_WALK_FLAG_ALLOC |
                TSK_FS_BLOCK_WALK_FLAG_UNALLOC);
    }
    /* Sanity check on a_flags -- make sure at least one META OR CONTENT is set */
    if (((a_flags & TSK_FS_BLOCK_WALK_FLAG_META) == 0) &&
        ((a_flags & TSK_FS_BLOCK_WALK_FLAG_CONT) == 0)) {
            a_flags = (TSK_FS_BLOCK_WALK_FLAG_ENUM)
                (a_flags | TSK_FS_BLOCK_WALK_FLAG_CONT | TSK_FS_BLOCK_WALK_FLAG_META);
    }

    if ((fsBlock = tsk_fs_block_alloc(a_fs)) == NULL) {
        return 1;
    }

    for (addr = a_start_blk; addr <= a_end_blk; addr++) {
        int retval;
        TSK_FS_BLOCK_FLAG_ENUM myflags;

        myflags = tffsfsBlockGetFlags(a_fs, addr);

        // test if we should call the callback with this one
        if ((myflags & TSK_FS_BLOCK_FLAG_META)
            && (!(a_flags & TSK_FS_BLOCK_WALK_FLAG_META)))
            continue;
        else if ((myflags & TSK_FS_BLOCK_FLAG_CONT)
            && (!(a_flags & TSK_FS_BLOCK_WALK_FLAG_CONT)))
            continue;
        else if ((myflags & TSK_FS_BLOCK_FLAG_ALLOC)
            && (!(a_flags & TSK_FS_BLOCK_WALK_FLAG_ALLOC)))
            continue;
        else if ((myflags & TSK_FS_BLOCK_FLAG_UNALLOC)
            && (!(a_flags & TSK_FS_BLOCK_WALK_FLAG_UNALLOC)))
            continue;

        if (tsk_fs_block_get_flag(a_fs, fsBlock, addr, myflags) == NULL) {
            tsk_error_set_errstr2("tffsfsBlockWalk: block %" PRIuDADDR,
                addr);
            tsk_fs_block_free(fsBlock);
            return 1;
        }

        retval = a_callback(fsBlock, a_ptr);
        if (retval == TSK_WALK_STOP) {
            break;
        }
        else if (retval == TSK_WALK_ERROR) {
            tsk_fs_block_free(fsBlock);
            return 1;
        }
    }

    tsk_fs_block_free(fsBlock);
    return 0;
}

/* Print inode metadata, allocation state, adjusted/original timestamps, and
 * content block addresses. Honor the requested block count and istat flags. */
static uint8_t
tffsfsIstat(TSK_FS_INFO *a_fs, TSK_FS_ISTAT_FLAG_ENUM a_flags,
    FILE *a_hfile, TSK_INUM_T a_addr, TSK_DADDR_T a_numblock,
    int32_t a_sec_skew)
{
    if (tsk_verbose)
        tsk_fprintf(stderr, "tffsfsIstat: called\n");
    if (a_fs == NULL || a_fs->tag != TSK_FS_INFO_TAG ||
        a_fs->img_info == NULL || a_hfile == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("tffsfsIstat: invalid file system or output handle");
        return 1;
    }
    if (a_addr < a_fs->first_inum || a_addr > a_fs->last_inum ||
        a_addr >= a_fs->block_count || a_addr % TFFS_PAGES_PER_BLOCK == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
        tsk_error_set_errstr("tffsfsIstat: invalid file start page: %" PRIuINUM,
            a_addr);
        return 1;
    }
    if ((a_flags & ~TSK_FS_ISTAT_RUNLIST) != 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("tffsfsIstat: unsupported flags: %d", a_flags);
        return 1;
    }

    TSK_FS_FILE *fsFile = tsk_fs_file_open_meta(a_fs, NULL, a_addr);
    if (fsFile == NULL)
        return 1;

    TSK_FS_DIR *rootDir = tsk_fs_dir_open_meta(a_fs, a_fs->root_inum);
    const char *fileName = NULL;
    if (rootDir != NULL) {
        for (size_t index = 0; index < rootDir->names_used; ++index) {
            if (rootDir->names[index].meta_addr == a_addr) {
                fileName = rootDir->names[index].name;
                break;
            }
        }
    }
    else {
        tsk_error_reset();
    }

    TFFS_HEADER first;
    if (readHeader(a_fs, (TSK_OFF_T)a_addr * a_fs->block_size, &first) != 0) {
        tsk_fs_dir_close(rootDir);
        tsk_fs_file_close(fsFile);
        return 1;
    }

    std::vector<std::pair<TSK_DADDR_T, TFFS_HEADER> > pages;
    TSK_DADDR_T page = a_addr;
    uint32_t expectedPart = 0;
    uint32_t file_id = first.file_id;
    uint32_t version = first.version;
    TSK_OFF_T totalSize = 0;
    while (pages.size() < a_fs->block_count) {
        if (page >= a_fs->block_count || page % TFFS_PAGES_PER_BLOCK == 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_CORRUPT);
            tsk_error_set_errstr("tffsfsIstat: invalid page in file chain");
            tsk_fs_dir_close(rootDir);
            tsk_fs_file_close(fsFile);
            return 1;
        }

        TFFS_HEADER header;
        if (readHeader(a_fs, (TSK_OFF_T)page * a_fs->block_size, &header) != 0) {
            tsk_fs_dir_close(rootDir);
            tsk_fs_file_close(fsFile);
            return 1;
        }

        if ((pages.empty() && (header.part != 0 || header.file_id != file_id ||
            header.version != version)) ||
            (!pages.empty() && (header.file_id != file_id ||
            header.version != version || header.part != expectedPart)) ||
            header.size > a_fs->block_size - sizeof(TFFS_HEADER)) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_CORRUPT);
            tsk_error_set_errstr("tffsfsIstat: invalid TFFS page header or chain");
            tsk_fs_dir_close(rootDir);
            tsk_fs_file_close(fsFile);
            return 1;
        }

        pages.push_back(std::make_pair(page, header));
        totalSize += header.size;
        expectedPart = header.nextpart;
        if (expectedPart == 0)
            break;

        ++page;
        if (page % TFFS_PAGES_PER_BLOCK == 0)
            ++page;
    }

    if (pages.empty() || expectedPart != 0 || totalSize != fsFile->meta->size) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_CORRUPT);
        tsk_error_set_errstr("tffsfsIstat: incomplete TFFS file page chain");
        tsk_fs_dir_close(rootDir);
        tsk_fs_file_close(fsFile);
        return 1;
    }

    TSK_FS_META *meta = fsFile->meta;
    char mode[12];
    tsk_fs_meta_make_ls(meta, mode, sizeof(mode));
    tsk_fprintf(a_hfile, "File: %" PRIuINUM "\n", a_addr);
    tsk_fprintf(a_hfile, "%sAllocated\n",
        (meta->flags & TSK_FS_META_FLAG_ALLOC) ? "" : "Not ");
    if (fileName != NULL)
        tsk_fprintf(a_hfile, "Name: %s\n", fileName);
    tsk_fprintf(a_hfile, "File ID / version: %" PRIu32 " / %" PRIu32 "\n",
        file_id, version);
    tsk_fprintf(a_hfile, "Type: Regular file\n");
    tsk_fprintf(a_hfile, "mode: %s\n", mode);
    tsk_fprintf(a_hfile, "size: %" PRIdOFF " bytes\n", meta->size);
    tsk_fprintf(a_hfile, "num of links: %d\n", meta->nlink);
    tsk_fprintf(a_hfile, "Pages required: %" PRIuSIZE "\n", pages.size());

    char timeBuf[128];
    if (a_sec_skew != 0) {
        tsk_fprintf(a_hfile, "Adjusted timestamp: %s\n",
            tsk_fs_time_to_str(meta->mtime - a_sec_skew, timeBuf));
        tsk_fprintf(a_hfile, "Original timestamp: %s\n",
            tsk_fs_time_to_str(meta->mtime, timeBuf));
    }
    else {
        tsk_fprintf(a_hfile, "Timestamp: %s\n",
            tsk_fs_time_to_str(meta->mtime, timeBuf));
    }

    if (a_flags & TSK_FS_ISTAT_RUNLIST)
        tsk_fprintf(a_hfile, "Data mapping: resident attribute; no non-resident runlist\n");

    TSK_DADDR_T pagesToPrint = (TSK_DADDR_T)pages.size();
    if (a_numblock > 0 && a_numblock < pagesToPrint)
        pagesToPrint = a_numblock;
    tsk_fprintf(a_hfile, "\nData Pages:\n");
    for (TSK_DADDR_T index = 0; index < pagesToPrint; ++index) {
        const TFFS_HEADER &header = pages[index].second;
        TSK_OFF_T imageOffset = a_fs->offset +
            (TSK_OFF_T)pages[index].first * a_fs->block_size;
        tsk_fprintf(a_hfile,
            "Page: %" PRIuDADDR ", Image Offset: %" PRIdOFF
            ", Part: %" PRIu32 ", Next Part: %" PRIu32
            ", Data Size: %" PRIu32 " bytes\n",
            pages[index].first, imageOffset, header.part, header.nextpart,
            header.size);
    }
    if (pagesToPrint < pages.size())
        tsk_fprintf(a_hfile, "Page list limited to %" PRIuDADDR " entries\n",
            pagesToPrint);

    tsk_fs_dir_close(rootDir);
    tsk_fs_file_close(fsFile);
    return 0;
}

/* Optional integrity check; report unsupported until TFFS checks are defined. */
static uint8_t
tffsfsFscheck(TSK_FS_INFO *a_fs, FILE *a_hfile)
{
    if (tsk_verbose)
        tsk_fprintf(stderr, "tffsfsFscheck: called\n");
    (void)a_fs;
    (void)a_hfile;
    return tffsfsNotImplemented("fscheck");
}

/* Free TFFS-owned caches/state, invalidate the tag, and release the TSK FS. */
static void
tffsfsClose(TSK_FS_INFO *a_fs)
{
    if (tsk_verbose)
        tsk_fprintf(stderr, "tffsfsClose: called\n");
    if (a_fs != NULL) {
        delete (TFFS_NAND_STATE *)a_fs->impl;
        a_fs->impl = NULL;
        a_fs->tag = 0;
        tsk_fs_free(a_fs);
    }
}

/* Open an image range as TFFS. Validate the type and image signature, parse
 * geometry and inode bounds, initialize TFFSFS_INFO/TSK_FS_INFO, then register
 * the callbacks below. Validate computed ranges against the image size and
 * verify the root directory before returning. On failure, release all partial
 * state and set a useful TSK error. The final arguments follow TSK's opener
 * convention for password/configuration and auto-detection mode.
 */
TSK_FS_INFO *
tffs_open(TSK_IMG_INFO *a_img_info, TSK_OFF_T a_offset,
    TSK_FS_TYPE_ENUM a_ftype, const char *a_pass, uint8_t a_test)
{
    if (tsk_verbose)
        tsk_fprintf(stderr, "tffs_open: called\n");
    (void)a_pass;
    (void)a_test;
    TSK_FS_INFO *fs;
    uint32_t pageSize;
    TSK_DADDR_T pageCount;
    char magicBuf[TFFS_MAGIC_LEN];
    ssize_t bytesRead;

    tsk_error_reset();

    if (a_img_info == NULL || !TSK_FS_TYPE_ISTFFS(a_ftype) || a_offset < 0) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("tffs_open: invalid image, offset, or file system type");
        return NULL;
    }
    if (a_offset > a_img_info->size) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("tffs_open: image offset is beyond image size");
        return NULL;
    }
    if (a_img_info->size - a_offset < (TSK_OFF_T)TFFS_MAGIC_LEN)
        return tffs_nor_open(a_img_info, a_offset, a_ftype, a_pass, a_test);

    bytesRead = tsk_img_read(a_img_info, a_offset, magicBuf, sizeof(magicBuf));
    if (bytesRead != (ssize_t)sizeof(magicBuf)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_READ);
        tsk_error_set_errstr("tffs_open: could not read file system signature");
        return NULL;
    }
    if (memcmp(magicBuf, TFFS_MAGIC, sizeof(magicBuf)) != 0)
        return tffs_nor_open(a_img_info, a_offset, a_ftype, a_pass, a_test);

    if (tffsfsDetectGeometry(a_img_info, a_offset, &pageSize,
            &pageCount) != 0) {
        return NULL;
    }

    fs = tsk_fs_malloc(sizeof(TSK_FS_INFO));
    if (fs == NULL)
        return NULL;

    TFFS_NAND_STATE *state = new (std::nothrow) TFFS_NAND_STATE();
    if (state == NULL) {
        tsk_fs_free(fs);
        return NULL;
    }

    fs->tag = TSK_FS_INFO_TAG;
    fs->ftype = a_ftype;
    fs->duname = "Page";
    fs->flags = (TSK_FS_INFO_FLAG_ENUM)0;
    fs->img_info = a_img_info;
    fs->offset = a_offset;
    fs->endian = TSK_BIG_ENDIAN;
    fs->impl = state;

    /* Format geometry and inode bounds are supplied by the TFFS parser. */
    /* meta data */
    fs->first_inum = 0;
    fs->root_inum = 0;

    fs->first_block = 0;
    fs->block_count = pageCount;
    fs->last_block = fs->block_count - 1;
    fs->last_block_act = fs->last_block;
    fs->last_inum = fs->last_block;
    fs->inum_count = fs->block_count;

    fs->block_size = pageSize;
    fs->dev_bsize = a_img_info->sector_size;

    if (tffsfsBuildVersionIndex(fs, state) != 0) {
        tffsfsClose(fs);
        return NULL;
    }

    fs->block_walk = tffsfsBlockWalk; // Done
    fs->block_getflags = tffsfsBlockGetFlags; // Done
    fs->inode_walk = tsk_fs_nofs_inode_walk; // TFFS has no Inodes, so use no_walk stub
    fs->file_add_meta = tffsfsFileAddMeta; // Done
    fs->get_default_attr_type = tffsfsGetDefaultAttrType; // Done
    fs->load_attrs = tffsfsLoadAttrs; // Done
    fs->istat = tffsfsIstat;
    fs->dir_open_meta = tffsfsDirOpenMeta;
    fs->jopen = tsk_fs_nofs_jopen; // TFFS has no journal, so use nofs_jopen stub
    fs->jblk_walk = tsk_fs_nofs_jblk_walk; // TFFS has no journal, so use nofs_kblk_walk stub
    fs->jentry_walk = tsk_fs_nofs_jentry_walk; // TFFS has no journal, so use nofs_jentry_walk stub
    fs->fsstat = tffsfsFsstat;
    fs->fscheck = tffsfsFscheck;
    fs->name_cmp = tsk_fs_unix_name_cmp;
    fs->close = tffsfsClose;

    return fs;
}