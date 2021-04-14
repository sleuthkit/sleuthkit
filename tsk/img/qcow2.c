/*
 * Copyright (c) 2017 Communication Security Establishment.  All rights reserved
 *
 * qcow2
 *
 * This software is distributed under the Common Public License 1.0
 */

/**
* \file qcow2.c
* Internal code to open and read qcow2 files with backing file support.
*/


#include "tsk_img_i.h"
#include "qcow2.h"

#ifdef HAVE_LIBZ
/* Compressed cluster support */
#include <zlib.h>

#define QCOW_ZLIB_BITLEN(cluster_bits)         (70 - cluster_bits)
#define QCOW_ZLIB_HOST_OFFSET(entry,bitlen)    ((entry) & (((uint64_t)1 << bitlen) - 1))

#endif

#ifdef TSK_WIN32
#define QCOW_INVALID_HANDLE INVALID_HANDLE_VALUE
#define QCOW_ERRORNO        ((int)GetLastError())
static void QCOW_CLOSE_FILE(QCOW_FILE_T h)
{
    CloseHandle(h);
}
static QCOW_FILE_T QCOW_OPEN_FILE(const TSK_TCHAR * name)
{
    return CreateFile(name, FILE_READ_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
}
static int QCOW_SEEK_FILE(QCOW_FILE_T h, TSK_OFF_T offset)
{
    DWORD nread;
    LARGE_INTEGER li;
    li.QuadPart = offset;

    li.LowPart = SetFilePointer(h, li.LowPart, &li.HighPart, FILE_BEGIN);

    return (li.LowPart != INVALID_SET_FILE_POINTER) || (GetLastError() == NO_ERROR);
}
static int QCOW_READ_FILE(QCOW_FILE_T h, void *buf, size_t len, ssize_t *read)
{
    DWORD nread;
    int ret = ReadFile(h, buf, (DWORD)len, &nread, NULL);
    if (ret)
    {
        *read = nread;
    }
    return ret;
}
int QCOW2_NORMALIZE_PATH(const TSK_TCHAR * path, IMG_QCOW2_INFO * q)
{
    UTF16 *utf16 = (UTF16 *)path;
    size_t ilen = wcslen(utf16);
    size_t olen = ilen * 4 + 1;
    UTF8 *utf8;
    if ((utf8 = (UTF8 *)tsk_malloc(olen)) == NULL)
    {
        return 0;
    }
    TSKConversionResult retval =
        tsk_UTF16toUTF8_lclorder((const UTF16 **)&utf16,
            &utf16[ilen], &utf8,
            &utf8[olen], TSKlenientConversion);

    *utf8 = '\0';
    if (retval != TSKconversionOK)
    {
        goto error;
    }

    q->meta.image_name = utf8;
    q->meta.image_path = utf8;

    while (*utf8) {
        if (*utf8 == '\\' || *utf8 == '/')
        {
            *utf8 = '/';
            q->meta.image_name = utf8 + 1;
        }
        utf8++;
    }
    if (strlen(q->meta.image_name) == 0)
    {
        goto error;
    }
    return 1;
error:
    if (utf8)
    {
        free(utf8);
    }
    q->meta.image_name = NULL;
    q->meta.image_path = NULL;
    return 0;
}
#else
#define QCOW_INVALID_HANDLE -1
#define QCOW_ERRORNO        (errno)
static void QCOW_CLOSE_FILE(QCOW_FILE_T h)
{
    close(h);
}
static QCOW_FILE_T QCOW_OPEN_FILE(const TSK_TCHAR * name)
{
    return open(name, O_RDONLY | O_BINARY);
}
static int QCOW_SEEK_FILE(QCOW_FILE_T h, TSK_OFF_T offset)
{
    return lseek(h, offset, SEEK_SET) == offset;
}
static int QCOW_READ_FILE(QCOW_FILE_T h, void *buf, size_t len, ssize_t *nread)
{
    ssize_t _nread;
    _nread = read(h, buf, len);
    if (_nread >= 0)
    {
        *nread = _nread;
    }
    return _nread >= 0;
}
int QCOW2_NORMALIZE_PATH(const TSK_TCHAR * path, IMG_QCOW2_INFO * q)
{
    UTF8 *utf8;
    if ((utf8 = (UTF8 *)strdup(path)) == NULL)
    {
        return 0;
    }

    q->meta.image_name = utf8;
    q->meta.image_path = utf8;

    while (*utf8) {
        if (*utf8 == '/')
        {
            q->meta.image_name = utf8 + 1;
        }
        utf8++;
    }
    if (strlen((void*)q->meta.image_name) == 0)
    {
        goto error;
    }
    return 1;
error:
    if (utf8)
    {
        free(utf8);
    }
    q->meta.image_name = NULL;
    q->meta.image_path = NULL;
    return 0;
}
#endif

#define QCOW_SET_ERROR(err_val, msg, ...)    { \
    tsk_error_reset(); \
    tsk_error_set_errno(TSK_ERR_FS_UNICODE); \
    tsk_error_set_errstr(msg, ##__VA_ARGS__ ); \
};

static void
qcow2_close(TSK_IMG_INFO * img_info)
{
    int i, end;
    IMG_QCOW2_INFO *qcow_info = (IMG_QCOW2_INFO *)img_info;
    if (qcow_info == NULL)
    {
        return;
    }

    for (i = 0, end = img_info->num_img; i < end; ++i)
    {
        free(img_info->images[i]);
    }
    free(img_info->images);

    if (qcow_info->meta.backing_meta)
    {
        qcow2_close((TSK_IMG_INFO *)qcow_info->meta.backing_meta);
    }

    if (qcow_info->meta.comp_buffer)
    {
        free(qcow_info->meta.comp_buffer);
    }
    if (qcow_info->meta.ucmp_buffer)
    {
        free(qcow_info->meta.ucmp_buffer);
    }
    if (qcow_info->meta.l1_cache)
    {
        free(qcow_info->meta.l1_cache);
    }
    if (qcow_info->meta.image_path)
    {
        free(qcow_info->meta.image_path);
    }
    if (qcow_info->meta.backing_path)
    {
        free(qcow_info->meta.backing_path);
    }
    if (qcow_info->meta.handle != QCOW_INVALID_HANDLE)
    {
        QCOW_CLOSE_FILE(qcow_info->meta.handle);
    }

    tsk_img_free(qcow_info);
}

static ssize_t
qcow2_read(TSK_IMG_INFO * img_info, TSK_OFF_T offset, char *buf, size_t len)
{
    IMG_QCOW2_INFO *qcow_info = (IMG_QCOW2_INFO *)img_info;
    IMG_QCOW2_INFO *qcow_ptr = qcow_info;
    uint64_t cluster_bytes = qcow_info->meta.cluster_bytes;
    ssize_t nread;

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "qcow2_read: byte offset: %" PRIdOFF " len: %" PRIdOFF
            "\n", offset, len);

    if (offset > img_info->size) {
        QCOW_SET_ERROR(TSK_ERR_IMG_READ_OFF, "qcow2_read: offset past image end - %" PRIdOFF, offset);
        return -1;
    }
    if (len > cluster_bytes)
    {
        /* Read is larger than a cluster */
        ssize_t a = qcow2_read(img_info, offset, buf, cluster_bytes);
        ssize_t b = qcow2_read(img_info, offset + cluster_bytes, buf + cluster_bytes, len - cluster_bytes);
        if (a == -1 || b == -1)
        {
            return -1;
        }
        return a + b;
    }

    uint64_t entry_table_len = (qcow_info->meta.cluster_bytes / sizeof(uint64_t));
    uint64_t l2_index = (offset / qcow_info->meta.cluster_bytes) % entry_table_len;
    uint64_t l1_index = (offset / qcow_info->meta.cluster_bytes) / entry_table_len;
    ssize_t cluster_offset = (offset % qcow_info->meta.cluster_bytes);

    while (qcow_ptr)
    {
        if (l1_index < qcow_ptr->header.l1_size &&      /* l1 index exists in this file */
            qcow_ptr->meta.l1_cache[l1_index].in_use)   /* l1 points to a valid l2 */
        {
            if (QCOW_SEEK_FILE(qcow_ptr->meta.handle,
                qcow_ptr->meta.l1_cache[l1_index].l2_offset + l2_index*sizeof(QCOW_2_L2_entry)) == 0)
            {
                QCOW_SET_ERROR(TSK_ERR_IMG_SEEK, "Cannot seek to l2 table - %d", QCOW_ERRORNO);
                return -1;
            }

            QCOW_2_L2_entry entry;
            if (QCOW_READ_FILE(qcow_ptr->meta.handle, (void*)&entry, sizeof(QCOW_2_L2_entry), &nread) == 0)
            {
                QCOW_SET_ERROR(TSK_ERR_IMG_READ, "Could not read l2 entry - %d", QCOW_ERRORNO);
                return -1;
            }

            entry.entry = tsk_getu64(TSK_BIG_ENDIAN, &entry.entry);

            if (entry.offset)
            {
                ssize_t remainder = len + cluster_offset - qcow_info->meta.cluster_bytes;
                if( remainder < 0)
                {
                    remainder = 0;
                }

                if (entry.compressed)
                {
#ifndef HAVE_LIBZ
                    QCOW_SET_ERROR(TSK_ERR_IMG_READ, "TSK not built with zlib support.");
                    return -1;
#else
                    uint64_t bitlen = QCOW_ZLIB_BITLEN(qcow_info->header.cluster_bits);
                    uint64_t block_offset = QCOW_ZLIB_HOST_OFFSET(entry.compressed_entry, bitlen);
                    uint64_t block_len = qcow_info->meta.cluster_bytes;
                    size_t nwrote = 0;

                    if (block_len > qcow_info->meta.cluster_bytes)
                    {
                        QCOW_SET_ERROR(TSK_ERR_IMG_READ, "Compressed cluster is larger than cluster size (%ld)", block_len);
                        return -1;
                    }

                    /* Need to allocate the buffer on first use. */
                    if (qcow_info->meta.comp_buffer == NULL)
                    {
                        if ((qcow_info->meta.comp_buffer = tsk_malloc(qcow_info->meta.cluster_bytes)) == NULL ||
                            (qcow_info->meta.ucmp_buffer = tsk_malloc(qcow_info->meta.cluster_bytes)) == NULL)
                        {
                            return -1;
                        }
                    }

                    if (QCOW_SEEK_FILE(qcow_ptr->meta.handle, block_offset) == 0)
                    {
                        QCOW_SET_ERROR(TSK_ERR_IMG_SEEK, "Cannot seek to host cluster - %d", QCOW_ERRORNO);
                        return -1;
                    }

                    if (QCOW_READ_FILE(qcow_ptr->meta.handle, qcow_info->meta.comp_buffer, block_len, &nread) == 0 ||
                        nread != block_len)
                    {
                        QCOW_SET_ERROR(TSK_ERR_IMG_READ, "Could not read host cluster - %d", QCOW_ERRORNO);
                        return -1;
                    }


                    if (zlib_inflate(qcow_info->meta.comp_buffer, block_len,
                                     qcow_info->meta.ucmp_buffer, qcow_info->meta.cluster_bytes, &nwrote) != Z_OK)
                    {
                        QCOW_SET_ERROR(TSK_ERR_IMG_READ, "Could not inflate cluster.");
                        return -1;
                    }

                    /* Verify entire read was inflated */
                    if ((len + cluster_offset - remainder) > nwrote)
                    {
                        QCOW_SET_ERROR(TSK_ERR_IMG_READ, "Inflated cluster does not contain read region.");
                        return -1;
                    }
                    memcpy(buf, (uint8_t*)qcow_info->meta.ucmp_buffer + cluster_offset, len - remainder);

                    nread = len - remainder;
#endif
                }
                else
                {
                    if (QCOW_SEEK_FILE(qcow_ptr->meta.handle, entry.offset + cluster_offset) == 0)
                    {
                        QCOW_SET_ERROR(TSK_ERR_IMG_SEEK, "Cannot seek to host cluster - %d", QCOW_ERRORNO);
                        return -1;
                    }

                    if (QCOW_READ_FILE(qcow_ptr->meta.handle, buf, len - remainder, &nread) == 0 ||
                        nread != len - remainder)
                    {
                        QCOW_SET_ERROR(TSK_ERR_IMG_READ, "Could not read host cluster - %d", QCOW_ERRORNO);
                        return -1;
                    }
                }

                if (remainder > 0)
                {
                    nread += qcow2_read(img_info, offset + nread, buf + nread, remainder);
                }
                return nread;

            }
            /* else: cache miss */
        }

        /* cache miss */
        qcow_ptr = qcow_ptr->meta.backing_meta;
    }

    /* Block is sparce */
    memset(buf, 0, len);
    return len;
}

static void
qcow2_imgstat(TSK_IMG_INFO * img_info, FILE * hFile)
{
    IMG_QCOW2_INFO *qcow_info = (IMG_QCOW2_INFO*)img_info;
    tsk_fprintf(hFile, "IMAGE FILE INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "Image Type: qcow2\n");
    tsk_fprintf(hFile, "\nSize in bytes: %" PRIdOFF "\n", img_info->size);
    tsk_fprintf(hFile, "Version: %d\n", (int)qcow_info->header.version);
    tsk_fprintf(hFile, "Cluster size: %d\n", (int)qcow_info->meta.cluster_bytes);
    return;
}

IMG_QCOW2_INFO *
qcow2_init_file(const TSK_TCHAR * path)
{
    IMG_QCOW2_INFO *qcow_info = NULL;
    QCOW_FILE_T h = QCOW_INVALID_HANDLE;
    ssize_t read;
    int i;

    if ((qcow_info =
        (IMG_QCOW2_INFO *)tsk_img_malloc(sizeof(IMG_QCOW2_INFO))) == NULL)
        return NULL;

    if (QCOW2_NORMALIZE_PATH(path, qcow_info) == 0)
    {
        QCOW_SET_ERROR(TSK_ERR_FS_UNICODE, "Error converting path to UTF-8 \"%" PRIttocTSK "\"", path);
        goto error;
    }

    h = QCOW_OPEN_FILE(path);

    if (h == QCOW_INVALID_HANDLE)
    {
        QCOW_SET_ERROR(TSK_ERR_IMG_OPEN, "Could not open file \"%" PRIttocTSK "\" - %d", path, QCOW_ERRORNO);
        goto error;
    }
    qcow_info->meta.handle = h;

    if (QCOW_READ_FILE(h, (void*)&qcow_info->header, sizeof(qcow_info->header), &read) == 0)
    {
        QCOW_SET_ERROR(TSK_ERR_IMG_READ, "Could not read file \"%" PRIttocTSK "\" - %d", path, QCOW_ERRORNO);
        goto error;
    }

    /* File is big endian */
    qcow_info->header.magic = tsk_getu32(TSK_BIG_ENDIAN, &qcow_info->header.magic);
    qcow_info->header.version = tsk_getu32(TSK_BIG_ENDIAN, &qcow_info->header.version);
    qcow_info->header.backing_file_offset = tsk_getu64(TSK_BIG_ENDIAN, &qcow_info->header.backing_file_offset);
    qcow_info->header.backing_file_size = tsk_getu32(TSK_BIG_ENDIAN, &qcow_info->header.backing_file_size);
    qcow_info->header.cluster_bits = tsk_getu32(TSK_BIG_ENDIAN, &qcow_info->header.cluster_bits);
    qcow_info->header.size = tsk_getu64(TSK_BIG_ENDIAN, &qcow_info->header.size);
    qcow_info->header.crypt_method = tsk_getu32(TSK_BIG_ENDIAN, &qcow_info->header.crypt_method);
    qcow_info->header.l1_size = tsk_getu32(TSK_BIG_ENDIAN, &qcow_info->header.l1_size);
    qcow_info->header.l1_table_offset = tsk_getu64(TSK_BIG_ENDIAN, &qcow_info->header.l1_table_offset);
    qcow_info->header.refcount_table_offset = tsk_getu64(TSK_BIG_ENDIAN, &qcow_info->header.refcount_table_offset);
    qcow_info->header.refcount_table_clusters = tsk_getu32(TSK_BIG_ENDIAN, &qcow_info->header.refcount_table_clusters);
    qcow_info->header.nb_snapshots = tsk_getu32(TSK_BIG_ENDIAN, &qcow_info->header.nb_snapshots);
    qcow_info->header.snapshots_offset = tsk_getu64(TSK_BIG_ENDIAN, &qcow_info->header.snapshots_offset);

    if (qcow_info->header.magic != 0x514649fb)
    {
        QCOW_SET_ERROR(TSK_ERR_IMG_MAGIC, "File \"%" PRIttocTSK "\" is not a qcow image", path);
        goto error;
    }

    if (qcow_info->header.crypt_method)
    {
        QCOW_SET_ERROR(TSK_ERR_IMG_UNSUPTYPE, "File \"%" PRIttocTSK "\" is encrypted", path);
        goto error;
    }

    if (qcow_info->header.cluster_bits < 9 || qcow_info->header.cluster_bits > 21)
    {
        QCOW_SET_ERROR(TSK_ERR_IMG_UNSUPTYPE, "File \"%" PRIttocTSK "\" has invalid cluster size", path);
        goto error;
    }
    qcow_info->meta.cluster_bytes = 1 << qcow_info->header.cluster_bits;

    /* Cache L1 cache */
    if ((qcow_info->meta.l1_cache =
        (QCOW_2_L1_entry *)tsk_malloc(qcow_info->header.l1_size * sizeof(QCOW_2_L1_entry))) == NULL)
    {
        goto error;
    }
    if (QCOW_SEEK_FILE(h, qcow_info->header.l1_table_offset) == 0)
    {
        QCOW_SET_ERROR(TSK_ERR_IMG_MAGIC, "File \"%" PRIttocTSK "\" has invalid l1 table", path);
        goto error;
    }

    if (QCOW_READ_FILE(h, qcow_info->meta.l1_cache,
        qcow_info->header.l1_size * sizeof(QCOW_2_L1_entry), &read) == 0 ||
        read != (qcow_info->header.l1_size * sizeof(QCOW_2_L1_entry)))
    {
        QCOW_SET_ERROR(TSK_ERR_IMG_MAGIC, "File \"%" PRIttocTSK "\" has invalid l1 table", path);
        goto error;
    }
    for (i = 0; i < qcow_info->header.l1_size; i++)
    {
        qcow_info->meta.l1_cache[i].entry = tsk_getu64(TSK_BIG_ENDIAN, &qcow_info->meta.l1_cache[i].entry);
    }

    /* Extract backing file */
    if (qcow_info->header.backing_file_offset && qcow_info->header.backing_file_size)
    {
        if ((qcow_info->header.backing_file_offset + qcow_info->header.backing_file_size)
            > qcow_info->meta.cluster_bytes)
        {
            QCOW_SET_ERROR(TSK_ERR_IMG_MAGIC, "File \"%" PRIttocTSK "\" has invalid backing file", path);
            goto error;
        }
        if ((qcow_info->meta.backing_path =
            (UTF8 *)tsk_malloc(qcow_info->header.backing_file_size + sizeof(UTF8))) == NULL)
        {
            goto error;
        }

        if (QCOW_SEEK_FILE(h, qcow_info->header.backing_file_offset) == 0)
        {
            QCOW_SET_ERROR(TSK_ERR_IMG_MAGIC, "File \"%" PRIttocTSK "\" has invalid backing file", path);
            goto error;
        }

        if (QCOW_READ_FILE(h, qcow_info->meta.backing_path, qcow_info->header.backing_file_size, &read) == 0 ||
            read != qcow_info->header.backing_file_size)
        {
            QCOW_SET_ERROR(TSK_ERR_IMG_MAGIC, "File \"%" PRIttocTSK "\" has invalid backing file", path);
            goto error;
        }
        qcow_info->meta.backing_name = qcow_info->meta.backing_path;
        for(i=0; i < qcow_info->header.backing_file_size; i++)
        {
            if(qcow_info->meta.backing_path[i] == '/')
            {
                qcow_info->meta.backing_name = qcow_info->meta.backing_path + i;
            }
        }
    }
    return qcow_info;
error:
    qcow2_close((TSK_IMG_INFO *)qcow_info);

    return NULL;
}

TSK_IMG_INFO *
qcow2_open(int a_num_img, const TSK_TCHAR * const images[], unsigned int a_ssize)
{
    IMG_QCOW2_INFO *qcow_info = NULL;
    TSK_IMG_INFO *img_info = NULL;
    IMG_QCOW2_INFO **qcow_info_list = NULL;
    int remaining_size = a_num_img;
    int i, j;

    if ((qcow_info_list =
        (IMG_QCOW2_INFO **)tsk_img_malloc(a_num_img * sizeof(void*))) == NULL)
        return NULL;

    /* Open all provided images */
    for (i = 0; i < a_num_img; i++)
    {
        qcow_info_list[i] = qcow2_init_file(images[i]);
        if (qcow_info_list[i] == NULL)
        {
            goto error;
        }

        qcow_info_list[i]->img_info.sector_size = 512;
        if (a_ssize)
        {
            qcow_info_list[i]->img_info.sector_size = a_ssize;
        }
    }

    /* Connect backing files, shrink backing file list */

    for (i = 0; i < remaining_size; i++)
    {
        for (j = 0; j < remaining_size; j++)
        {
            if (i == j || !qcow_info_list[j]->meta.backing_name)
            {
                continue;
            }
            if (strcmp((void*)qcow_info_list[i]->meta.image_name,
                        (void*)qcow_info_list[j]->meta.backing_name) == 0)
            {
                qcow_info_list[j]->meta.backing_meta = qcow_info_list[i];
                /* remove i from image list */
                if (i != remaining_size - 1)
                {
                    memmove(&qcow_info_list[i], &qcow_info_list[i+1], sizeof(void*) * (remaining_size - i));
                }
                i--;
                remaining_size--;
                break;
            }
        }
    }

    if (remaining_size != 1)
    {
        QCOW_SET_ERROR(TSK_ERR_IMG_ARG, "Invalid parameters, not all images are part of the same hard disk.");
        goto error;
    }
    IMG_QCOW2_INFO *ptr = qcow_info_list[0];
    /* check for loop or missing backing file */
    for (i = 0; ptr && i < 20; i++)
    {
        if (ptr->meta.backing_meta)
        {
            /* sanity check, make sure all cluster sizes are identical */
            if (ptr->header.cluster_bits != ptr->meta.backing_meta->header.cluster_bits)
            {
                QCOW_SET_ERROR(TSK_ERR_IMG_UNSUPTYPE, "Cluster size mismatch between  \"%s\" and \"%s\".",
                    ptr->meta.image_path, ptr->meta.backing_meta->meta.image_path);
                goto error;
            }
            ptr = ptr->meta.backing_meta;
        }
        else if (ptr->meta.backing_path)
        {
            QCOW_SET_ERROR(TSK_ERR_IMG_ARG, "Either too many backing files or backing file loop.");
            goto error;
        }
        ptr = ptr->meta.backing_meta;
    }
    if (ptr)
    {
        QCOW_SET_ERROR(TSK_ERR_IMG_ARG, "Either too many backing files or backing file loop.");
        goto error;
    }

    qcow_info = qcow_info_list[0];
    img_info = (TSK_IMG_INFO *)qcow_info;

    img_info->read = qcow2_read;
    img_info->close = qcow2_close;
    img_info->imgstat = qcow2_imgstat;
    img_info->num_img = a_num_img;
    img_info->size = qcow_info->header.size;

    img_info->images =
        (TSK_TCHAR **)tsk_malloc(sizeof(TSK_TCHAR *) * img_info->num_img);

    if (img_info->images == NULL) {
        goto error;
    }

    for (i = 0; i < a_num_img; i++)
    {
        size_t len = TSTRLEN(images[i]);
        img_info->images[i] = (TSK_TCHAR *)tsk_malloc(sizeof(TSK_TCHAR) * (len + 1));
        if (img_info->images[i] == NULL)
        {
            goto error;
        }

        TSTRNCPY(img_info->images[i], images[i], len + 1);
    }


    TSK_IMG_INFO *retVal = (TSK_IMG_INFO *)qcow_info_list[0];
    free(qcow_info_list);
    return retVal;

error:
    if (img_info && img_info->images)
    {
        for (i = 0; i < a_num_img; i++)
        {
            if (img_info->images[i])
            {
                free(img_info->images[i]);
            }
            else
            {
                break;
            }
        }
    }
    if (qcow_info_list)
    {
        for (i = 0; i < remaining_size; i++)
        {
            qcow2_close((TSK_IMG_INFO *)qcow_info_list[i]);
        }
        free(qcow_info_list);
    }
    return NULL;
}

