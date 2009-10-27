/*
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2006-2008 Brian Carrier, Basis Technology.  All rights reserved
 * Copyright (c) 2005 Brian Carrier.  All rights reserved
 *
 * raw
 *
 * This software is distributed under the Common Public License 1.0
 *
 */


/**
 * \file raw.c
 * Internal code to open and read single raw disk images
 */

#include "tsk_img_i.h"
#include "raw.h"

#if defined(__APPLE__)
#include <sys/disk.h>
#endif

#ifdef TSK_WIN32
#include "winioctl.h"
#endif


/**
 * Read an arbitrary amount of data from a specific location in a raw image file.
 * This takes two offsets are arguments.  The first is the offset of the volume in the
 * image file and the second is the offset in the volume.  Both are added to find the 
 * actual offset.
 *
 * @param img_info The image to read from.
 * @param offset The byte offset in the image to start reading from
 * @param buf [out] Buffer to store data in
 * @param len Number of bytes to read
 * @returns The number of bytes read or -1 on error -- which can occur if the offset is larger than the img.
 */
static ssize_t
raw_read(TSK_IMG_INFO * img_info, TSK_OFF_T offset, char *buf, size_t len)
{
    ssize_t cnt;
    IMG_RAW_INFO *raw_info = (IMG_RAW_INFO *) img_info;

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "raw_read: byte offset: %" PRIuOFF " len: %" PRIuSIZE "\n",
            offset, len);

    if (offset > img_info->size) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_IMG_READ_OFF;
        snprintf(tsk_errstr, TSK_ERRSTR_L, "raw_read - %" PRIuOFF, offset);
        return -1;
    }

#ifdef TSK_WIN32
    {
        DWORD nread;

        if (raw_info->seek_pos != offset) {
            LARGE_INTEGER li;
            li.QuadPart = offset;

            li.LowPart = SetFilePointer(raw_info->fd, li.LowPart,
                &li.HighPart, FILE_BEGIN);

            if ((li.LowPart == INVALID_SET_FILE_POINTER) && (GetLastError()
                    != NO_ERROR)) {
                tsk_error_reset();
                tsk_errno = TSK_ERR_IMG_SEEK;
                snprintf(tsk_errstr, TSK_ERRSTR_L,
                    "raw_read - %" PRIuOFF, offset);
                return -1;
            }
            raw_info->seek_pos = offset;
        }

        if (FALSE == ReadFile(raw_info->fd, buf, (DWORD) len,
                &nread, NULL)) {
            tsk_error_reset();
            tsk_errno = TSK_ERR_IMG_READ;
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "raw_read - offset: %" PRIuOFF " - len: %zu", offset, len);
            return -1;
        }
        cnt = (ssize_t) nread;
    }
#else
    if (raw_info->seek_pos != offset) {
        if (lseek(raw_info->fd, offset, SEEK_SET) != offset) {
            tsk_error_reset();
            tsk_errno = TSK_ERR_IMG_SEEK;
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "raw_read - %" PRIuOFF " - %s", offset, strerror(errno));
            return -1;
        }
        raw_info->seek_pos = offset;
    }

    cnt = read(raw_info->fd, buf, len);
    if (cnt < 0) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_IMG_READ;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "raw_read - offset: %" PRIuOFF " - len: %" PRIuSIZE " - %s",
            offset, len, strerror(errno));
        return -1;
    }
#endif
    raw_info->seek_pos += cnt;
    return cnt;
}

static void
raw_imgstat(TSK_IMG_INFO * img_info, FILE * hFile)
{
    tsk_fprintf(hFile, "IMAGE FILE INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "Image Type: raw\n");
    tsk_fprintf(hFile, "\nSize in bytes: %" PRIuOFF "\n", img_info->size);
    return;
}

static void
raw_close(TSK_IMG_INFO * img_info)
{
    IMG_RAW_INFO *raw_info = (IMG_RAW_INFO *) img_info;
#ifdef TSK_WIN32
    CloseHandle(raw_info->fd);
#else
    close(raw_info->fd);
#endif
    free(raw_info);
}


/**
 * \internal
 * Open the file as a raw image.  
 * @param image Path to disk image to open.
 * @param a_ssize Size of device sector in bytes (or 0 for default)
 * @returns NULL on error.
 */
TSK_IMG_INFO *
raw_open(const TSK_TCHAR * image, unsigned int a_ssize)
{
    IMG_RAW_INFO *raw_info;
    TSK_IMG_INFO *img_info;
    struct STAT_STR stat_buf;
    int is_winobj = 0;

    if ((raw_info =
            (IMG_RAW_INFO *) tsk_malloc(sizeof(IMG_RAW_INFO))) == NULL)
        return NULL;

    img_info = (TSK_IMG_INFO *) raw_info;

    img_info->itype = TSK_IMG_TYPE_RAW_SING;
    img_info->read = raw_read;
    img_info->close = raw_close;
    img_info->imgstat = raw_imgstat;

    img_info->sector_size = 512;
    if (a_ssize)
        img_info->sector_size = a_ssize;


#if defined(TSK_WIN32) || defined(__CYGWIN__)
    if ((image[0] == _TSK_T('\\'))
        && (image[1] == _TSK_T('\\'))
        && (image[2] == _TSK_T('.'))
        && (image[3] == _TSK_T('\\'))) {
        is_winobj = 1;
    }
#endif
    if (is_winobj == 0) {
        /* Exit if we are given a directory */
        if (TSTAT(image, &stat_buf) < 0) {
            tsk_error_reset();
            tsk_errno = TSK_ERR_IMG_STAT;
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "raw_open: %s", strerror(errno));
            return NULL;
        }
        else if ((stat_buf.st_mode & S_IFMT) == S_IFDIR) {
            if (tsk_verbose)
                TFPRINTF(stderr,
                    _TSK_T("raw_open: image %s is a directory\n"), image);

            tsk_error_reset();
            tsk_errno = TSK_ERR_IMG_MAGIC;
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "raw_open: path is for a directory");
            return NULL;
        }
    }

#ifdef TSK_WIN32
    {
        DWORD dwHi, dwLo;

        if ((raw_info->fd = CreateFile(image, FILE_READ_DATA,
                    FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)) ==
            INVALID_HANDLE_VALUE) {

            // if it is a device, try with SHARE_WRITE
            if ((image[0] == _TSK_T('\\')) && (image[1] == _TSK_T('\\')) &&
                (image[2] == _TSK_T('.')) && (image[3] == _TSK_T('\\'))) {
                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "raw_open: Trying Windows device with share_write mode\n");

                raw_info->fd = CreateFile(image, FILE_READ_DATA,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                    OPEN_EXISTING, 0, NULL);
            }

            if (raw_info->fd == INVALID_HANDLE_VALUE) {
                tsk_error_reset();
                tsk_errno = TSK_ERR_IMG_OPEN;
                // print string of commonly found errors
                if (GetLastError() == ERROR_ACCESS_DENIED) {
                    snprintf(tsk_errstr, TSK_ERRSTR_L,
                        "raw_open file: %" PRIttocTSK " (Access Denied)",
                        image);
                }
                else if (GetLastError() == ERROR_SHARING_VIOLATION) {
                    snprintf(tsk_errstr, TSK_ERRSTR_L,
                        "raw_open file: %" PRIttocTSK
                        " (Sharing Violation)", image);
                }
                else if (GetLastError() == ERROR_FILE_NOT_FOUND) {
                    snprintf(tsk_errstr, TSK_ERRSTR_L,
                        "raw_open file: %" PRIttocTSK " (File not found)",
                        image);
                }
                else {
                    snprintf(tsk_errstr, TSK_ERRSTR_L,
                        "raw_open file: %" PRIttocTSK " (%d)", image,
                        (int) GetLastError());
                }
                return NULL;
            }
        }

        /* We need different techniques to determine the size of physical
         * devices versus normal files
         */
        if (is_winobj == 0) {
            dwLo = GetFileSize(raw_info->fd, &dwHi);
            if (dwLo == 0xffffffff) {
                tsk_error_reset();
                tsk_errno = TSK_ERR_IMG_OPEN;
                snprintf(tsk_errstr, TSK_ERRSTR_L,
                    "raw_open file: %" PRIttocTSK " GetFileSize: %d",
                    image, (int) GetLastError());
                return NULL;
            }
            img_info->size = dwLo | ((TSK_OFF_T) dwHi << 32);
        }
        else {
            DISK_GEOMETRY pdg;
            DWORD junk;

            if (FALSE == DeviceIoControl(raw_info->fd,  // device to be queried
                    IOCTL_DISK_GET_DRIVE_GEOMETRY,      // operation to perform
                    NULL, 0, &pdg, sizeof(pdg), &junk,
                    (LPOVERLAPPED) NULL)) {
                tsk_error_reset();
                tsk_errno = TSK_ERR_IMG_OPEN;
                snprintf(tsk_errstr, TSK_ERRSTR_L,
                    "raw_open file: %" PRIttocTSK
                    " DeviceIoControl: %d", image, (int) GetLastError());
                return NULL;
            }

            img_info->size =
                pdg.Cylinders.QuadPart *
                (TSK_OFF_T) pdg.TracksPerCylinder *
                (TSK_OFF_T) pdg.SectorsPerTrack *
                (TSK_OFF_T) pdg.BytesPerSector;
        }
    }
#else
    if ((raw_info->fd = open(image, O_RDONLY | O_BINARY)) < 0) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_IMG_OPEN;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "raw_open file: %" PRIttocTSK " msg: %s", image,
            strerror(errno));
        return NULL;
    }

#if defined(__APPLE__)
    /* OS X doesn't support SEEK_END on char devices */
    if ((stat_buf.st_mode & S_IFMT) != S_IFCHR) {
        img_info->size = lseek(raw_info->fd, 0, SEEK_END);
        lseek(raw_info->fd, 0, SEEK_SET);
    }

    if (img_info->size == 0) {
        int blkSize;
        long long blkCnt;

        if (ioctl(raw_info->fd, DKIOCGETBLOCKSIZE, &blkSize) >= 0) {
            if (ioctl(raw_info->fd, DKIOCGETBLOCKCOUNT, &blkCnt) >= 0) {
                img_info->size = blkCnt * (long long) blkSize;
            }
        }
    }
#else
    /* We don't use the stat output because it doesn't work on raw
     * devices and such */
    img_info->size = lseek(raw_info->fd, 0, SEEK_END);
    lseek(raw_info->fd, 0, SEEK_SET);
#endif

#endif
    raw_info->seek_pos = 0;

    return img_info;
}
