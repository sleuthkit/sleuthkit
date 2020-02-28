/*
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All rights reserved
 * Copyright (c) 2005 Brian Carrier.  All rights reserved
 *
 * raw
 *
 * This software is distributed under the Common Public License 1.0
 *
 */


/**
 * \file raw.c
 * Internal code to open and read single or split raw disk images
 */

#include "tsk_img_i.h"
#include "raw.h"

#ifdef __APPLE__
#include <sys/disk.h>
#endif

#ifdef TSK_WIN32
#include <winioctl.h>
#else
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#endif

#ifndef S_IFMT
#define S_IFMT __S_IFMT
#endif

#ifndef S_IFDIR
#define S_IFDIR __S_IFDIR
#endif


/** 
 * \internal
 * Read from one of the multiple files in a split set of disk images.
 *
 * @param split_info Disk image info to read from
 * @param idx Index of the disk image in the set to read from
 * @param buf [out] Buffer to write data to
 * @param len Number of bytes to read
 * @param rel_offset Byte offset in the disk image to read from (not the offset in the full disk image set)
 *
 * @return -1 on error or number of bytes read
 */
static ssize_t
raw_read_segment(IMG_RAW_INFO * raw_info, int idx, char *buf,
    size_t len, TSK_OFF_T rel_offset)
{
    IMG_SPLIT_CACHE *cimg;
    ssize_t cnt;

    /* Is the image already open? */
    if (raw_info->cptr[idx] == -1) {
        if (tsk_verbose) {
            tsk_fprintf(stderr,
                "raw_read_segment: opening file into slot %d: %" PRIttocTSK
                "\n", raw_info->next_slot, raw_info->img_info.images[idx]);
        }

        /* Grab the next cache slot */
        cimg = &raw_info->cache[raw_info->next_slot];

        /* Free it if being used */
        if (cimg->fd != 0) {
            if (tsk_verbose) {
                tsk_fprintf(stderr,
                    "raw_read_segment: closing file %" PRIttocTSK "\n",
                    raw_info->img_info.images[cimg->image]);
            }
#ifdef TSK_WIN32
            CloseHandle(cimg->fd);
#else
            close(cimg->fd);
#endif
            raw_info->cptr[cimg->image] = -1;
        }

#ifdef TSK_WIN32
        cimg->fd = CreateFile(raw_info->img_info.images[idx], FILE_READ_DATA,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0,
                              NULL);
        if ( cimg->fd == INVALID_HANDLE_VALUE ) {
            int lastError = (int)GetLastError();
            cimg->fd = 0; /* so we don't close it next time */
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_IMG_OPEN);
            tsk_error_set_errstr("raw_read: file \"%" PRIttocTSK
                                "\" - %d", raw_info->img_info.images[idx], lastError);
            return -1;
        }

#else
        if ((cimg->fd =
                open(raw_info->img_info.images[idx], O_RDONLY | O_BINARY)) < 0) {
            cimg->fd = 0; /* so we don't close it next time */
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_IMG_OPEN);
            tsk_error_set_errstr("raw_read: file \"%" PRIttocTSK
                "\" - %s", raw_info->img_info.images[idx], strerror(errno));
            return -1;
        }
#endif
        cimg->image = idx;
        cimg->seek_pos = 0;
        raw_info->cptr[idx] = raw_info->next_slot;
        if (++raw_info->next_slot == SPLIT_CACHE) {
            raw_info->next_slot = 0;
        }
    }
    else {
        /* image already open */
        cimg = &raw_info->cache[raw_info->cptr[idx]];
    }

#ifdef TSK_WIN32
    {
        // Default to the values that were passed in
        TSK_OFF_T offset_to_read = rel_offset;
        size_t len_to_read = len;
        char ** buf_pointer = &buf;
        char * sector_aligned_buf = NULL;

        // If the offset to seek to isn't sector-aligned and this is a device, we need to start at the previous sector boundary and
        // read some extra data.
        if ((offset_to_read % raw_info->img_info.sector_size != 0)
                && (TSTRNCMP(raw_info->img_info.images[idx], _TSK_T("\\\\.\\"), 4) == 0)) {
            offset_to_read = (offset_to_read / raw_info->img_info.sector_size) * raw_info->img_info.sector_size;
            len_to_read += raw_info->img_info.sector_size; // this length will already be a multiple of sector size
            sector_aligned_buf = (char *)tsk_malloc(len_to_read);
            if (sector_aligned_buf == NULL) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_IMG_READ);
                tsk_error_set_errstr("raw_read: error allocating memory to read file \"%" PRIttocTSK
                    "\" offset: %" PRIdOFF " read len: %" PRIuSIZE,
                    raw_info->img_info.images[idx], offset_to_read, len_to_read);
                return -1;
            }
            buf_pointer = &sector_aligned_buf;
        }

        DWORD nread;
        if (cimg->seek_pos != offset_to_read) {
            LARGE_INTEGER li;
            li.QuadPart = offset_to_read;

            li.LowPart = SetFilePointer(cimg->fd, li.LowPart,
                &li.HighPart, FILE_BEGIN);

            if ((li.LowPart == INVALID_SET_FILE_POINTER) &&
                (GetLastError() != NO_ERROR)) {
                if (sector_aligned_buf != NULL) {
                    free(sector_aligned_buf);
                }
                int lastError = (int)GetLastError();
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_IMG_SEEK);
                tsk_error_set_errstr("raw_read: file \"%" PRIttocTSK
                    "\" offset %" PRIdOFF " seek - %d",
                    raw_info->img_info.images[idx], offset_to_read,
                    lastError);
                return -1;
            }
            cimg->seek_pos = offset_to_read;
        }

        //For physical drive when the buffer is larger than remaining data,
        // WinAPI ReadFile call returns -1
        //in this case buffer of exact length must be passed to ReadFile
        if ((raw_info->is_winobj) && (offset_to_read + (TSK_OFF_T)len_to_read > raw_info->img_info.size ))
            len_to_read = (size_t)(raw_info->img_info.size - offset_to_read);

        if (FALSE == ReadFile(cimg->fd, *buf_pointer, (DWORD)len_to_read, &nread, NULL)) {
            if (sector_aligned_buf != NULL) {
                free(sector_aligned_buf);
            }
            int lastError = GetLastError();
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_IMG_READ);
            tsk_error_set_errstr("raw_read: file \"%" PRIttocTSK
                "\" offset: %" PRIdOFF " read len: %" PRIuSIZE " - %d",
                raw_info->img_info.images[idx], offset_to_read, len_to_read,
                lastError);
            return -1;
        }
        // When the read operation reaches the end of a file,
        // ReadFile returns TRUE and sets nread to zero.
        // We need to check if we've reached the end of a file and set nread to
        // the number of bytes read.
        if ((raw_info->is_winobj) && (nread == 0) && (offset_to_read + len_to_read == raw_info->img_info.size)) {
            nread = (DWORD)len_to_read;
        }
        cnt = (ssize_t) nread;

        if (raw_info->img_writer != NULL) {
            /* img_writer is not used with split images, so rel_offset is just the normal offset*/
            TSK_RETVAL_ENUM result = raw_info->img_writer->add(raw_info->img_writer, offset_to_read, *buf_pointer, cnt);
            // If WriteFile returns error in the addNewBlock, hadErrorExtending is 1
            if (raw_info->img_writer->inFinalizeImageWriter && raw_info->img_writer->hadErrorExtending) {
                if (sector_aligned_buf != NULL) {
                    free(sector_aligned_buf);
                }
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_IMG_WRITE);
                tsk_error_set_errstr("raw_read: file \"%" PRIttocTSK
                    "\" offset: %" PRIdOFF " tsk_img_writer_add cnt: %" PRIuSIZE " - %d",
                    raw_info->img_info.images[idx], offset_to_read, cnt
                    );
                return -1;
            }
        }

        // Update this with the actual bytes read
        cimg->seek_pos += cnt;

        // If we had to do the sector alignment, copy the result into the original buffer and fix
        // the number of bytes read
        if (sector_aligned_buf != NULL) {
            memcpy(buf, sector_aligned_buf + rel_offset % raw_info->img_info.sector_size, len);
            cnt = cnt - offset_to_read % raw_info->img_info.sector_size;
            if (cnt < 0) {
                cnt = -1;
            }
            free(sector_aligned_buf);
        }
    }
#else
    if (cimg->seek_pos != rel_offset) {
        if (lseek(cimg->fd, rel_offset, SEEK_SET) != rel_offset) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_IMG_SEEK);
            tsk_error_set_errstr("raw_read: file \"%" PRIttocTSK
                "\" offset %" PRIdOFF " seek - %s", raw_info->img_info.images[idx],
                rel_offset, strerror(errno));
            return -1;
        }
        cimg->seek_pos = rel_offset;
    }

    cnt = read(cimg->fd, buf, len);
    if (cnt < 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_READ);
        tsk_error_set_errstr("raw_read: file \"%" PRIttocTSK "\" offset: %"
			PRIdOFF " read len: %" PRIuSIZE " - %s", raw_info->img_info.images[idx],
            rel_offset, len, strerror(errno));
        return -1;
    }
    cimg->seek_pos += cnt;
#endif

    return cnt;
}


/** 
 * \internal
 * Read data from a (potentially split) raw disk image.  The offset to
 * start reading from is equal to the volume offset plus the read offset.
 *
 * Note: The routine -assumes- we are under a lock on &(img_info->cache_lock))
 *
 * @param img_info Disk image to read from
 * @param offset Byte offset in image to start reading from
 * @param buf [out] Buffer to write data to
 * @param len Number of bytes to read
 *
 * @return number of bytes read or -1 on error
 */
static ssize_t
raw_read(TSK_IMG_INFO * img_info, TSK_OFF_T offset, char *buf, size_t len)
{
    IMG_RAW_INFO *raw_info = (IMG_RAW_INFO *) img_info;
    int i;

    if (tsk_verbose) {
        tsk_fprintf(stderr,
            "raw_read: byte offset: %" PRIdOFF " len: %" PRIuSIZE "\n",
            offset, len);
    }

    if (offset > img_info->size) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_READ_OFF);
        tsk_error_set_errstr("raw_read: offset %" PRIdOFF " too large",
            offset);
        return -1;
    }

    // Find the location of the offset
    for (i = 0; i < raw_info->img_info.num_img; i++) {

        /* Does the data start in this image? */
        if (offset < raw_info->max_off[i]) {
            TSK_OFF_T rel_offset;
            size_t read_len;
            ssize_t cnt;

            /* Get the offset relative to this image segment */
            if (i > 0) {
                rel_offset = offset - raw_info->max_off[i - 1];
            }
            else {
                rel_offset = offset;
            }

            /* Get the length to read */
            // NOTE: max_off - offset can be a very large number.  Do not cast to size_t
            if (raw_info->max_off[i] - offset >= (TSK_OFF_T)len)
                read_len = len;
            else
                read_len = (size_t) (raw_info->max_off[i] - offset);


            if (tsk_verbose) {
                tsk_fprintf(stderr,
                    "raw_read: found in image %d relative offset: %"
					PRIdOFF " len: %" PRIdOFF "\n", i, rel_offset,
                    (TSK_OFF_T) read_len);
            }

            cnt = raw_read_segment(raw_info, i, buf, read_len, rel_offset);
            if (cnt < 0) {
                return -1;
            }
            if ((size_t) cnt != read_len) {
                return cnt;
            }

            /* read from the next image segment(s) if needed */
            if (((size_t) cnt == read_len) && (read_len != len)) {

                len -= read_len;

                /* go to the next image segment */
                while ((len > 0) && (i+1 < raw_info->img_info.num_img)) {
                    ssize_t cnt2;
                    
                    i++;

                    if ((raw_info->max_off[i] - raw_info->max_off[i - 1]) >= (TSK_OFF_T)len)
                        read_len = len;
                    else
                        read_len = (size_t) (raw_info->max_off[i] - raw_info->max_off[i - 1]);

                    if (tsk_verbose) {
                        tsk_fprintf(stderr,
                            "raw_read: additional image reads: image %d len: %"
							PRIuSIZE "\n", i, read_len);
                    }

                    cnt2 = raw_read_segment(raw_info, i, &buf[cnt],
                        read_len, 0);
                    if (cnt2 < 0) {
                        return -1;
                    }
                    cnt += cnt2;

                    if ((size_t) cnt2 != read_len) {
                        return cnt;
                    }

                    len -= cnt2;
                }
            }
            return cnt;
        }
    }

    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_IMG_READ_OFF);
    tsk_error_set_errstr("raw_read: offset %" PRIdOFF
        " not found in any segments", offset);

    return -1;
}


/** 
 * \internal
 * Display information about the disk image set.
 *
 * @param img_info Disk image to analyze
 * @param hFile Handle to print information to
 */
static void
raw_imgstat(TSK_IMG_INFO * img_info, FILE * hFile)
{
    IMG_RAW_INFO *raw_info = (IMG_RAW_INFO *) img_info;

    tsk_fprintf(hFile, "IMAGE FILE INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "Image Type: raw\n");
    tsk_fprintf(hFile, "\nSize in bytes: %" PRIdOFF "\n", img_info->size);
    tsk_fprintf(hFile, "Sector size:\t%d\n", img_info->sector_size);

    if (raw_info->img_info.num_img > 1) {
        int i;

        tsk_fprintf(hFile,
            "\n--------------------------------------------\n");
        tsk_fprintf(hFile, "Split Information:\n");

        for (i = 0; i < raw_info->img_info.num_img; i++) {
            tsk_fprintf(hFile,
                "%" PRIttocTSK "  (%" PRIdOFF " to %" PRIdOFF ")\n",
                raw_info->img_info.images[i],
                (TSK_OFF_T) (i == 0) ? 0 : raw_info->max_off[i - 1],
                (TSK_OFF_T) (raw_info->max_off[i] - 1));
        }
    }

    return;
}


/** 
 * \internal
 * Free the memory and close the file  handles for the disk image
 *
 * @param img_info Disk image to close
 */
static void
raw_close(TSK_IMG_INFO * img_info)
{
    IMG_RAW_INFO *raw_info = (IMG_RAW_INFO *) img_info;
    int i;

#ifdef TSK_WIN32
    if (raw_info->img_writer != NULL) {
        raw_info->img_writer->close(raw_info->img_writer);
        free(raw_info->img_writer);
        raw_info->img_writer = NULL;
    }
#endif

    for (i = 0; i < SPLIT_CACHE; i++) {
        if (raw_info->cache[i].fd != 0)
#ifdef TSK_WIN32
            CloseHandle(raw_info->cache[i].fd);
#else
            close(raw_info->cache[i].fd);
#endif
    }
    for (i = 0; i < raw_info->img_info.num_img; i++) {
        free(raw_info->img_info.images[i]);
    }
    free(raw_info->max_off);
    free(raw_info->img_info.images);
    free(raw_info->cptr);

    tsk_img_free(raw_info);
}


/**
 * Get the size in bytes of the given file.
 *
 * @param a_file The file to test
 * @param is_winobj 1 if the file is a windows object and not a real file
 *
 * @return the size in bytes, or -1 on error/unknown,
 *         -2 if unreadable, -3 if it's a directory.
 */
static TSK_OFF_T
get_size(const TSK_TCHAR * a_file, uint8_t a_is_winobj)
{
    TSK_OFF_T size = -1;
    struct STAT_STR sb;

    if (TSTAT(a_file, &sb) < 0) {
        if (a_is_winobj) {
            /* stat can fail for Windows objects; ignore that */
            if (tsk_verbose) {
                tsk_fprintf(stderr,
                    "raw_open: ignoring stat result on Windows device %"
                    PRIttocTSK "\n", a_file);
            }
        }
        else {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_IMG_STAT);
            tsk_error_set_errstr("raw_open: image \"%" PRIttocTSK
                "\" - %s", a_file, strerror(errno));
            return -2;
        }
    }
    else if ((sb.st_mode & S_IFMT) == S_IFDIR) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_MAGIC);
        tsk_error_set_errstr("raw_open: image \"%" PRIttocTSK
            "\" - is a directory", a_file);
        return -3;
    }

#ifdef TSK_WIN32
    {
        HANDLE fd;
        DWORD dwHi, dwLo;

        if ((fd = CreateFile(a_file, FILE_READ_DATA,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, 
                    OPEN_EXISTING, 0, NULL)) ==
            INVALID_HANDLE_VALUE) {
            int lastError = (int)GetLastError();
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_IMG_OPEN);
            // print string of commonly found errors
            if (lastError == ERROR_ACCESS_DENIED) {
                tsk_error_set_errstr("raw_open: file \"%" PRIttocTSK
                    "\" - access denied", a_file);
            }
            else if (lastError == ERROR_SHARING_VIOLATION) {
                tsk_error_set_errstr("raw_open: file \"%" PRIttocTSK
                    "\" - sharing violation", a_file);
            }
            else if (lastError == ERROR_FILE_NOT_FOUND) {
                tsk_error_set_errstr("raw_open: file \"%" PRIttocTSK
                    "\" - file not found", a_file);
            }
            else {
                tsk_error_set_errstr("raw_open: file \"%" PRIttocTSK
                    "\" - (error %d)", a_file, lastError);
            }
            return -2;
        }

        /* We need different techniques to determine the size of Windows physical
         * devices versus normal files */
        if (a_is_winobj == 0) {
            dwLo = GetFileSize(fd, &dwHi);
            if (dwLo == 0xffffffff) {
                int lastError = (int)GetLastError();
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_IMG_OPEN);
                tsk_error_set_errstr("raw_open: file \"%" PRIttocTSK
                    "\" - GetFileSize: %d", a_file, lastError);
                size = -1;
            }
            else {
                size = dwLo | ((TSK_OFF_T) dwHi << 32);
            }
        }
        else {
            
            //use GET_PARTITION_INFO_EX prior to IOCTL_DISK_GET_DRIVE_GEOMETRY
            // to determine the physical disk size because
            //calculating it with the help of GET_DRIVE_GEOMETRY gives only
            // approximate number
            DWORD junk;
            
            PARTITION_INFORMATION_EX partition;
            if (FALSE == DeviceIoControl(fd,
                IOCTL_DISK_GET_PARTITION_INFO_EX,
                NULL, 0, &partition, sizeof(partition), &junk,
                (LPOVERLAPPED)NULL) )  {
                DISK_GEOMETRY pdg;

                if (FALSE == DeviceIoControl(fd, IOCTL_DISK_GET_DRIVE_GEOMETRY,
                        NULL, 0, &pdg, sizeof(pdg), &junk, (LPOVERLAPPED) NULL)) {
                    int lastError = (int)GetLastError();
                    tsk_error_reset();
                    tsk_error_set_errno(TSK_ERR_IMG_OPEN);
                    tsk_error_set_errstr("raw_open: file \"%" PRIttocTSK
                        "\" - DeviceIoControl: %d", a_file,
                        lastError);
                    size = -1;
                }
                else {
                    size = pdg.Cylinders.QuadPart *
                        (TSK_OFF_T) pdg.TracksPerCylinder *
                        (TSK_OFF_T) pdg.SectorsPerTrack *
                        (TSK_OFF_T) pdg.BytesPerSector;
                }
            }
            else {
                size = partition.PartitionLength.QuadPart;
            }
        }

        CloseHandle(fd);
    }
#else

    int fd;

    if ((fd = open(a_file, O_RDONLY | O_BINARY)) < 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_OPEN);
        tsk_error_set_errstr("raw_open: file \"%" PRIttocTSK "\" - %s",
            a_file, strerror(errno));
        return -2;
    }

#ifdef __APPLE__
    /* OS X doesn't support SEEK_END on char devices */
    if ((sb.st_mode & S_IFMT) != S_IFCHR) {
        size = lseek(fd, 0, SEEK_END);
    }

    if (size <= 0) {
        int blkSize;
        long long blkCnt;

        if (ioctl(fd, DKIOCGETBLOCKSIZE, &blkSize) >= 0) {
            if (ioctl(fd, DKIOCGETBLOCKCOUNT, &blkCnt) >= 0) {
                size = blkCnt * (long long) blkSize;
            }
        }
    }
#else
    /* We don't use the stat output because it doesn't work on raw
     * devices and such */
    size = lseek(fd, 0, SEEK_END);
#endif

    close(fd);

#endif

    return size;
}


/** 
 * \internal
 * Open the set of disk images as a set of split raw images
 *
 * @param a_num_img Number of images in set
 * @param a_images List of disk image paths (in sorted order)
 * @param a_ssize Size of device sector in bytes (or 0 for default)
 *
 * @return NULL on error
 */
TSK_IMG_INFO *
raw_open(int a_num_img, const TSK_TCHAR * const a_images[],
    unsigned int a_ssize)
{
    IMG_RAW_INFO *raw_info;
    TSK_IMG_INFO *img_info;
    int i;
    TSK_OFF_T first_seg_size;

    if ((raw_info =
            (IMG_RAW_INFO *) tsk_img_malloc(sizeof(IMG_RAW_INFO))) == NULL)
        return NULL;

    img_info = (TSK_IMG_INFO *) raw_info;

    img_info->itype = TSK_IMG_TYPE_RAW;
    img_info->read = raw_read;
    img_info->close = raw_close;
    img_info->imgstat = raw_imgstat;

    img_info->sector_size = 512;
    if (a_ssize)
        img_info->sector_size = a_ssize;
    raw_info->is_winobj = 0;

#if defined(TSK_WIN32) || defined(__CYGWIN__)
    /* determine if this is the path to a Windows device object */
    if ((a_images[0][0] == _TSK_T('\\'))
        && (a_images[0][1] == _TSK_T('\\'))
        && ((a_images[0][2] == _TSK_T('.')) || (a_images[0][2] == _TSK_T('?')))
        && (a_images[0][3] == _TSK_T('\\'))) {
        raw_info->is_winobj = 1;
    }
#endif

    /* Check that the first image file exists and is not a directory */
    first_seg_size = get_size(a_images[0], raw_info->is_winobj);
    if (first_seg_size < -1) {
        tsk_img_free(raw_info);
        return NULL;
    }

    /* see if there are more of them... */
    if ((a_num_img == 1) && (raw_info->is_winobj == 0)) {
        if ((raw_info->img_info.images =
                tsk_img_findFiles(a_images[0],
                    &raw_info->img_info.num_img)) == NULL) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_IMG_STAT);
            tsk_error_set_errstr
                ("raw_open: could not find segment files starting at \"%"
                PRIttocTSK "\"", a_images[0]);
            tsk_img_free(raw_info);
            return NULL;
        }
    }
    else {
        raw_info->img_info.num_img = a_num_img;
        raw_info->img_info.images =
            (TSK_TCHAR **) tsk_malloc(sizeof(TSK_TCHAR *) * a_num_img);
        if (raw_info->img_info.images == NULL) {
            tsk_img_free(raw_info);
            return NULL;
        }

        for (i = 0; i < raw_info->img_info.num_img; i++) {
            size_t len = TSTRLEN(a_images[i]);
            raw_info->img_info.images[i] =
                (TSK_TCHAR *) tsk_malloc(sizeof(TSK_TCHAR) * (len + 1));
            if (raw_info->img_info.images[i] == NULL) {
                int j;
                for (j = 0; j < i; j++) {
                    free(raw_info->img_info.images[j]);
                }
                free(raw_info->img_info.images);
                tsk_img_free(raw_info);
                return NULL;
            }
            TSTRNCPY(raw_info->img_info.images[i], a_images[i], len + 1);
        }
    }

    /* sanity check: when we have multiple segments, the size of
     * each must be known */
    if ((raw_info->img_info.num_img > 1) && (first_seg_size < 0)) {
        if (tsk_verbose) {
            tsk_fprintf(stderr,
                "raw_open: file size is unknown in a segmented raw image\n");
        }

        for (i = 0; i < raw_info->img_info.num_img; i++) {
            free(raw_info->img_info.images[i]);
        }
        free(raw_info->img_info.images);
        tsk_img_free(raw_info);
        return NULL;
    }

    /* initialize the split cache */
    raw_info->cptr = (int *) tsk_malloc(raw_info->img_info.num_img * sizeof(int));
    if (raw_info->cptr == NULL) {
        for (i = 0; i < raw_info->img_info.num_img; i++) {
            free(raw_info->img_info.images[i]);
        }
        free(raw_info->img_info.images);
        tsk_img_free(raw_info);
        return NULL;
    }
    memset((void *) &raw_info->cache, 0,
        SPLIT_CACHE * sizeof(IMG_SPLIT_CACHE));
    raw_info->next_slot = 0;

    /* initialize the offset table and re-use the first segment
     * size gathered above */
    raw_info->max_off =
        (TSK_OFF_T *) tsk_malloc(raw_info->img_info.num_img * sizeof(TSK_OFF_T));
    if (raw_info->max_off == NULL) {
        free(raw_info->cptr);
        for (i = 0; i < raw_info->img_info.num_img; i++) {
            free(raw_info->img_info.images[i]);
        }
        free(raw_info->img_info.images);
        tsk_img_free(raw_info);
        return NULL;
    }
    img_info->size = first_seg_size;
    raw_info->max_off[0] = img_info->size;
    raw_info->cptr[0] = -1;
    if (tsk_verbose) {
        tsk_fprintf(stderr,
            "raw_open: segment: 0  size: %" PRIdOFF "  max offset: %"
			PRIdOFF "  path: %" PRIttocTSK "\n", first_seg_size,
            raw_info->max_off[0], raw_info->img_info.images[0]);
    }

    /* get size info for each file - we do not open each one because that
     * could cause us to run out of file descriptors when we only need a few.
     * The descriptors are opened as needed */
    for (i = 1; i < raw_info->img_info.num_img; i++) {
        TSK_OFF_T size;
        raw_info->cptr[i] = -1;
        size = get_size(raw_info->img_info.images[i], raw_info->is_winobj);
        if (size < 0) {
            if (size == -1) {
                if (tsk_verbose) {
                    tsk_fprintf(stderr,
                        "raw_open: file size is unknown in a segmented raw image\n");
                }
            }
            free(raw_info->cptr);
            for (i = 0; i < raw_info->img_info.num_img; i++) {
                free(raw_info->img_info.images[i]);
            }
            free(raw_info->img_info.images);
            tsk_img_free(raw_info);
            return NULL;
        }

        /* add the size of this image to the total and save the current max */
        img_info->size += size;
        raw_info->max_off[i] = img_info->size;

        if (tsk_verbose) {
            tsk_fprintf(stderr,
                "raw_open: segment: %d  size: %" PRIdOFF "  max offset: %"
				PRIdOFF "  path: %" PRIttocTSK "\n", i, size,
                raw_info->max_off[i], raw_info->img_info.images[i]);
        }
    }

    return img_info;
}


/* tsk_img_malloc - tsk_malloc, then set image tag
 * This is for img module and all its inheritances
 */
void *
tsk_img_malloc(size_t a_len)
{
    TSK_IMG_INFO *imgInfo;
    if ((imgInfo = (TSK_IMG_INFO *) tsk_malloc(a_len)) == NULL)
        return NULL;
    imgInfo->tag = TSK_IMG_INFO_TAG;
    return (void *) imgInfo;
}


/* tsk_img_free - unset image tag, then free memory
 * This is for img module and all its inheritances
 */
void
tsk_img_free(void *a_ptr)
{
    TSK_IMG_INFO *imgInfo = (TSK_IMG_INFO *) a_ptr;
    imgInfo->tag = 0;
    free(imgInfo);
}
