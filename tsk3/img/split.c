/*
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2006-2008 Brian Carrier, Basis Technology.  All rights reserved
 * Copyright (c) 2005 Brian Carrier.  All rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 *
 */

/**
 * \file split.c
 * Internal code to handle opening and reading of split raw disk images.
 */

#include "tsk_img_i.h"
#include "split.h"


/** 
 * \internal
 * Read from one of the multiple files in a split set of disk images.
 *
 * @param split_info Disk image info to read from
 * @param idx Index of the disk image in the set to read from
 * @param buf [out] Buffer to write data to
 * @param len Number of bytes to read
 * @param rel_offset Byte offset in the disk image to read from (not the offset in the full disk image set)
 * @return -1 on error or number of bytes read
 */
static ssize_t
split_read_segment(IMG_SPLIT_INFO * split_info, int idx, char *buf,
    size_t len, TSK_OFF_T rel_offset)
{
    IMG_SPLIT_CACHE *cimg;
    ssize_t cnt;

    /* Is the image already open? */
    if (split_info->cptr[idx] == -1) {
        if (tsk_verbose)
            tsk_fprintf(stderr,
                "split_read_rand: opening file into slot %d %" PRIttocTSK
                "\n", split_info->next_slot, split_info->images[idx]);

        /* Grab the next cache slot */
        cimg = &split_info->cache[split_info->next_slot];

        /* Free it if being used */
        if (cimg->fd != 0) {
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "split_read_rand: closing file %" PRIttocTSK "\n",
                    split_info->images[cimg->image]);
#ifdef TSK_WIN32
            CloseHandle(cimg->fd);
#else
            close(cimg->fd);
#endif
            split_info->cptr[cimg->image] = -1;
        }

#ifdef TSK_WIN32
        if ((cimg->fd = CreateFile(split_info->images[idx], FILE_READ_DATA,
                    FILE_SHARE_READ, NULL, OPEN_EXISTING, 0,
                    NULL)) == INVALID_HANDLE_VALUE) {
            tsk_error_reset();
            tsk_errno = TSK_ERR_IMG_OPEN;
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "split_read file: %" PRIttocTSK " msg: %d",
                split_info->images[idx], (int) GetLastError());
            return -1;
        }
#else
        if ((cimg->fd =
                open(split_info->images[idx], O_RDONLY | O_BINARY)) < 0) {
            tsk_error_reset();
            tsk_errno = TSK_ERR_IMG_OPEN;
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "split_read file: %" PRIttocTSK " msg: %s",
                split_info->images[idx], strerror(errno));
            return -1;
        }
#endif
        cimg->image = idx;
        cimg->seek_pos = 0;
        split_info->cptr[idx] = split_info->next_slot;
        if (++split_info->next_slot == SPLIT_CACHE) {
            split_info->next_slot = 0;
        }
    }
    else {
        cimg = &split_info->cache[split_info->cptr[idx]];
    }

#ifdef TSK_WIN32
    {
        DWORD nread;
        if (cimg->seek_pos != rel_offset) {
            LARGE_INTEGER li;
            li.QuadPart = rel_offset;

            li.LowPart = SetFilePointer(cimg->fd, li.LowPart,
                &li.HighPart, FILE_BEGIN);

            if ((li.LowPart == INVALID_SET_FILE_POINTER) &&
                (GetLastError() != NO_ERROR)) {
                tsk_error_reset();
                tsk_errno = TSK_ERR_IMG_SEEK;
                snprintf(tsk_errstr, TSK_ERRSTR_L,
                    "split_read - %" PRIuOFF, rel_offset);
                return -1;
            }
            cimg->seek_pos = rel_offset;
        }

        if (FALSE == ReadFile(cimg->fd, buf, (DWORD) len, &nread, NULL)) {
            tsk_error_reset();
            tsk_errno = TSK_ERR_IMG_READ;
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "split_read - offset: %" PRIuOFF " - len: %" PRIuSIZE "",
                rel_offset, len);
            return -1;
        }
        cnt = (ssize_t) nread;
    }
#else
    if (cimg->seek_pos != rel_offset) {
        if (lseek(cimg->fd, rel_offset, SEEK_SET) != rel_offset) {
            tsk_error_reset();
            tsk_errno = TSK_ERR_IMG_SEEK;
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "split_read - %s - %" PRIuOFF " - %s",
                split_info->images[idx], rel_offset, strerror(errno));
            return -1;
        }
        cimg->seek_pos = rel_offset;
    }

    cnt = read(cimg->fd, buf, len);
    if (cnt < 0) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_IMG_READ;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "split_read - offset: %" PRIuOFF
            " - len: %" PRIuSIZE " - %s", rel_offset, len,
            strerror(errno));
        return -1;
    }
#endif
    cimg->seek_pos += cnt;

    return cnt;
}

/** 
 * \internal
 * Read data from a split disk image.  The offset to start reading from is 
 * equal to the volume offset plus the read offset.
 *
 * @param img_info Disk image to read from
 * @param offset Byte offset in image to start reading from
 * @param buf [out] Buffer to write data to
 * @param len Number of bytes to read
 * @return number of bytes read or -1 on error
 */
static ssize_t
split_read(TSK_IMG_INFO * img_info, TSK_OFF_T offset, char *buf,
    size_t len)
{
    IMG_SPLIT_INFO *split_info = (IMG_SPLIT_INFO *) img_info;
    int i;

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "split_read: byte offset: %" PRIuOFF " len: %"
            PRIuOFF "\n", offset, len);

    if (offset > img_info->size) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_IMG_READ_OFF;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "split_read - %" PRIuOFF, offset);
        return -1;
    }

    // Find the location of the offset
    for (i = 0; i < split_info->num_img; i++) {

        /* Does the data start in this image? */
        if (offset < split_info->max_off[i]) {
            TSK_OFF_T rel_offset;
            size_t read_len;
            ssize_t cnt;

            /* Get the offset relative to this image */
            if (i > 0) {
                rel_offset = offset - split_info->max_off[i - 1];
            }
            else {
                rel_offset = offset;
            }

            /* Get the length to read */
            if ((split_info->max_off[i] - offset) >= len)
                read_len = len;
            else
                read_len = (size_t) (split_info->max_off[i] - offset);


            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "split_read_rand: found in image %d relative: %"
                    PRIuOFF "  len: %" PRIuOFF "\n", i, rel_offset,
                    read_len);

            cnt =
                split_read_segment(split_info, i, buf, read_len,
                rel_offset);
            if (cnt < 0)
                return -1;

            if ((TSK_OFF_T) cnt != read_len)
                return cnt;

            /* Go to the next image(s) */
            if (((TSK_OFF_T) cnt == read_len) && (read_len != len)) {
                ssize_t cnt2;

                len -= read_len;

                while (len > 0) {
                    /* go to the next image */
                    i++;

                    if (split_info->max_off[i] -
                        split_info->max_off[i - 1] >= len)
                        read_len = len;
                    else
                        read_len = (size_t)
                            (split_info->max_off[i] -
                            split_info->max_off[i - 1]);

                    if (tsk_verbose)
                        tsk_fprintf(stderr,
                            "split_read_rand: Additional image reads: image %d  len: %"
                            PRIuOFF "\n", i, read_len);


                    cnt2 =
                        split_read_segment(split_info, i, &buf[cnt],
                        read_len, 0);
                    if (cnt2 < 0)
                        return -1;
                    cnt += cnt2;

                    if ((TSK_OFF_T) cnt2 != read_len)
                        return cnt;

                    len -= cnt2;
                }
            }

            return cnt;
        }
    }

    tsk_error_reset();
    tsk_errno = TSK_ERR_IMG_READ_OFF;
    snprintf(tsk_errstr, TSK_ERRSTR_L,
        "split_read - %" PRIuOFF " - %s", offset, strerror(errno));
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
split_imgstat(TSK_IMG_INFO * img_info, FILE * hFile)
{
    IMG_SPLIT_INFO *split_info = (IMG_SPLIT_INFO *) img_info;
    int i;

    tsk_fprintf(hFile, "IMAGE FILE INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "Image Type: split\n");
    tsk_fprintf(hFile, "\nSize in bytes: %" PRIuOFF "\n", img_info->size);

    tsk_fprintf(hFile, "\n--------------------------------------------\n");
    tsk_fprintf(hFile, "Split Information:\n");

    for (i = 0; i < split_info->num_img; i++) {
        tsk_fprintf(hFile, "%s  (%" PRIuOFF " to %" PRIuOFF ")\n",
            split_info->images[i],
            (TSK_OFF_T) (i == 0) ? 0 : split_info->max_off[i - 1],
            (TSK_OFF_T) (split_info->max_off[i] - 1));
    }
}



/** 
 * \internal
 * Free the memory and close the file  handles for the disk image
 *
 * @param img_info Disk image to close
 */
static void
split_close(TSK_IMG_INFO * img_info)
{
    int i;
    IMG_SPLIT_INFO *split_info = (IMG_SPLIT_INFO *) img_info;
    for (i = 0; i < SPLIT_CACHE; i++) {
        if (split_info->cache[i].fd != 0)
#ifdef TSK_WIN32
            CloseHandle(split_info->cache[i].fd);
#else
            close(split_info->cache[i].fd);
#endif
    }
    free(split_info->cptr);
    free(split_info);
}


/** 
 * \internal
 * Open the set of disk images as a set of split raw images
 *
 * @param num_img Number of images in set
 * @param images List of disk image paths (in sorted order)
 * @param a_ssize Size of device sector in bytes (or 0 for default)
 *
 * @return NULL on error
 */
TSK_IMG_INFO *
split_open(int num_img, const TSK_TCHAR * const images[],
    unsigned int a_ssize)
{
    IMG_SPLIT_INFO *split_info;
    TSK_IMG_INFO *img_info;
    int i;

    if ((split_info =
            (IMG_SPLIT_INFO *) tsk_malloc(sizeof(IMG_SPLIT_INFO))) == NULL)
        return NULL;

    img_info = (TSK_IMG_INFO *) split_info;

    img_info->itype = TSK_IMG_TYPE_RAW_SPLIT;
    img_info->read = split_read;
    img_info->close = split_close;
    img_info->imgstat = split_imgstat;

    img_info->sector_size = 512;
    if (a_ssize)
        img_info->sector_size = a_ssize;

    /* Open the files */
    if ((split_info->cptr =
            (int *) tsk_malloc(num_img * sizeof(int))) == NULL) {
        free(split_info);
        return NULL;
    }

    memset((void *) &split_info->cache, 0,
        SPLIT_CACHE * sizeof(IMG_SPLIT_CACHE));
    split_info->next_slot = 0;

    split_info->max_off =
        (TSK_OFF_T *) tsk_malloc(num_img * sizeof(TSK_OFF_T));
    if (split_info->max_off == NULL) {
        free(split_info->cptr);
        free(split_info);
        return NULL;
    }
    img_info->size = 0;

    split_info->num_img = num_img;
    split_info->images = images;

    /* Get size info for each file - we do not open each one because that
     * could cause us to run out of file decsriptors when we only need a few.
     * The descriptors are opened as needed
     */
    for (i = 0; i < num_img; i++) {
        struct STAT_STR sb;

        split_info->cptr[i] = -1;
        if (TSTAT(images[i], &sb) < 0) {
            tsk_error_reset();
            tsk_errno = TSK_ERR_IMG_STAT;
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "split_open - %" PRIttocTSK " - %s", images[i],
                strerror(errno));
            free(split_info->max_off);
            free(split_info->cptr);
            free(split_info);
            return NULL;
        }
        else if ((sb.st_mode & S_IFMT) == S_IFDIR) {
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "split_open: image %" PRIttocTSK " is a directory\n",
                    images[i]);

            tsk_error_reset();
            tsk_errno = TSK_ERR_IMG_MAGIC;
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "split_open: Image is a directory");
            return NULL;
        }

        /* Add the size of this image to the total and save the current max */
        img_info->size += sb.st_size;
        split_info->max_off[i] = img_info->size;

        if (tsk_verbose)
            tsk_fprintf(stderr,
                "split_open: %d  size: %" PRIuOFF "  max offset: %"
                PRIuOFF "  Name: %" PRIttocTSK "\n", i, sb.st_size,
                split_info->max_off[i], images[i]);
    }

    return img_info;
}
