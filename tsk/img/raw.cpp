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
#include "tsk/util/file_system_utils.h"

#include <memory>

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
    TSK_IMG_INFO* img_info = &raw_info->img_info.img_info;

    IMG_SPLIT_CACHE *cimg;
    ssize_t cnt;

    /* Is the image already open? */
    if (raw_info->cptr[idx] == -1) {
        if (tsk_verbose) {
            tsk_fprintf(stderr,
                "raw_read_segment: opening file into slot %d: %" PRIttocTSK
                "\n", raw_info->next_slot, img_info->images[idx]);
        }

        /* Grab the next cache slot */
        cimg = &raw_info->cache[raw_info->next_slot];

        /* Free it if being used */
        if (cimg->fd != 0) {
            if (tsk_verbose) {
                tsk_fprintf(stderr,
                    "raw_read_segment: closing file %" PRIttocTSK "\n",
                    img_info->images[cimg->image]);
            }
#ifdef TSK_WIN32
            CloseHandle(cimg->fd);
#else
            close(cimg->fd);
#endif
            raw_info->cptr[cimg->image] = -1;
        }

#ifdef TSK_WIN32
        cimg->fd = CreateFile(img_info->images[idx], FILE_READ_DATA,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0,
                              NULL);
        if ( cimg->fd == INVALID_HANDLE_VALUE ) {
            int lastError = (int)GetLastError();
            cimg->fd = 0; /* so we don't close it next time */
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_IMG_OPEN);
            tsk_error_set_errstr("raw_read: file \"%" PRIttocTSK
                                "\" - %d", img_info->images[idx], lastError);
            return -1;
        }

#else
        if ((cimg->fd =
                open(img_info->images[idx], O_RDONLY | O_BINARY)) < 0) {
            cimg->fd = 0; /* so we don't close it next time */
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_IMG_OPEN);
            tsk_error_set_errstr("raw_read: file \"%" PRIttocTSK
                "\" - %s", img_info->images[idx], strerror(errno));
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
        if ((offset_to_read % img_info->sector_size != 0)
                && is_windows_device_path(img_info->images[idx])) {
            offset_to_read = (offset_to_read / img_info->sector_size) * img_info->sector_size;
            len_to_read += img_info->sector_size; // this length will already be a multiple of sector size
            sector_aligned_buf = (char *)tsk_malloc(len_to_read);
            if (sector_aligned_buf == NULL) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_IMG_READ);
                tsk_error_set_errstr("raw_read: error allocating memory to read file \"%" PRIttocTSK
                    "\" offset: %" PRIdOFF " read len: %" PRIuSIZE,
                    img_info->images[idx], offset_to_read, len_to_read);
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
                    img_info->images[idx], offset_to_read,
                    lastError);
                return -1;
            }
            cimg->seek_pos = offset_to_read;
        }

        //For physical drive when the buffer is larger than remaining data,
        // WinAPI ReadFile call returns -1
        //in this case buffer of exact length must be passed to ReadFile
        if ((raw_info->is_winobj) && (offset_to_read + (TSK_OFF_T)len_to_read > img_info->size ))
            len_to_read = (size_t)(img_info->size - offset_to_read);

        if (FALSE == ReadFile(cimg->fd, *buf_pointer, (DWORD)len_to_read, &nread, NULL)) {
            if (sector_aligned_buf != NULL) {
                free(sector_aligned_buf);
            }
            int lastError = GetLastError();
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_IMG_READ);
            tsk_error_set_errstr("raw_read: file \"%" PRIttocTSK
                "\" offset: %" PRIdOFF " read len: %" PRIuSIZE " - %d",
                img_info->images[idx], offset_to_read, len_to_read,
                lastError);
            return -1;
        }
        // When the read operation reaches the end of a file,
        // ReadFile returns TRUE and sets nread to zero.
        // We need to check if we've reached the end of a file and set nread to
        // the number of bytes read.
        if (raw_info->is_winobj && nread == 0 && offset_to_read + len_to_read == (size_t) img_info->size) {
            nread = (DWORD)len_to_read;
        }
        cnt = (ssize_t) nread;

        if (raw_info->img_writer != NULL) {
            /* img_writer is not used with split images, so rel_offset is just the normal offset*/
            raw_info->img_writer->add(raw_info->img_writer, offset_to_read, *buf_pointer, cnt);
            // If WriteFile returns error in the addNewBlock, hadErrorExtending is 1
            if (raw_info->img_writer->inFinalizeImageWriter && raw_info->img_writer->hadErrorExtending) {
                if (sector_aligned_buf != NULL) {
                    free(sector_aligned_buf);
                }
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_IMG_WRITE);
                tsk_error_set_errstr("raw_read: file \"%" PRIttocTSK
                    "\" offset: %" PRIdOFF " tsk_img_writer_add cnt: %" PRIuSIZE,
                    img_info->images[idx], offset_to_read, cnt
                    );
                return -1;
            }
        }

        // Update this with the actual bytes read
        cimg->seek_pos += cnt;

        // If we had to do the sector alignment, copy the result into the original buffer and fix
        // the number of bytes read
        if (sector_aligned_buf != NULL) {
            memcpy(buf, sector_aligned_buf + rel_offset % img_info->sector_size, len);
            cnt = cnt - rel_offset % img_info->sector_size;
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
                "\" offset %" PRIdOFF " seek - %s", img_info->images[idx],
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
			PRIdOFF " read len: %" PRIuSIZE " - %s", img_info->images[idx],
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

    tsk_take_lock(&raw_info->read_lock);
    std::unique_ptr<tsk_lock_t, void(*)(tsk_lock_t*)> lock_guard(
      &raw_info->read_lock, tsk_release_lock
    );

    // Find the location of the offset
    for (i = 0; i < img_info->num_img; i++) {

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
                while ((len > 0) && (i+1 < img_info->num_img)) {
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

    if (img_info->num_img > 1) {
        int i;

        tsk_fprintf(hFile,
            "\n--------------------------------------------\n");
        tsk_fprintf(hFile, "Split Information:\n");

        for (i = 0; i < img_info->num_img; i++) {
            tsk_fprintf(hFile,
                "%" PRIttocTSK "  (%" PRIdOFF " to %" PRIdOFF ")\n",
                img_info->images[i],
                (TSK_OFF_T) (i == 0) ? 0 : raw_info->max_off[i - 1],
                (TSK_OFF_T) (raw_info->max_off[i] - 1));
        }
    }
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

    free(raw_info->max_off);
    free(raw_info->cptr);

    tsk_deinit_lock(&(raw_info->read_lock));
    tsk_img_free(raw_info);
}

#ifdef TSK_WIN32
/**
* \internal
* Test seeking to the given offset and then reading a sector.
* @param file_handle The open file handle to the image
* @param offset      The offset to seek to (in bytes)
* @param len         The length to read (in bytes). Should be a multiple of the sector size.
* @param buf         An allocated buffer large enough to hold len bytes
*
* @return 1 if the seek/read is successful, 0 if not
*/
static int
test_sector_read(HANDLE file_handle, TSK_OFF_T offset, DWORD len, char * buf) {
    LARGE_INTEGER li;
    li.QuadPart = offset;

    // Seek to the given offset
    li.LowPart = SetFilePointer(file_handle, li.LowPart,
        &li.HighPart, FILE_BEGIN);
    if ((li.LowPart == INVALID_SET_FILE_POINTER) &&
        (GetLastError() != NO_ERROR)) {
        return 0;
    }

    // Read a byte at the given offset
    DWORD nread;
    if (FALSE == ReadFile(file_handle, buf, len, &nread, NULL)) {
        return 0;
    }
    if (nread != len) {
        return 0;
    }

    // Success
    return 1;
}

/**
 * Attempts to calculate the actual sector size needed for reading the image.
 * If successful, the calculated sector size will be stored in raw_info. If it
 * fails the sector_size field will not be updated.
 * @param raw_info    The incomplete IMG_RAW_INFO object. The sector_size field may be updated by this method.
 * @param image_name  Image file name
 * @param image_size  Image size
*/
static void
set_device_sector_size(IMG_RAW_INFO * raw_info, const TSK_TCHAR * image_name, TSK_OFF_T image_size) {
    unsigned int min_sector_size = 512;
    unsigned int max_sector_size = 4096;

    HANDLE file_handle = CreateFile(image_name, FILE_READ_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0,
        NULL);
    if (file_handle == INVALID_HANDLE_VALUE) {
        if (tsk_verbose) {
            tsk_fprintf(stderr,
                "find_sector_size: failed to open image \"%" PRIttocTSK "\"\n", image_name);
        }
        return;
    }

    TSK_IMG_INFO* img_info = &raw_info->img_info.img_info;

    // First test whether we need to align on sector boundaries
    char* buf = (char*) malloc(max_sector_size);
    int needs_sector_alignment = 0;
    if (image_size > img_info->sector_size) {
        if (test_sector_read(file_handle, 1, img_info->sector_size, buf)) {
            needs_sector_alignment = 0;
        }
        else {
            needs_sector_alignment = 1;
        }
    }

    // If reading a sector starting at offset 1 failed, the assumption is that we have a device
    // that requires reads to be sector-aligned.
    if (needs_sector_alignment) {
        // Start at the minimum (512) and double up to max_sector_size (4096)
        unsigned int sector_size = min_sector_size;

        while (sector_size <= max_sector_size) {
            // If we don't have enough data to do the test just stop
            if (image_size < sector_size * 2) {
                break;
            }

            if (test_sector_read(file_handle, sector_size, sector_size, buf)) {
                // Found a valid sector size
                if (tsk_verbose) {
                    tsk_fprintf(stderr,
                        "find_sector_size: using sector size %d\n", sector_size);
                }
                img_info->sector_size = sector_size;

                if (file_handle != 0) {
                    CloseHandle(file_handle);
                }
                free(buf);
                return;
            }
            sector_size *= 2;
        }
        if (tsk_verbose) {
            tsk_fprintf(stderr,
                "find_sector_size: failed to determine correct sector size. Reverting to default %d\n", img_info->sector_size);
        }
        free(buf);
    }

    if (file_handle != 0) {
        CloseHandle(file_handle);
    }
}
#endif

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
    TSK_IMG_INFO *img_info;
    int i;
    TSK_OFF_T first_seg_size;

    const auto deleter = [](IMG_RAW_INFO* raw_info) {
        if (raw_info) {
            free(raw_info->cptr);
            free(raw_info->max_off);
        }
        tsk_img_free(raw_info);
    };

    std::unique_ptr<IMG_RAW_INFO, decltype(deleter)> raw_info{
        (IMG_RAW_INFO *) tsk_img_malloc(sizeof(IMG_RAW_INFO)),
        deleter
    };
    if (!raw_info) {
        return nullptr;
    }

    raw_info->cptr = nullptr;
    raw_info->max_off = nullptr;
    img_info = (TSK_IMG_INFO *) raw_info.get();

    img_info->itype = TSK_IMG_TYPE_RAW;

    raw_info->img_info.read = raw_read;
    raw_info->img_info.close = raw_close;
    raw_info->img_info.imgstat = raw_imgstat;

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
    first_seg_size = get_size_of_file_on_disk(a_images[0], raw_info->is_winobj);
    if (first_seg_size < -1) {
        return nullptr;
    }

    /* Set the sector size */
    img_info->sector_size = 512;
    if (a_ssize) {
        img_info->sector_size = a_ssize;
    }
#ifdef TSK_WIN32
    else if (is_windows_device_path(a_images[0])) {
        /* On Windows, figure out the actual sector size if one was not given and this is a device.
         * This is to prevent problems reading later. */
        set_device_sector_size(raw_info.get(), a_images[0], first_seg_size);
    }
#endif

    /* see if there are more of them... */
    if (a_num_img == 1 && raw_info->is_winobj == 0) {
        if ((img_info->images =
                tsk_img_findFiles(a_images[0],
                    &img_info->num_img)) == nullptr) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_IMG_STAT);
            tsk_error_set_errstr
                ("raw_open: could not find segment files starting at \"%"
                PRIttocTSK "\"", a_images[0]);
            return nullptr;
        }
    }
    else {
        if (!tsk_img_copy_image_names(img_info, a_images, a_num_img)) {
            return nullptr;
        }
    }

    /* sanity check: when we have multiple segments, the size of
     * each must be known */
    if (img_info->num_img > 1 && first_seg_size < 0) {
        if (tsk_verbose) {
            tsk_fprintf(stderr,
                "raw_open: file size is unknown in a segmented raw image\n");
        }
        return nullptr;
    }

    /* initialize the split cache */
    raw_info->cptr = (int *) tsk_malloc(img_info->num_img * sizeof(int));
    if (!raw_info->cptr) {
        return nullptr;
    }
    memset((void *) &raw_info->cache, 0,
        SPLIT_CACHE * sizeof(IMG_SPLIT_CACHE));
    raw_info->next_slot = 0;

    /* initialize the offset table and re-use the first segment
     * size gathered above */
    raw_info->max_off =
        (TSK_OFF_T *) tsk_malloc(img_info->num_img * sizeof(TSK_OFF_T));
    if (!raw_info->max_off) {
        return nullptr;
    }
    img_info->size = first_seg_size;
    raw_info->max_off[0] = img_info->size;
    raw_info->cptr[0] = -1;
    if (tsk_verbose) {
        tsk_fprintf(stderr,
            "raw_open: segment: 0  size: %" PRIdOFF "  max offset: %"
			PRIdOFF "  path: %" PRIttocTSK "\n", first_seg_size,
            raw_info->max_off[0], img_info->images[0]);
    }

    /* get size info for each file - we do not open each one because that
     * could cause us to run out of file descriptors when we only need a few.
     * The descriptors are opened as needed */
    for (i = 1; i < img_info->num_img; i++) {
        TSK_OFF_T size;
        raw_info->cptr[i] = -1;
        size = get_size_of_file_on_disk(img_info->images[i], raw_info->is_winobj);
        if (size < 0) {
            if (size == -1) {
                if (tsk_verbose) {
                    tsk_fprintf(stderr,
                        "raw_open: file size is unknown in a segmented raw image\n");
                }
            }
            return nullptr;
        }

        /* add the size of this image to the total and save the current max */
        img_info->size += size;
        raw_info->max_off[i] = img_info->size;

        if (tsk_verbose) {
            tsk_fprintf(stderr,
                "raw_open: segment: %d  size: %" PRIdOFF "  max offset: %"
				PRIdOFF "  path: %" PRIttocTSK "\n", i, size,
                raw_info->max_off[i], img_info->images[i]);
        }
    }

    // initialize the read lock
    tsk_init_lock(&raw_info->read_lock);

    return (TSK_IMG_INFO*) raw_info.release();
}
