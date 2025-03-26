/*
** The Sleuth Kit
**
** Copyright (c) 2022 Basis Technology Corp.  All rights reserved
** Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
**
** This software is distributed under the Common Public License 1.0
**
*/

/**
 * Internal code to open and read logical directories
 */

#include "tsk_img_i.h"
#include "legacy_cache.h"
#include "logical_img.h"
#include "tsk/util/file_system_utils.h"

/**
 * \internal
 * Display information about the disk image set.
 *
 * @param img_info Disk image to analyze
 * @param hFile Handle to print information to
 */
static void
logical_imgstat(TSK_IMG_INFO * img_info, FILE * hFile)
{
	IMG_LOGICAL_INFO *dir_info = (IMG_LOGICAL_INFO *) img_info;

    tsk_fprintf(hFile, "IMAGE FILE INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");
    tsk_fprintf(hFile, "Image Type: logical directory\n");
	tsk_fprintf(hFile,
		"Base Directory Path: %" PRIttocTSK "\n",
		dir_info->base_path);
}

/*
 * Clear a cache entry. Assumes we acquired the cache_lock already or are in the process
 * of closing the image and don't need it.
 */
void
clear_inum_cache_entry(IMG_LOGICAL_INFO *logical_img_info, int index) {
	logical_img_info->inum_cache[index].inum = LOGICAL_INVALID_INUM;
	if (logical_img_info->inum_cache[index].path != NULL) {
		free(logical_img_info->inum_cache[index].path);
		logical_img_info->inum_cache[index].path = NULL;
	}
	logical_img_info->inum_cache[index].cache_age = 0;
}

/**
 * \internal
 *
 *
 * @param img_info logical directory to close
 */
static void
logical_close(TSK_IMG_INFO * img_info)
{
	IMG_LOGICAL_INFO *logical_img_info = (IMG_LOGICAL_INFO *)img_info;
	free(logical_img_info->base_path);
	for (int i = 0; i < LOGICAL_FILE_HANDLE_CACHE_LEN; i++) {
#ifdef TSK_WIN32
		if (logical_img_info->file_handle_cache[i].fd != 0) {
			CloseHandle(logical_img_info->file_handle_cache[i].fd);
		}
#endif
	}
	for (int i = 0; i < LOGICAL_INUM_CACHE_LEN; i++) {
		clear_inum_cache_entry(logical_img_info, i);
	}

  delete logical_img_info->cache;

	tsk_img_free(img_info);
}

static ssize_t
logical_read(
  [[maybe_unused]] TSK_IMG_INFO * img_info,
  [[maybe_unused]] TSK_OFF_T offset,
  [[maybe_unused]] char *buf,
  [[maybe_unused]] size_t len)
{
	tsk_error_reset();
	tsk_error_set_errno(TSK_ERR_IMG_READ);
	tsk_error_set_errstr("logical_read: Logical image read is not supported");
	return 0;
}

/**
 * \internal
 *
 *
 * @param a_num_img Number of images in set
 * @param a_images List of disk image paths (in sorted order)
 * @param a_ssize Size of device sector in bytes (or 0 for default)
 *
 * @return NULL on error
 */
TSK_IMG_INFO *
logical_open(
  int a_num_img,
  const TSK_TCHAR * const a_images[],
  [[maybe_unused]] unsigned int a_ssize)
{
	IMG_LOGICAL_INFO *logical_info;
	TSK_IMG_INFO *img_info;

	if (LOGICAL_IMG_DEBUG_PRINT) fprintf(stderr, "logical_open - Opening image\n");
	fflush(stderr);

#ifndef TSK_WIN32
	tsk_error_reset();
	tsk_error_set_errno(TSK_ERR_IMG_ARG);
	tsk_error_set_errstr("logical_open: Logical directories not supported for non-Windows systems");
	return NULL;
#endif

	if (a_num_img != 1) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_IMG_ARG);
		tsk_error_set_errstr("logical_open: Only one directory (image name) is supported for logical directories");
		return NULL;
	}

	if ((logical_info =
		(IMG_LOGICAL_INFO *)tsk_img_malloc(sizeof(IMG_LOGICAL_INFO))) == NULL)
		return NULL;
	img_info = (TSK_IMG_INFO *)logical_info;

	logical_info->is_winobj = 0;
#ifdef TSK_WIN32
	logical_info->is_winobj = is_windows_device_path(a_images[0]);
#endif

	// Check that the given path exists and is a directory (return value = -3)
	TSK_OFF_T size_result = get_size_of_file_on_disk(a_images[0], logical_info->is_winobj);
	if (size_result != -3) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_IMG_ARG);
		tsk_error_set_errstr("logical_open: Image path is not a directory");
		tsk_img_free(img_info);
		return NULL;
	}

	img_info->size = INT64_MAX;
	img_info->itype = TSK_IMG_TYPE_LOGICAL;

	// Initialize file handle cache
	for (int i = 0; i < LOGICAL_FILE_HANDLE_CACHE_LEN; i++) {
		logical_info->file_handle_cache[i].fd = 0;
		logical_info->file_handle_cache[i].inum = LOGICAL_INVALID_INUM;
	}
	logical_info->next_file_handle_cache_slot = 0;

	// Initialize the inum cache
	for (int i = 0; i < LOGICAL_INUM_CACHE_LEN; i++) {
		logical_info->inum_cache[i].inum = LOGICAL_INVALID_INUM;
		logical_info->inum_cache[i].path = NULL;
		logical_info->inum_cache[i].cache_age = 0;
	}

	logical_info->img_info.read = logical_read;
	logical_info->img_info.close = logical_close;
	logical_info->img_info.imgstat = logical_imgstat;

	size_t len = TSTRLEN(a_images[0]);
	logical_info->base_path =
		(TSK_TCHAR *)tsk_malloc(sizeof(TSK_TCHAR) * (len + 1));
	if (logical_info->base_path == NULL) {
		tsk_img_free(img_info);
		return NULL;
	}
	TSTRNCPY(logical_info->base_path, a_images[0], len + 1);
	// Remove trailing slash
#ifdef TSK_WIN32
	if ((logical_info->base_path[TSTRLEN(logical_info->base_path) - 1] == L'/')
			|| (logical_info->base_path[TSTRLEN(logical_info->base_path) - 1] == L'\\')) {
		logical_info->base_path[TSTRLEN(logical_info->base_path) - 1] = '\0';
	}
#else
	if (logical_info->base_path[TSTRLEN(logical_info->base_path) - 1] == '/') {
		logical_info->base_path[TSTRLEN(logical_info->base_path) - 1] = '\0';
	}
#endif

  logical_info->cache = new LegacyCache();

	if (LOGICAL_IMG_DEBUG_PRINT) fprintf(stderr, "logical_open - Image opened successfully\n");
	fflush(stderr);
    return img_info;
}
