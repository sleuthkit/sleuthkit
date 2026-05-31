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
#include "logical_img.h"
#include "tsk/util/file_system_utils.h"

#ifdef TSK_WIN32
// Extended-length path prefixes. "\\?\" enables long-path support for Win32 APIs;
// UNC paths use "\\?\UNC\" with the leading "\\" of the original path replaced.
static const TSK_TCHAR LOGICAL_LONG_PATH_PREFIX[]     = L"\\\\?\\";
static const TSK_TCHAR LOGICAL_UNC_LONG_PATH_PREFIX[] = L"\\\\?\\UNC\\";
// Wide-char lengths (excluding trailing NUL).
#define LOGICAL_LONG_PATH_PREFIX_LEN     ((sizeof(LOGICAL_LONG_PATH_PREFIX)     / sizeof(TSK_TCHAR)) - 1)
#define LOGICAL_UNC_LONG_PATH_PREFIX_LEN ((sizeof(LOGICAL_UNC_LONG_PATH_PREFIX) / sizeof(TSK_TCHAR)) - 1)
// Number of leading characters to skip from the source path when applying the
// corresponding prefix (UNC strips the leading "\\" so it isn't duplicated).
#define LOGICAL_LONG_PATH_SOURCE_SKIP     0
#define LOGICAL_UNC_LONG_PATH_SOURCE_SKIP 2
#endif

/**
 * \internal
 * Display information about the disk image set.
 *
 * @param img_info Disk image to analyze
 * @param hFile Handle to print information to
 */
static void
logical_imgstat(TSK_IMG_INFO * a_img_info, FILE * a_hFile)
{
	IMG_LOGICAL_INFO *dir_info = (IMG_LOGICAL_INFO *) a_img_info;

	tsk_fprintf(a_hFile, "IMAGE FILE INFORMATION\n");
	tsk_fprintf(a_hFile, "--------------------------------------------\n");
	tsk_fprintf(a_hFile, "Image Type: logical directory\n");
	tsk_fprintf(a_hFile,
		"Base Directory Path: %" PRIttocTSK "\n",
		dir_info->base_path);
}

/*
 * Clear a cache entry. Assumes we acquired the cache_lock already or are in the process
 * of closing the image and don't need it.
 */
void
clear_inum_cache_entry(IMG_LOGICAL_INFO *a_logical_img_info, int a_index) {
	a_logical_img_info->inum_cache[a_index].inum = LOGICAL_INVALID_INUM;
	if (a_logical_img_info->inum_cache[a_index].path != NULL) {
		free(a_logical_img_info->inum_cache[a_index].path);
		a_logical_img_info->inum_cache[a_index].path = NULL;
	}
	a_logical_img_info->inum_cache[a_index].path_len = 0;
	a_logical_img_info->inum_cache[a_index].last_used = 0;
}

/**
 * \internal
 *
 *
 * @param img_info logical directory to close
 */
static void
logical_close(TSK_IMG_INFO * a_img_info)
{
	IMG_LOGICAL_INFO *logical_img_info = (IMG_LOGICAL_INFO *)a_img_info;
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
	// Clean up the per-directory file-list cache entries
	for (int i = 0; i < DIR_FILE_LIST_CACHE_LEN; i++) {
		if (logical_img_info->dir_file_list_cache.entries[i].file_names != NULL) {
			for (size_t j = 0; j < logical_img_info->dir_file_list_cache.entries[i].file_count; j++) {
				free(logical_img_info->dir_file_list_cache.entries[i].file_names[j]);
			}
			free(logical_img_info->dir_file_list_cache.entries[i].file_names);
		}
	}
	tsk_img_free(a_img_info);
}

static ssize_t
logical_read(TSK_IMG_INFO * a_img_info, TSK_OFF_T a_offset, char *a_buf, size_t a_len)
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
logical_open(int a_num_img, const TSK_TCHAR * const a_images[],
	unsigned int a_ssize)
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
	logical_info->inum_cache_clock = 0;
	for (int i = 0; i < LOGICAL_INUM_CACHE_LEN; i++) {
		logical_info->inum_cache[i].inum = LOGICAL_INVALID_INUM;
		logical_info->inum_cache[i].path = NULL;
		logical_info->inum_cache[i].path_len = 0;
		logical_info->inum_cache[i].last_used = 0;
	}

	// Initialize the per-directory file-list cache
	logical_info->dir_file_list_cache.next_insert_index = 0;
	for (int i = 0; i < DIR_FILE_LIST_CACHE_LEN; i++) {
		logical_info->dir_file_list_cache.entries[i].dir_inum = LOGICAL_INVALID_INUM;
		logical_info->dir_file_list_cache.entries[i].file_names = NULL;
		logical_info->dir_file_list_cache.entries[i].file_count = 0;
	}

	img_info->read = logical_read;
	img_info->close = logical_close;
	img_info->imgstat = logical_imgstat;

	size_t len = TSTRLEN(a_images[0]);
	logical_info->base_path =
		(TSK_TCHAR *)tsk_malloc(sizeof(TSK_TCHAR) * (len + 1));
	if (logical_info->base_path == NULL) {
		tsk_img_free(img_info);
		return NULL;
	}
	TSTRNCPY(logical_info->base_path, a_images[0], len + 1);

#ifdef TSK_WIN32
	// Remove trailing slash
	size_t base_len = TSTRLEN(logical_info->base_path);
	if (base_len > 0 &&
		(logical_info->base_path[base_len - 1] == L'/' ||
		logical_info->base_path[base_len - 1] == L'\\')) {
		logical_info->base_path[base_len - 1] = L'\0';
	}

	// Fully resolve the path (handles relative paths, symlinks, . and ..) then
	// prepend the \\?\ extended-length prefix so that every path built from
	// base_path is long-path safe without any per-call conversion.
	// UNC paths (\\server\share) require \\?\UNC\ with the leading \\ replaced.
	DWORD required = GetFullPathNameW(logical_info->base_path, 0, NULL, NULL);
	if (required == 0) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_IMG_OPEN);
		tsk_error_set_errstr("logical_open: GetFullPathNameW failed for %" PRIttocTSK " (error %d)",
			logical_info->base_path, (int)GetLastError());
		free(logical_info->base_path);
		tsk_img_free(img_info);
		return NULL;
	}
	TSK_TCHAR *resolved = (TSK_TCHAR *)tsk_malloc(sizeof(TSK_TCHAR) * required);
	if (resolved == NULL) {
		free(logical_info->base_path);
		tsk_img_free(img_info);
		return NULL;
	}
	DWORD written = GetFullPathNameW(logical_info->base_path, required, resolved, NULL);
	if (written == 0 || written >= required) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_IMG_OPEN);
		tsk_error_set_errstr("logical_open: GetFullPathNameW failed for %" PRIttocTSK " (error %d)",
			logical_info->base_path, (int)GetLastError());
		free(resolved);
		free(logical_info->base_path);
		tsk_img_free(img_info);
		return NULL;
	}
	// Strip any trailing slash that GetFullPathNameW may have added (e.g. for "C:\")
	if (written > 1 && resolved[written - 1] == L'\\') {
		resolved[written - 1] = L'\0';
		written--;
	}

	// Choose prefix based on path type. UNC inputs (\\server\share\...) take the
	// \\?\UNC\ prefix with the leading "\\" of the source replaced; non-UNC inputs
	// take the plain \\?\ prefix.
	const int is_unc = (resolved[0] == L'\\' && resolved[1] == L'\\');
	const TSK_TCHAR *prefix = is_unc ? LOGICAL_UNC_LONG_PATH_PREFIX : LOGICAL_LONG_PATH_PREFIX;
	const size_t prefix_len = is_unc ? LOGICAL_UNC_LONG_PATH_PREFIX_LEN : LOGICAL_LONG_PATH_PREFIX_LEN;
	const size_t path_skip  = is_unc ? LOGICAL_UNC_LONG_PATH_SOURCE_SKIP : LOGICAL_LONG_PATH_SOURCE_SKIP;

	free(logical_info->base_path);
	logical_info->base_path = (TSK_TCHAR *)tsk_malloc(
		sizeof(TSK_TCHAR) * (prefix_len + written - path_skip + 1));
	if (logical_info->base_path == NULL) {
		free(resolved);
		tsk_img_free(img_info);
		return NULL;
	}
	memcpy(logical_info->base_path, prefix, prefix_len * sizeof(TSK_TCHAR));
	TSTRNCPY(logical_info->base_path + prefix_len, resolved + path_skip, written - path_skip + 1);
	free(resolved);

#else
	// Non-Windows: just strip trailing slash
	size_t base_len = TSTRLEN(logical_info->base_path);
	if (base_len > 0 && logical_info->base_path[base_len - 1] == '/') {
		logical_info->base_path[base_len - 1] = '\0';
	}
#endif

	if (LOGICAL_IMG_DEBUG_PRINT) fprintf(stderr, "logical_open - Image opened successfully\n");
	fflush(stderr);
    return img_info;
}
