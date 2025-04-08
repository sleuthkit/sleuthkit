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
*\file logical_fs.cpp
* Contains the internal TSK logical file system functions.
*/

#include <algorithm>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <string.h>

#include "tsk_fs_i.h"
#include "tsk_fs.h"
#include "tsk_logical_fs.h"
#include "tsk/img/legacy_cache.h"
#include "tsk/img/logical_img.h"

#ifdef TSK_WIN32
#include <windows.h>
#endif

using std::vector;
using std::string;
using std::wstring;

static uint8_t
logicalfs_inode_walk(
  [[maybe_unused]] TSK_FS_INFO *fs,
  [[maybe_unused]] TSK_INUM_T start_inum,
  [[maybe_unused]] TSK_INUM_T end_inum,
  [[maybe_unused]] TSK_FS_META_FLAG_ENUM flags,
  [[maybe_unused]] TSK_FS_META_WALK_CB a_action,
  [[maybe_unused]] void *a_ptr)
{
	tsk_error_reset();
	tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
	tsk_error_set_errstr("block_walk for logical directory is not implemented");
	return 1;
}

static uint8_t
logicalfs_block_walk(
  [[maybe_unused]] TSK_FS_INFO *a_fs,
  [[maybe_unused]] TSK_DADDR_T a_start_blk,
  [[maybe_unused]] TSK_DADDR_T a_end_blk,
  [[maybe_unused]] TSK_FS_BLOCK_WALK_FLAG_ENUM a_flags,
  [[maybe_unused]] TSK_FS_BLOCK_WALK_CB a_action,
  [[maybe_unused]] void *a_ptr)
{
	tsk_error_reset();
	tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
	tsk_error_set_errstr("block_walk for logical directory is not implemented");
	return 1;
}

static TSK_FS_BLOCK_FLAG_ENUM
logicalfs_block_getflags(
  [[maybe_unused]] TSK_FS_INFO *fs,
  [[maybe_unused]] TSK_DADDR_T a_addr)
{
	return TSK_FS_BLOCK_FLAG_UNUSED;
}

static TSK_FS_ATTR_TYPE_ENUM
logicalfs_get_default_attr_type([[maybe_unused]] const TSK_FS_FILE * a_file)
{
	return TSK_FS_ATTR_TYPE_DEFAULT;
}

/*
 * Convert a FILETIME to a timet
 *
 * @param ft The FILETIME to convert
 *
 * @return The converted timet
 */
/*
#ifdef TSK_WIN32
static time_t
filetime_to_timet(FILETIME const& ft)
{
	ULARGE_INTEGER ull;
	ull.LowPart = ft.dwLowDateTime;
	ull.HighPart = ft.dwHighDateTime;
	return ull.QuadPart / 10000000ULL - 11644473600ULL;
}
#endif
*/

/*
 * Create a LOGICALFS_SEARCH_HELPER that will run a search for
 * the given inum.
 *
 * @param target_inum The inum to search for
 *
 * @return The search helper object (must be freed by caller)
 */
static LOGICALFS_SEARCH_HELPER*
create_inum_search_helper(TSK_INUM_T target_inum) {
	LOGICALFS_SEARCH_HELPER *helper = (LOGICALFS_SEARCH_HELPER *)tsk_malloc(sizeof(LOGICALFS_SEARCH_HELPER));
	if (helper == NULL)
		return NULL;

	helper->target_found = false;
	helper->search_type = LOGICALFS_SEARCH_BY_INUM;
	helper->target_path = NULL;
	helper->target_inum = target_inum;
	helper->found_path = NULL;
	return helper;
}

/*
* Create a LOGICALFS_SEARCH_HELPER that will run a search over
* the entire image. Used to find the max inum.
*
* @return The search helper object (must be freed by caller)
*/
static LOGICALFS_SEARCH_HELPER*
create_max_inum_search_helper() {
	LOGICALFS_SEARCH_HELPER *helper = (LOGICALFS_SEARCH_HELPER *)tsk_malloc(sizeof(LOGICALFS_SEARCH_HELPER));
	if (helper == NULL)
		return NULL;

	helper->target_found = false;
	helper->search_type = LOGICALFS_NO_SEARCH;
	helper->target_path = NULL;
	helper->found_path = NULL;
	return helper;
}

/*
* Create a LOGICALFS_SEARCH_HELPER that will run a search for
* the given path.
*
* @param target_path The path to search for
*
* @return The search helper object (must be freed by caller)
*/
static LOGICALFS_SEARCH_HELPER*
create_path_search_helper(const TSK_TCHAR *target_path) {
	LOGICALFS_SEARCH_HELPER *helper = (LOGICALFS_SEARCH_HELPER *)tsk_malloc(sizeof(LOGICALFS_SEARCH_HELPER));
	if (helper == NULL)
		return NULL;

	helper->target_found = false;
	helper->search_type = LOGICALFS_SEARCH_BY_PATH;
	helper->target_path = (TSK_TCHAR*)tsk_malloc(sizeof(TSK_TCHAR) * (TSTRLEN(target_path) + 1));
	TSTRNCPY(helper->target_path, target_path, TSTRLEN(target_path) + 1);
	helper->found_inum = LOGICAL_INVALID_INUM;
	helper->found_path = NULL;
	return helper;
}

/*
 * Free the search helper object
 *
 * @param helper The object to free
 */
static void
free_search_helper(LOGICALFS_SEARCH_HELPER* helper) {
	if (helper->target_path != NULL) {
		free(helper->target_path);
	}
	if (helper->found_path != NULL) {
		free(helper->found_path);
	}
	free(helper);
}

/*
 * Convert a wide string to UTF8.
 *
 * @param source The wide string to convert.
 *
 * @return The converted string (must be freed by caller) or "INVALID FILE NAME" if conversion fails. NULL if memory allocation fails.
 */
#ifdef TSK_WIN32
static char*
convert_wide_string_to_utf8(const wchar_t *source) {

	const char invalidName[] = "INVALID FILE NAME";
	UTF16 *utf16 = (UTF16 *)source;
	size_t ilen = wcslen(source);
	size_t maxUTF8len = ilen * 4;
	if (maxUTF8len < strlen(invalidName) + 1) {
		maxUTF8len = strlen(invalidName) + 1;
	}
	char *dest = (char*)tsk_malloc(maxUTF8len);
	if (dest == NULL) {
		return NULL;
	}
	UTF8 *utf8 = (UTF8*)dest;

	TSKConversionResult retVal =
		tsk_UTF16toUTF8_lclorder((const UTF16 **)&utf16,
			&utf16[ilen], &utf8,
			&utf8[maxUTF8len], TSKlenientConversion);

	if (retVal != TSKconversionOK) {
		// If the conversion failed, use a default name
		if (tsk_verbose)
			tsk_fprintf(stderr,
				"convert_wide_string_to_utf8: error converting logical file name to UTF-8\n");
		strcpy(dest, invalidName);
	}
	return dest;
}
#endif

/*
 * Check if we should set the type as directory.
 * We currently treat sym links as regular files to avoid
 * issues trying to read then as directories.
 */
 #ifdef TSK_WIN32
int
shouldTreatAsDirectory(DWORD dwFileAttributes) {
	return ((dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		&& (!(dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)));
}
#endif

/*
 * Use data in the WIN32_FIND_DATA to populate a TSK_FS_FILE object.
 * Expects a_fs_file and a_fs_file->meta to be allocated
 *
 * @param fd        The find data results
 * @param a_fs_file The file to populate
 *
 * @return TSK_OK if successful, TSK_ERR otherwise
 */
#ifdef TSK_WIN32
TSK_RETVAL_ENUM
populate_fs_file_from_win_find_data(const WIN32_FIND_DATA* fd, TSK_FS_FILE * a_fs_file) {

	if (a_fs_file == NULL || a_fs_file->meta == NULL) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_FS_ARG);
		tsk_error_set_errstr("populate_fs_file_from_win_find_data - a_fs_file argument not initialized");
		return TSK_ERR;
	}

	// For the current use case, we leave the timestamps set to zero.
	//a_fs_file->meta->crtime = filetime_to_timet(fd->ftCreationTime);
	//a_fs_file->meta->atime = filetime_to_timet(fd->ftLastAccessTime);
	//a_fs_file->meta->mtime = filetime_to_timet(fd->ftLastWriteTime);

	// Set the type
	if (shouldTreatAsDirectory(fd->dwFileAttributes)) {
		a_fs_file->meta->type = TSK_FS_META_TYPE_DIR;
	}
	else {
		a_fs_file->meta->type = TSK_FS_META_TYPE_REG;
	}

	// All files are allocated
	a_fs_file->meta->flags = TSK_FS_META_FLAG_ALLOC;

	// Set the file size
	LARGE_INTEGER ull;
	ull.LowPart = fd->nFileSizeLow;
	ull.HighPart = fd->nFileSizeHigh;
	a_fs_file->meta->size = ull.QuadPart;

	return TSK_OK;
}
#endif

/*
 * Create the wildcard search path used to find directory contents
 *
 * @param base_path The path to the directory to open
 *
 * @return The search path with wildcard appended (must be freed by caller)
 */
TSK_TCHAR * create_search_path(const TSK_TCHAR *base_path) {
	size_t len = TSTRLEN(base_path);
	TSK_TCHAR * searchPath;
	size_t searchPathLen = len + 4;
	searchPath = (TSK_TCHAR *)tsk_malloc(sizeof(TSK_TCHAR) * (searchPathLen));
	if (searchPath == NULL) {
		return NULL;
	}

#ifdef TSK_WIN32
	TSTRNCPY(searchPath, base_path, len + 1);
	TSTRNCAT(searchPath, L"\\*", 4);
#else
	TSTRNCPY(searchPath, base_path, len + 1);
	TSTRNCAT(searchPath, "/*", 3);
#endif
	return searchPath;
}

/*
* Create the wildcard search path used to find directory contents using
* the absolute directory and unicode prefix. We only call this method for
* long paths because it does not work in cygwin - prepending "\\?\" only
* works for absolute paths starting with a drive letter.
*
* @param base_path The path to the directory to open
*
* @return The search path with wildcard appended (must be freed by caller)
*/
#ifdef TSK_WIN32
TSK_TCHAR * create_search_path_long_path(const TSK_TCHAR *base_path) {

	// First convert the base path to an absolute path
	TCHAR absPath[LOGICAL_MAX_PATH_UNICODE];
	GetFullPathNameW(base_path, LOGICAL_MAX_PATH_UNICODE, absPath, NULL);

	size_t len = TSTRLEN(absPath);
	TSK_TCHAR * searchPath;
	size_t searchPathLen = len + 9;
	searchPath = (TSK_TCHAR *)tsk_malloc(sizeof(TSK_TCHAR) * (searchPathLen));
	if (searchPath == NULL) {
		return NULL;
	}

	TSTRNCPY(searchPath, L"\\\\?\\", 5);
	TSTRNCAT(searchPath, absPath, len + 1);
	TSTRNCAT(searchPath, L"\\*", 4);
	return searchPath;
}
#else
TSK_TCHAR * create_search_path_long_path(
  [[maybe_unused]] const TSK_TCHAR *base_path)
{
	// Nothing to do here if it's not Windows
	return NULL;
}
#endif

/*
 * Load the names of child files and/or directories into the given vectors.
 *
 * @param base_path  The parent path
 * @param file_names Will be populated with file names contained in the parent dir (if requested)
 * @param dir_names  Will be populated with dir names contained in the parent dir (if requested)
 * @param mode       Specifies whether files, directories, or both should be loaded
 *
 * @return TSK_OK if successful, TSK_ERR otherwise
 */
#ifdef TSK_WIN32
static TSK_RETVAL_ENUM
load_dir_and_file_lists_win(const TSK_TCHAR *base_path, vector<wstring>& file_names, vector<wstring>& dir_names, LOGICALFS_DIR_LOADING_MODE mode) {

	WIN32_FIND_DATAW fd;
	HANDLE hFind;

	// Create the search string (base path + "\*")
	TSK_TCHAR * search_path_wildcard = create_search_path(base_path);
	if (search_path_wildcard == NULL) {
		return TSK_ERR;
	}

	// If the paths is too long, attempt to make a different version that will work
	if (TSTRLEN(search_path_wildcard) >= MAX_PATH) {
		free(search_path_wildcard);
		search_path_wildcard = create_search_path_long_path(base_path);
		if (search_path_wildcard == NULL) {
			tsk_error_reset();
			tsk_error_set_errno(TSK_ERR_FS_GENFS);
			tsk_error_set_errstr("load_dir_and_file_lists: Error looking up contents of directory (path too long) %" PRIttocTSK, base_path);
			return TSK_ERR;
		}
	}

	// Look up all files and folders in the base directory
	hFind = ::FindFirstFileW(search_path_wildcard, &fd);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			if (shouldTreatAsDirectory(fd.dwFileAttributes)) {
				if (mode == LOGICALFS_LOAD_ALL || mode == LOGICALFS_LOAD_DIRS_ONLY) {
					// For the moment at least, skip . and ..
					if (0 != wcsncmp(fd.cFileName, L"..", 3) && 0 != wcsncmp(fd.cFileName, L".", 3)) {
						dir_names.push_back(fd.cFileName);
					}
				}
			}
			else {
				if (mode == LOGICALFS_LOAD_ALL || mode == LOGICALFS_LOAD_FILES_ONLY) {
					// For now, consider everything else to be a file
					file_names.push_back(fd.cFileName);
				}
			}
		} while (::FindNextFileW(hFind, &fd));
		::FindClose(hFind);
		free(search_path_wildcard);
		return TSK_OK;
	}
	else {
		free(search_path_wildcard);
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_FS_GENFS);
		tsk_error_set_errstr("load_dir_and_file_lists: Error looking up contents of directory %" PRIttocTSK, base_path);
		return TSK_ERR;
	}
}
#endif

void unlock(LegacyCache* cache) {
  cache->unlock();
};

/*
 * Finds closest cache match for the given path.
 * If best_path is not NULL, caller must free.
 *
 * @param logical_fs_info The logical file system
 * @param target_path     The full path being searched for
 * @param best_path       The best match found in the cache (NULL if none are found, must be freed by caller otherwise)
 * @param best_inum       The inum matching the best path found
 *
 * @return TSK_ERR if an error occurred, TSK_OK otherwise
 */
static TSK_RETVAL_ENUM
find_closest_path_match_in_cache(LOGICALFS_INFO *logical_fs_info, TSK_TCHAR *target_path, TSK_TCHAR **best_path, TSK_INUM_T *best_inum) {
	TSK_IMG_INFO* img_info = logical_fs_info->fs_info.img_info;
	IMG_LOGICAL_INFO* logical_img_info = (IMG_LOGICAL_INFO*)img_info;

  auto cache = logical_img_info->cache;
  cache->lock();
  std::unique_ptr<LegacyCache, decltype(&unlock)> lock_guard(cache, unlock);

	*best_inum = LOGICAL_INVALID_INUM;
	*best_path = NULL;
	int best_match_index = -1;
	size_t longest_match = 0;
	size_t target_len = TSTRLEN(target_path);

	for (int i = 0; i < LOGICAL_INUM_CACHE_LEN; i++) {
		if (logical_img_info->inum_cache[i].path != NULL) {

			// Check that:
			// - We haven't already found the exact match (longest_match = target_len)
			// - The cache entry could potentially be a longer match than what we have so far
			// - The cache entry isn't longer than what we're looking for
			size_t cache_path_len = TSTRLEN(logical_img_info->inum_cache[i].path);
			if ((longest_match != target_len) && (cache_path_len > longest_match) && (cache_path_len <= target_len)) {
				size_t matching_len = 0;
#ifdef TSK_WIN32
				if (0 == _wcsnicmp(target_path, logical_img_info->inum_cache[i].path, cache_path_len)) {
					matching_len = cache_path_len;
				}
#endif

				// Save this path if:
				// - It is longer than our previous best match
				// - It is either the full length of the path we're searching for or is a valid
				//      substring of our path
				if ((matching_len > longest_match) &&
					((matching_len == target_len) || ((matching_len < target_len) && 
						((target_path[matching_len] == L'/') || (target_path[matching_len] == L'\\'))))) {

					// We found the full path or a partial match
					longest_match = matching_len;
					best_match_index = i;

					// For the moment, consider any potential best match to have been useful. We could
					// change this to only reset the age of the actual best match.
					logical_img_info->inum_cache[i].cache_age = LOGICAL_INUM_CACHE_MAX_AGE;
				}
				else {
					// The cache entry was not useful so decrease the age
					if (logical_img_info->inum_cache[i].cache_age > 1) {
						logical_img_info->inum_cache[i].cache_age--;
					}
				}
			}
			else {
				// The cache entry was not useful so decrease the age
				if (logical_img_info->inum_cache[i].cache_age > 1) {
					logical_img_info->inum_cache[i].cache_age--;
				}
			}
		}
	}

	// If we found a full or partial match, store the values
	if (best_match_index >= 0) {
		*best_inum = logical_img_info->inum_cache[best_match_index].inum;
		*best_path = (TSK_TCHAR*)tsk_malloc(sizeof(TSK_TCHAR) * (TSTRLEN(logical_img_info->inum_cache[best_match_index].path) + 1));
		if (*best_path == NULL) {
			return TSK_ERR;
		}
		TSTRNCPY(*best_path, logical_img_info->inum_cache[best_match_index].path, TSTRLEN(logical_img_info->inum_cache[best_match_index].path) + 1);
	}

	return TSK_OK;
}

/*
 * Look up the path corresponding to the given inum in the cache.
 * Returned path must be freed by caller.
 *
 * @param logical_fs_info The logical file system
 * @param target_inum     The inum we're searching for
 *
 * @return The path corresponding to the given inum or NULL if not found or an error occurred. Must be freed by caller.
 */
static TSK_TCHAR*
find_path_for_inum_in_cache(LOGICALFS_INFO *logical_fs_info, TSK_INUM_T target_inum) {
	TSK_IMG_INFO* img_info = logical_fs_info->fs_info.img_info;
	IMG_LOGICAL_INFO* logical_img_info = (IMG_LOGICAL_INFO*)img_info;

  auto cache = logical_img_info->cache;
  cache->lock();
  std::unique_ptr<LegacyCache, decltype(&unlock)> lock_guard(cache, unlock);

	TSK_TCHAR *target_path = NULL;
	for (int i = 0; i < LOGICAL_INUM_CACHE_LEN; i++) {
		if (target_path == NULL && logical_img_info->inum_cache[i].inum == target_inum) {
			// The cache entry was useful so reset the age
			logical_img_info->inum_cache[i].cache_age = LOGICAL_INUM_CACHE_MAX_AGE;

			// Copy the path
      const size_t len = TSTRLEN(logical_img_info->inum_cache[i].path);
			target_path = (TSK_TCHAR*)tsk_malloc(sizeof(TSK_TCHAR) * (len + 1));
			if (target_path == NULL) {
				return NULL;
			}
			TSTRNCPY(target_path, logical_img_info->inum_cache[i].path, len + 1);
		}
		else {
			// The cache entry was not useful so decrease the age
			if (logical_img_info->inum_cache[i].cache_age > 1) {
				logical_img_info->inum_cache[i].cache_age--;
			}
		}
	}

	return target_path;
}

/*
 * Add a directory to the cache
 *
 * @param logical_fs_info The logical file system
 * @param path            The directory path
 * @param inum            The inum corresponding to the path
 * @param always_cache    If false, only cache the entry if we have empty space (and it will get a smaller age)
 *
 * @return TSK_OK if successful, TSK_ERR on error
 */
static TSK_RETVAL_ENUM
add_directory_to_cache(LOGICALFS_INFO *logical_fs_info, const TSK_TCHAR *path, TSK_INUM_T inum, bool always_cache) {

	// If the path is very long then don't cache it to make sure the cache stays reasonably small.
	if (TSTRLEN(path) > LOGICAL_INUM_CACHE_MAX_PATH_LEN) {
		return TSK_OK;
	}

	TSK_IMG_INFO* img_info = logical_fs_info->fs_info.img_info;
	IMG_LOGICAL_INFO* logical_img_info = (IMG_LOGICAL_INFO*)img_info;

  auto cache = logical_img_info->cache;
  cache->lock();
  std::unique_ptr<LegacyCache, decltype(&unlock)> lock_guard(cache, unlock);

	// Check if this entry is already in the cache. 
	for (int i = 0; i < LOGICAL_INUM_CACHE_LEN; i++) {
		if (logical_img_info->inum_cache[i].inum == inum) {
			// If we found it and we're always caching then reset the age
			if (always_cache && logical_img_info->inum_cache[i].cache_age < LOGICAL_INUM_CACHE_MAX_AGE) {
				logical_img_info->inum_cache[i].cache_age = LOGICAL_INUM_CACHE_MAX_AGE;
			}
			return TSK_OK;
		}
	}

	// Find the next cache slot. If we find an unused slot, use that. Otherwise find the entry
	// with the lowest age.
	int next_slot = 0;
	int lowest_age = LOGICAL_INUM_CACHE_MAX_AGE + 1;
	for (int i = 0; i < LOGICAL_INUM_CACHE_LEN; i++) {
		if (logical_img_info->inum_cache[i].inum == LOGICAL_INVALID_INUM) {
			next_slot = i;
			break;
		}

		if (logical_img_info->inum_cache[i].cache_age < lowest_age) {
			next_slot = i;
			lowest_age = logical_img_info->inum_cache[i].cache_age;
		}
	}

	// If the always_cache flag is not set, only continue if we've found an empty space
	if (!always_cache && logical_img_info->inum_cache[next_slot].inum != LOGICAL_INVALID_INUM) {
		return TSK_OK;
	}

	clear_inum_cache_entry(logical_img_info, next_slot);

	// Copy the data
	logical_img_info->inum_cache[next_slot].path = (TSK_TCHAR*)tsk_malloc(sizeof(TSK_TCHAR) * (TSTRLEN(path) + 1));
	if (logical_img_info->inum_cache[next_slot].path == NULL) {
		return TSK_ERR;
	}
	TSTRNCPY(logical_img_info->inum_cache[next_slot].path, path, TSTRLEN(path) + 1);
	logical_img_info->inum_cache[next_slot].inum = inum;
	if (always_cache) {
		logical_img_info->inum_cache[next_slot].cache_age = LOGICAL_INUM_CACHE_MAX_AGE;
	} else {
		// We want to remove the random folders first when we run out of space
		logical_img_info->inum_cache[next_slot].cache_age = LOGICAL_INUM_CACHE_MAX_AGE / 2;
	}

	return TSK_OK;
}

/*
 * Main recursive method for walking the directories. Will load and sort all directories found
 * in parent_path, assign an inum to each and check if this is what we're searching for, calling
 * this method recursively if not.
 *
 * @param parent_path The full path on disk to the directory to open
 * @last_inum_ptr     Pointer to the last assigned inum. Will be updated for every directory found
 * @search_helper     Contains information on what type of search is being performed and will store the results in most cases.
 *
 * @return TSK_OK if successfull, TSK_ERR otherwise
 */
static TSK_RETVAL_ENUM
search_directory_recursive(LOGICALFS_INFO *logical_fs_info, const TSK_TCHAR * parent_path, TSK_INUM_T *last_inum_ptr, LOGICALFS_SEARCH_HELPER* search_helper) {

#ifdef TSK_WIN32
	vector<wstring> file_names;
	vector<wstring> dir_names;
#else
	vector<string> file_names;
	vector<string> dir_names;
#endif

	// If we're searching for a file and this is the correct directory, load only the files in the folder and
	// return the correct one.
	if (search_helper->search_type == LOGICALFS_SEARCH_BY_INUM
		&& (*last_inum_ptr == (search_helper->target_inum & LOGICAL_INUM_DIR_MASK))
		&& ((search_helper->target_inum & LOGICAL_INUM_FILE_MASK) != 0)) {

#ifdef TSK_WIN32
		if (TSK_OK != load_dir_and_file_lists_win(parent_path, file_names, dir_names, LOGICALFS_LOAD_FILES_ONLY)) {
			// Error message already set
			return TSK_ERR;
		}
#endif
		sort(file_names.begin(), file_names.end());

		// Look for the file corresponding to the given inum
		size_t file_index = (search_helper->target_inum & LOGICAL_INUM_FILE_MASK) - 1;
		if (file_names.size() <= file_index) {
			tsk_error_reset();
			tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
			tsk_error_set_errstr("search_directory_recusive - inum %" PRIuINUM " not found", search_helper->target_inum);
			return TSK_ERR;
		}

		search_helper->target_found = true;
		size_t found_path_len = TSTRLEN(parent_path) + 1 + TSTRLEN(file_names[file_index].c_str());
		search_helper->found_path = (TSK_TCHAR*)tsk_malloc(sizeof(TSK_TCHAR) * (found_path_len + 1));
		TSTRNCPY(search_helper->found_path, parent_path, TSTRLEN(parent_path) + 1);
#ifdef TSK_WIN32
		TSTRNCAT(search_helper->found_path, L"\\", 2);
#else
		TSTRNCAT(search_helper->found_path, "/", 2);
#endif
		TSTRNCAT(search_helper->found_path, file_names[file_index].c_str(), TSTRLEN(file_names[file_index].c_str()) + 1);
		return TSK_OK;
	}

#ifdef TSK_WIN32
	if (TSK_OK != load_dir_and_file_lists_win(parent_path, file_names, dir_names, LOGICALFS_LOAD_DIRS_ONLY)) {
		// Error message already set
		return TSK_ERR;
	}
#endif

	// Sort the directory names
	sort(dir_names.begin(), dir_names.end());
		
	// Set up the beginning of full path to the file on disk
	// The directoy name being added should generally be less than 270 characters, but if necessary we will
	// make more space available.
	size_t allocated_dir_name_len = 270;
  const size_t current_path_len = TSTRLEN(parent_path) + 1 + allocated_dir_name_len;
	TSK_TCHAR* current_path = (TSK_TCHAR*)tsk_malloc(sizeof(TSK_TCHAR) * (current_path_len + 1));
	if (current_path == NULL)
		return TSK_ERR;
	TSTRNCPY(current_path, parent_path, current_path_len + 1);
#ifdef TSK_WIN32
	TSTRNCAT(current_path, L"\\", 2);
#else
	TSTRNCAT(current_path, "/", 2);
#endif
	size_t parent_path_len = TSTRLEN(current_path);

	for (size_t i = 0; i < dir_names.size(); i++) {

		// If we don't have space for this name, increase the size of the buffer
		if (TSTRLEN(dir_names[i].c_str()) > allocated_dir_name_len) {
			free(current_path);
			allocated_dir_name_len = TSTRLEN(dir_names[i].c_str()) + 20;
			current_path = (TSK_TCHAR*)tsk_malloc(sizeof(TSK_TCHAR) * (TSTRLEN(parent_path) + 2 + allocated_dir_name_len));
			if (current_path == NULL)
				return TSK_ERR;
			TSTRNCPY(current_path, parent_path, TSTRLEN(parent_path) + 1);
#ifdef TSK_WIN32
			TSTRNCAT(current_path, L"\\", 2);
#else
			TSTRNCAT(current_path, "/", 2);
#endif
		}

		// Append the current directory name to the parent path
		TSTRNCPY(current_path + parent_path_len, dir_names[i].c_str(), TSTRLEN(dir_names[i].c_str()) + 1);
		if (*last_inum_ptr == LOGICAL_INUM_DIR_MAX) {
			// We're run out of inums to assign. Return an error.
			tsk_error_reset();
			tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
			tsk_error_set_errstr("search_directory_recusive: Too many directories in logical file set");
			free(current_path);
			return TSK_ERR;
		}
		TSK_INUM_T current_inum = *last_inum_ptr + LOGICAL_INUM_DIR_INC;
		*last_inum_ptr = current_inum;

		// There's no perfect way to do the caching. Caching everything here had the problem that if we have a miss then the 
		// whole cache gets overwritten while we search. So we'll generally only cache directories that get us closer to 
		// our target (so if we search for something in the same or similar folders it'll be a fast search) and directories 
		// that are close to the root one (one or two folders deep).
		size_t current_path_len = TSTRLEN(current_path);
		size_t path_offset = TSTRLEN(logical_fs_info->base_path) + 1; // The +1 advances past the slash after the root dir
		bool is_near_root_folder = false;
		if (((search_helper->search_type == LOGICALFS_SEARCH_BY_PATH) || (search_helper->search_type == LOGICALFS_NO_SEARCH))
			&& path_offset < current_path_len) {
			int slash_count = 0;
			for (size_t i = path_offset; i < current_path_len; i++) {
				if (current_path[i] == '/' || current_path[i] == '\\') {
					slash_count++;
				}
			}
			is_near_root_folder = (slash_count < 2);
		}
		if (search_helper->search_type == LOGICALFS_SEARCH_BY_PATH) {
			if (is_near_root_folder || TSTRNCMP(current_path, search_helper->target_path, current_path_len) == 0) {
				add_directory_to_cache(logical_fs_info, current_path, current_inum, true);
			}
			else {
				// This will only add to the cache if we have empty space
				add_directory_to_cache(logical_fs_info, current_path, current_inum, false);
			}
		}
		else if (search_helper->search_type == LOGICALFS_NO_SEARCH && is_near_root_folder) {
			// Cache the base directories when opening the file system
			add_directory_to_cache(logical_fs_info, current_path, current_inum, true);
		}

		// Check if we've found it
		if ((search_helper->search_type == LOGICALFS_SEARCH_BY_PATH)
			&& (TSTRCMP(current_path, search_helper->target_path) == 0)) {
			search_helper->target_found = true;
			search_helper->found_inum = current_inum;
			free(current_path);
			return TSK_OK;
		}

		if ((search_helper->search_type == LOGICALFS_SEARCH_BY_INUM)
				&& (current_inum == search_helper->target_inum)) {

			search_helper->target_found = true;
			search_helper->found_path = (TSK_TCHAR*)tsk_malloc(sizeof(TSK_TCHAR) * (TSTRLEN(current_path) + 1));
			if (search_helper->found_path == NULL)
				return TSK_ERR;
			TSTRNCPY(search_helper->found_path, current_path, TSTRLEN(current_path) + 1);
			free(current_path);
			return TSK_OK;
		}

		TSK_RETVAL_ENUM result = search_directory_recursive(logical_fs_info, current_path, last_inum_ptr, search_helper);
		if (result != TSK_OK) {
			free(current_path);
			return result;
		}
		if (search_helper->target_found) {
			free(current_path);
			return TSK_OK;
		}
	}
	free(current_path);
	return TSK_OK;
}

/*
 * Find the path corresponding to the given inum
 *
 * @param logical_fs_info The logical file system
 * @param a_addr          The inum to search for
 *
 * @return The path corresponding to the inum. Null on error. Must be freed by caller.
 */
static TSK_TCHAR *
load_path_from_inum(LOGICALFS_INFO *logical_fs_info, TSK_INUM_T a_addr) {

	TSK_TCHAR *path = NULL;
	if (a_addr == logical_fs_info->fs_info.root_inum) {
		// No need to do a search - it's just the root folder
		const size_t len = TSTRLEN(logical_fs_info->base_path);
		path = (TSK_TCHAR*)tsk_malloc(sizeof(TSK_TCHAR) * (len + 1));
		if (path == NULL)
			return NULL;
		TSTRNCPY(path, logical_fs_info->base_path, len + 1);
		return path;
	}

	// Default starting position for the search is the base folder
	TSK_INUM_T starting_inum = logical_fs_info->fs_info.root_inum;
	const TSK_TCHAR *starting_path = logical_fs_info->base_path;

	// See if the directory is in the cache
	TSK_INUM_T dir_addr = a_addr & LOGICAL_INUM_DIR_MASK;
	TSK_TCHAR *cache_path = find_path_for_inum_in_cache(logical_fs_info, dir_addr);
	if (cache_path != NULL) {
		if (dir_addr == a_addr) {
			// If we were looking for a directory, we're done
			return cache_path;
		}

		// Otherwise, set up the search parameters to start with the folder found
		starting_inum = dir_addr;
		starting_path = cache_path;

	}

	// Create the struct that holds search params and results
	LOGICALFS_SEARCH_HELPER *search_helper = create_inum_search_helper(a_addr);
	if (search_helper == NULL) {
		return NULL;
	}

	// Run the search
	TSK_RETVAL_ENUM result = search_directory_recursive(logical_fs_info, starting_path, &starting_inum, search_helper);

	if (cache_path != NULL) {
		free(cache_path);
	}

	if ((result != TSK_OK) || (!search_helper->target_found)) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
		tsk_error_set_errstr("load_path_from_inum - failed to find path corresponding to inum %" PRIuINUM, search_helper->target_inum);
                // Free search_helper after using it to format the error string.
		free_search_helper(search_helper);
		return NULL;
	}

	// Copy the path
	const size_t len = TSTRLEN(search_helper->found_path);
	path = (TSK_TCHAR*)tsk_malloc(sizeof(TSK_TCHAR) * (len + 1));
	if (path == NULL) {
		free_search_helper(search_helper);
		return NULL;
	}
	TSTRNCPY(path, search_helper->found_path, len + 1);
	free_search_helper(search_helper);
	return path;
}

static uint8_t
logicalfs_file_add_meta(TSK_FS_INFO *a_fs, TSK_FS_FILE * a_fs_file,
	TSK_INUM_T inum)
{
	LOGICALFS_INFO *logical_fs_info = (LOGICALFS_INFO*)a_fs;
	if (a_fs_file == NULL) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_FS_ARG);
		tsk_error_set_errstr("logicalfs_file_add_meta - null TSK_FS_FILE given");
		return TSK_ERR;
	}
	if (a_fs_file->meta == NULL) {
		if ((a_fs_file->meta = tsk_fs_meta_alloc(0)) == NULL) {
			return TSK_ERR;
		}
	}
	else {
		tsk_fs_meta_reset(a_fs_file->meta);
	}

	a_fs_file->meta->addr = inum;
	
	// Get the full path to the given file
	TSK_TCHAR* path  = load_path_from_inum(logical_fs_info, inum);
	if (path == NULL) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
		tsk_error_set_errstr("logicalfs_file_add_meta - Error loading directory with inum %" PRIuINUM, inum);
		return TSK_ERR;
	}

#ifdef TSK_WIN32
	// Load the file
	WIN32_FIND_DATAW fd;
	HANDLE hFind;
	if (TSTRLEN(path) < MAX_PATH) {
		hFind = ::FindFirstFileW(path, &fd);
	}
	else {
		TCHAR absPath[LOGICAL_MAX_PATH_UNICODE + 4];
		TSTRNCPY(absPath, L"\\\\?\\", 4);
		int absPathLen = GetFullPathNameW(path, LOGICAL_MAX_PATH_UNICODE, &(absPath[4]), NULL);
		if (absPathLen <= 0) {
			tsk_error_reset();
			tsk_error_set_errno(TSK_ERR_FS_GENFS);
			tsk_error_set_errstr("logicalfs_file_add_meta: Error looking up contents of directory (path too long) %" PRIttocTSK, path);
			free(path);
			return TSK_ERR;
		}
		hFind = ::FindFirstFileW(absPath, &fd);
	}

	if (hFind != INVALID_HANDLE_VALUE) {

		TSK_RETVAL_ENUM result = populate_fs_file_from_win_find_data(&fd, a_fs_file);
		::FindClose(hFind);
		free(path);
		return result;
	}
	else {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_FS_GENFS);
		tsk_error_set_errstr("logicalfs_file_add_meta: Error loading directory %" PRIttocTSK, path);
		free(path);
		return TSK_ERR;
	}
#endif
	free(path);
	return TSK_OK;
}

/*
* Find the max inum in the logical image
*
* @param logical_fs_info The logical file system
*
* @return The max inum, or LOGICAL_INVALID_INUM if an error occurred
*/
static TSK_INUM_T
find_max_inum(LOGICALFS_INFO *logical_fs_info) {

	// Create the struct that holds search params and results
	LOGICALFS_SEARCH_HELPER *search_helper = create_max_inum_search_helper();
	if (search_helper == NULL) {
		return LOGICAL_INVALID_INUM;
	}

	// Run the search to get the maximum directory inum
	TSK_INUM_T last_assigned_inum = logical_fs_info->fs_info.root_inum;
	TSK_RETVAL_ENUM result = search_directory_recursive(logical_fs_info, logical_fs_info->base_path, &last_assigned_inum, search_helper);
	free_search_helper(search_helper);

	if (result != TSK_OK) {
		return LOGICAL_INVALID_INUM;
	}

	// The maximum inum will be the inum of the last file in that folder. We don't care which file it is,
	// so just getting a count is sufficient. First we need the path on disk corresponding to the last
	// directory inum.
	TSK_TCHAR* path = load_path_from_inum(logical_fs_info, last_assigned_inum);
	if (path == NULL) {
		return LOGICAL_INVALID_INUM;
	}

	// Finally we need to get a count of files in that last folder. The max inum is the
	// folder inum plus the number of files (if none, it'll just be the folder inum).
#ifdef TSK_WIN32
	vector<wstring> file_names;
	vector<wstring> dir_names;
	if (TSK_OK != load_dir_and_file_lists_win(path, file_names, dir_names, LOGICALFS_LOAD_FILES_ONLY)) {
		free(path);
		return LOGICAL_INVALID_INUM;
	}
#else
	vector<string> file_names;
	vector<string> dir_names;
#endif
	free(path);
	last_assigned_inum += file_names.size();
	return last_assigned_inum;
}

/*
* Find the inum corresponding to the given path
*
* @param logical_fs_info The logical file system
* @param a_addr          The inum to search for
* @param base_path       Will be loaded with path corresponding to the inum
* @param base_path_len   Size of base_path
*
* @return The corresponding inum, or LOGICAL_INVALID_INUM if an error occurs
*/
static TSK_INUM_T
#ifdef TSK_WIN32
get_inum_from_directory_path(LOGICALFS_INFO *logical_fs_info, TSK_TCHAR *base_path, wstring& dir_path) {
#else
get_inum_from_directory_path(LOGICALFS_INFO *logical_fs_info, TSK_TCHAR *base_path, string& dir_path) {
#endif

	// Get the full path on disk by combining the base path for the logical image with the relative path in dir_path
	size_t len = TSTRLEN(base_path) + dir_path.length() + 1;
	TSK_TCHAR *path_buf = (TSK_TCHAR*)tsk_malloc(sizeof(TSK_TCHAR) *(len + 2));
	TSTRNCPY(path_buf, base_path, TSTRLEN(base_path) + 1);
#ifdef TSK_WIN32
	TSTRNCAT(path_buf, L"\\", 2);
#else
	TSTRNCAT(path_buf, "/", 2);
#endif
	TSTRNCAT(path_buf, dir_path.c_str(), TSTRLEN(dir_path.c_str()) + 1);

	// Default starting position for search is the base folder
	TSK_INUM_T starting_inum = logical_fs_info->fs_info.root_inum;
	const TSK_TCHAR *starting_path = logical_fs_info->base_path;

	// See how close we can get using the cache
	TSK_TCHAR *cache_path = NULL;
	TSK_INUM_T cache_inum = LOGICAL_INVALID_INUM;
	TSK_RETVAL_ENUM result = find_closest_path_match_in_cache(logical_fs_info, path_buf, &cache_path, &cache_inum);
	if (result != TSK_OK) {
		return LOGICAL_INVALID_INUM;
	}
	if (cache_inum != LOGICAL_INVALID_INUM) {
		if (TSTRCMP(path_buf, cache_path) == 0) {
			// We found an exact match - no need to do a search
			free(cache_path);
			return cache_inum;
		}
		// Otherwise, we at least have a better place to start the search
		starting_inum = cache_inum;
		starting_path = cache_path;
	}

	// Create the struct that holds search params and results
	LOGICALFS_SEARCH_HELPER *search_helper = create_path_search_helper(path_buf);
	free(path_buf);
	if (search_helper == NULL) {
		if (cache_path != NULL) {
			free(cache_path);
		}
		return LOGICAL_INVALID_INUM;
	}

	// Run the search
	TSK_INUM_T last_assigned_inum = logical_fs_info->fs_info.root_inum;
	// use last_assigned_inum variable on non-win32 builds to prevent error
	(void)last_assigned_inum;
	result = search_directory_recursive(logical_fs_info, starting_path, &starting_inum, search_helper);

	if (cache_path != NULL) {
		free(cache_path);
	}

	// Return the target inum if found
	TSK_INUM_T target_inum;
	if ((result != TSK_OK) || (!search_helper->target_found)) {
		target_inum = LOGICAL_INVALID_INUM;
	}
	else {
		target_inum = search_helper->found_inum;
	}
	free_search_helper(search_helper);
	return target_inum;
}

static TSK_RETVAL_ENUM
logicalfs_dir_open_meta(
  TSK_FS_INFO *a_fs,
  TSK_FS_DIR ** a_fs_dir,
  TSK_INUM_T a_addr,
  [[maybe_unused]] int recursion_depth)
{
	TSK_FS_DIR *fs_dir;
	LOGICALFS_INFO *logical_fs_info = (LOGICALFS_INFO*)a_fs;

	if (a_fs_dir == NULL) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_FS_ARG);
		tsk_error_set_errstr("logicalfs_dir_open_meta: NULL fs_dir argument given");
		return TSK_ERR;
	}
	if ((a_addr & LOGICAL_INUM_FILE_MASK) != 0) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_FS_ARG);
		tsk_error_set_errstr("logicalfs_dir_open_meta: Inode %" PRIuINUM " is not a directory", a_addr);
		return TSK_ERR;
	}
	if (a_addr == LOGICAL_INVALID_INUM) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_FS_ARG);
		tsk_error_set_errstr("logicalfs_dir_open_meta: Inode %" PRIuINUM " is not valid", a_addr);
		return TSK_ERR;
	}

	fs_dir = *a_fs_dir;
	if (fs_dir) {
		tsk_fs_dir_reset(fs_dir);
		fs_dir->addr = a_addr;
	}
	else if ((*a_fs_dir = fs_dir = tsk_fs_dir_alloc(a_fs, a_addr, 128)) == NULL) {
		return TSK_ERR;
	}
	
	// Load the base path for the given meta address
	TSK_TCHAR* path = load_path_from_inum(logical_fs_info, a_addr);
	if (path == NULL) {
		return TSK_ERR;
	}

#ifdef TSK_WIN32
	// Populate the fs_file field
	WIN32_FIND_DATAW fd;
	HANDLE hFind;
	if (TSTRLEN(path) < MAX_PATH) {
		hFind = ::FindFirstFileW(path, &fd);
	}
	else {
		TCHAR absPath[LOGICAL_MAX_PATH_UNICODE + 4];
		TSTRNCPY(absPath, L"\\\\?\\", 4);
		int absPathLen = GetFullPathNameW(path, LOGICAL_MAX_PATH_UNICODE, &(absPath[4]), NULL);
		if (absPathLen <= 0) {
			tsk_error_reset();
			tsk_error_set_errno(TSK_ERR_FS_GENFS);
			tsk_error_set_errstr("logicalfs_dir_open_meta: Error looking up contents of directory (path too long) %" PRIttocTSK, path);
			free(path);
			return TSK_ERR;
		}
		hFind = ::FindFirstFileW(absPath, &fd);
	}
	if (hFind != INVALID_HANDLE_VALUE) {

		if ((fs_dir->fs_file = tsk_fs_file_alloc(a_fs)) == NULL) {
			free(path);
			return TSK_ERR;
		}

		if ((fs_dir->fs_file->meta = tsk_fs_meta_alloc(0)) == NULL) {
			free(path);
			return TSK_ERR;
		}

		TSK_RETVAL_ENUM result = populate_fs_file_from_win_find_data(&fd, fs_dir->fs_file);
		::FindClose(hFind);

		if (result != TSK_OK) {
			// Error message already set
			return TSK_ERR;
		}
		
	}
	else {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_FS_GENFS);
		tsk_error_set_errstr("logicalfs_dir_open_meta: Error loading directory %" PRIttocTSK, path);
		free(path);
		return TSK_ERR;
	}
#endif

#ifdef TSK_WIN32
	vector<wstring> file_names;
	vector<wstring> dir_names;
	if (TSK_OK != load_dir_and_file_lists_win(path, file_names, dir_names, LOGICALFS_LOAD_ALL)) {
		// Error message already set
		free(path);
		return TSK_ERR;
	}
#else
	vector<string> file_names;
	vector<string> dir_names;
#endif

	// Sort the files and directories
	sort(file_names.begin(), file_names.end());
	sort(dir_names.begin(), dir_names.end());

	// Add the folders
	for (auto it = begin(dir_names); it != end(dir_names); ++it) {
		TSK_INUM_T dir_inum = get_inum_from_directory_path(logical_fs_info, path, *it);
		if (dir_inum == LOGICAL_INVALID_INUM) {
			tsk_error_reset();
			tsk_error_set_errno(TSK_ERR_FS_GENFS);
			tsk_error_set_errstr("logicalfs_dir_open_meta: Error looking up inum from path");
			return TSK_ERR;
		}

		TSK_FS_NAME *fs_name;

#ifdef TSK_WIN32
		char *utf8Name = convert_wide_string_to_utf8(it->c_str());
		if (utf8Name == NULL) {
			tsk_error_reset();
			tsk_error_set_errno(TSK_ERR_FS_UNICODE);
			tsk_error_set_errstr("logicalfs_dir_open_meta: Error converting wide string");
			return TSK_ERR;
		}
		size_t name_len = strlen(utf8Name);
#else
		size_t name_len = strlen(it->c_str());
#endif
		if ((fs_name = tsk_fs_name_alloc(name_len, 0)) == NULL) {
#ifdef TSK_WIN32
			free(utf8Name);
#endif
			free(path);
			return TSK_ERR;
		}

		fs_name->type = TSK_FS_NAME_TYPE_DIR;
		fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
		fs_name->par_addr = a_addr;
		fs_name->meta_addr = dir_inum;
#ifdef TSK_WIN32
		strncpy(fs_name->name, utf8Name, name_len + 1);
		free(utf8Name);
#else
		strncpy(fs_name->name, it->c_str(), name_len + 1);
#endif
		if (tsk_fs_dir_add(fs_dir, fs_name)) {
			tsk_fs_name_free(fs_name);
			free(path);
			return TSK_ERR;
		}
		tsk_fs_name_free(fs_name);
	}
	free(path);

	// Add the files
	TSK_INUM_T file_inum = a_addr | 1; // First inum is directory inum in the high part, 1 in the low part
	for (auto it = begin(file_names); it != end(file_names); ++it) {
		TSK_FS_NAME *fs_name;
		size_t name_len;
#ifdef TSK_WIN32
		char *utf8Name = convert_wide_string_to_utf8(it->c_str());
		if (utf8Name == NULL) {
			tsk_error_reset();
			tsk_error_set_errno(TSK_ERR_FS_UNICODE);
			tsk_error_set_errstr("logicalfs_dir_open_meta: Error converting wide string");
			return TSK_ERR;
		}
		name_len = strlen(utf8Name);
#else
		name_len = it->length();
#endif
		if ((fs_name = tsk_fs_name_alloc(name_len, 0)) == NULL) {
#ifdef TSK_WIN32
			free(utf8Name);
#endif
			return TSK_ERR;
		}

		fs_name->type = TSK_FS_NAME_TYPE_REG;
		fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
		fs_name->par_addr = a_addr;
		fs_name->meta_addr = file_inum;
#ifdef TSK_WIN32
		strncpy(fs_name->name, utf8Name, name_len + 1);
		free(utf8Name);
#else
		strncpy(fs_name->name, it->c_str(), name_len + 1);
#endif
		if (tsk_fs_dir_add(fs_dir, fs_name)) {
			tsk_fs_name_free(fs_name);
			return TSK_ERR;
		}
		tsk_fs_name_free(fs_name);

		file_inum++;
	}

	return TSK_OK;
}

static uint8_t
logicalfs_load_attrs(TSK_FS_FILE *file)
{
	if (file == NULL || file->meta == NULL || file->fs_info == NULL)
	{
		tsk_error_set_errno(TSK_ERR_FS_ARG);
		tsk_error_set_errstr
		("logicalfs_load_attrs: called with NULL pointers");
		return 1;
	}

	TSK_FS_META* meta = file->meta;

	// See if we have already loaded the runs
	if ((meta->attr != NULL)
		&& (meta->attr_state == TSK_FS_META_ATTR_STUDIED)) {
		return 0;
	}
	else if (meta->attr_state == TSK_FS_META_ATTR_ERROR) {
		return 1;
	}
	else if (meta->attr != NULL) {
		tsk_fs_attrlist_markunused(meta->attr);
	}
	else if (meta->attr == NULL) {
		meta->attr = tsk_fs_attrlist_alloc();
	}

	TSK_FS_ATTR_RUN *data_run;
	TSK_FS_ATTR *attr = tsk_fs_attrlist_getnew(meta->attr, TSK_FS_ATTR_NONRES);
	if (attr == NULL) {
		meta->attr_state = TSK_FS_META_ATTR_ERROR;
		return 1;
	}

	if (meta->size == 0) {
		data_run = NULL;
	}
	else {
		data_run = tsk_fs_attr_run_alloc();
		if (data_run == NULL) {
			meta->attr_state = TSK_FS_META_ATTR_ERROR;
			return 1;
		}

		data_run->next = NULL;
		data_run->offset = 0;
		data_run->addr = 0;
		data_run->len = (meta->size + file->fs_info->block_size - 1) / file->fs_info->block_size;
		data_run->flags = TSK_FS_ATTR_RUN_FLAG_NONE;
	}

	if (tsk_fs_attr_set_run(file, attr, NULL, NULL,
		TSK_FS_ATTR_TYPE_DEFAULT, TSK_FS_ATTR_ID_DEFAULT,
		meta->size, meta->size,
		roundup(meta->size, file->fs_info->block_size),
		(TSK_FS_ATTR_FLAG_ENUM)0, 0)) {

		meta->attr_state = TSK_FS_META_ATTR_ERROR;
		return 1;
	}

	// If the file has size zero, return now
	if (meta->size == 0) {
		meta->attr_state = TSK_FS_META_ATTR_STUDIED;
		return 0;
	}

	// Otherwise add the data run
	if (0 != tsk_fs_attr_add_run(file->fs_info, attr, data_run)) {
		return 1;
	}
	meta->attr_state = TSK_FS_META_ATTR_STUDIED;

	return 0;
}

/*
 * Reads a block from a logical file. If the file is not long enough to complete the block,
 * null bytes are padded on to the end of the bytes read.
 *
 * @param a_fs         File system
 * @param a_fs_file    File being read
 * @param a_offset     Starting offset
 * @param buf          Holds bytes read from the file (should be the size of a block)
 *
 * @return Size of the block or -1 on error.
 */
ssize_t
logicalfs_read_block(TSK_FS_INFO *a_fs, TSK_FS_FILE *a_fs_file, TSK_DADDR_T a_block_num, char *buf) {

	if ((a_fs == NULL) || (a_fs_file == NULL) || (a_fs_file->meta == NULL)) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_FS_ARG);
		tsk_error_set_errstr("logical_fs_read_block: Called with null arguments");
		return -1;
	}

	if (a_fs->ftype != TSK_FS_TYPE_LOGICAL) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_FS_ARG);
		tsk_error_set_errstr("logical_fs_read_block: Called with files system that is not TSK_FS_TYPE_LOGICAL");
		return -1;
	}

	unsigned int block_size = a_fs->block_size;

	// The caching used for logical file blocks is simpler than
	// the version for images in img_io.c because we will always store complete
	// blocks - the block size for logical files is set to the same size as
	// the image cache. So each block in the cache will correspond to a
	// file inum and block number.

	// cache_lock is used for both the cache in IMG_INFO and
	// the shared variables in the img type specific INFO structs.
	// Grab it now so that it is held before any reads.
	IMG_LOGICAL_INFO* logical_img_info = (IMG_LOGICAL_INFO*)a_fs->img_info;
	LOGICALFS_INFO *logical_fs_info = (LOGICALFS_INFO*)a_fs;

	auto cache = logical_img_info->cache;
  cache->lock();
  std::unique_ptr<LegacyCache, decltype(&unlock)> lock_guard(cache, unlock);

	// Check if this block is in the cache
	int cache_next = 0;         // index to lowest age cache (to use next)
	bool match_found = 0;
	for (int cache_index = 0; cache_index < TSK_IMG_INFO_CACHE_NUM; cache_index++) {

		// Look into the in-use cache entries
		if (cache->cache_len[cache_index] > 0) {
			if ((logical_img_info->cache_inum[cache_index] == a_fs_file->meta->addr)
				// check if non-negative and cast to uint to avoid signed/unsigned comparison warning
				&& (cache->cache_off[cache_index] >= 0 && (TSK_DADDR_T)cache->cache_off[cache_index] == a_block_num)) {
				// We found it
				memcpy(buf, cache->cache[cache_index], block_size);
				match_found = true;

				// reset its "age" since it was useful
				cache->cache_age[cache_index] = LOGICAL_IMG_CACHE_AGE;

				// we don't break out of the loop so that we update all ages
			}
			else {
				// Decrease its "age" since it was not useful.
				// We don't let used ones go below 1 so that they are not
				// confused with entries that have never been used.
				if (cache->cache_age[cache_index] > 2) {
					cache->cache_age[cache_index]--;
				}

				// See if this is the most eligible replacement
				if ((cache->cache_len[cache_next] > 0)
					&& (cache->cache_age[cache_index] <
						cache->cache_age[cache_next])) {
					cache_next = cache_index;
				}
			}
		}
	}

	// If we found the block in the cache, we're done
	if (match_found) {
		return block_size;
	}

	// See if this file is already open
	LOGICAL_FILE_HANDLE_CACHE* file_handle_entry = NULL;
	for (int i = 0; i < LOGICAL_FILE_HANDLE_CACHE_LEN; i++) {
		if (logical_img_info->file_handle_cache[i].inum == a_fs_file->meta->addr) {
			// File is already open
			file_handle_entry = &(logical_img_info->file_handle_cache[i]);
		}
	}

	// If we didn't find it, open the file and save to the cache
	if (file_handle_entry == NULL) {
		// Load the path
		TSK_TCHAR* path = load_path_from_inum(logical_fs_info, a_fs_file->meta->addr);

#ifdef TSK_WIN32
		// Open the file
		HANDLE fd;
		if (TSTRLEN(path) < MAX_PATH) {
			fd = CreateFileW(path, FILE_READ_DATA,
				FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0,
				NULL);
		}
		else {
			TCHAR absPath[LOGICAL_MAX_PATH_UNICODE + 4];
			TSTRNCPY(absPath, L"\\\\?\\", 4);
			int absPathLen = GetFullPathNameW(path, LOGICAL_MAX_PATH_UNICODE, &(absPath[4]), NULL);
			if (absPathLen <= 0) {
				tsk_error_reset();
				tsk_error_set_errno(TSK_ERR_FS_GENFS);
				tsk_error_set_errstr("logicalfs_read_block: Error looking up contents of directory (path too long) %" PRIttocTSK, path);
				free(path);
				return TSK_ERR;
			}
			fd = CreateFileW(absPath, FILE_READ_DATA,
				FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0,
				NULL);
		}
		if (fd == INVALID_HANDLE_VALUE) {
			int lastError = (int)GetLastError();
			tsk_error_reset();
			tsk_error_set_errno(TSK_ERR_FS_READ);
			tsk_error_set_errstr("logical_fs_read_block: file \"%" PRIttocTSK
				"\" - %d", path, lastError);
			return -1;
		}
#else
		int fd = 0;
		// use path variable on non-win32 builds to prevent error
		(void)path;
#endif

		// Set up this cache entry
		file_handle_entry = &(logical_img_info->file_handle_cache[logical_img_info->next_file_handle_cache_slot]);
		if (file_handle_entry->fd != 0) {
			// Close the current file handle
#ifdef TSK_WIN32
			CloseHandle(file_handle_entry->fd);
#endif
		}
		file_handle_entry->fd = fd;
		file_handle_entry->inum = a_fs_file->meta->addr;
		file_handle_entry->seek_pos = 0;

		// Set up the next cache entry to use
		logical_img_info->next_file_handle_cache_slot++;
		if (logical_img_info->next_file_handle_cache_slot >= LOGICAL_FILE_HANDLE_CACHE_LEN) {
			logical_img_info->next_file_handle_cache_slot = 0;
		}
	}

	// Seek to the starting offset (if necessary)
	TSK_OFF_T offset_to_read = a_block_num * block_size;
	if (offset_to_read != file_handle_entry->seek_pos) {
#ifdef TSK_WIN32
		LARGE_INTEGER li;
		li.QuadPart = a_block_num * block_size;

		li.LowPart = SetFilePointer(file_handle_entry->fd, li.LowPart,
			&li.HighPart, FILE_BEGIN);

		if ((li.LowPart == INVALID_SET_FILE_POINTER) &&
			(GetLastError() != NO_ERROR)) {

			int lastError = (int)GetLastError();
			tsk_error_reset();
			tsk_error_set_errno(TSK_ERR_IMG_SEEK);
			tsk_error_set_errstr("logical_fs_read_block: file addr %" PRIuINUM
				" offset %" PRIdOFF " seek - %d",
				a_fs_file->meta->addr, a_block_num, lastError);
			return -1;
		}
#endif
		file_handle_entry->seek_pos = offset_to_read;
	}

	// Read the data
	unsigned int len_to_read;
	if (((a_block_num + 1) * block_size) <= (unsigned long long)a_fs_file->meta->size) {
		// If the file is large enough to read the entire block, then try to do so
		len_to_read = block_size;
	}
	else {
		// Otherwise, we expect to only be able to read a smaller number of bytes
		len_to_read = a_fs_file->meta->size % block_size;
		memset(buf, 0, block_size);
	}

#ifdef TSK_WIN32
	DWORD nread;
	if (FALSE == ReadFile(file_handle_entry->fd, buf, (DWORD)len_to_read, &nread, NULL)) {
		int lastError = GetLastError();
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_IMG_READ);
		tsk_error_set_errstr("logicalfs_read_block: file addr %" PRIuINUM
			" offset: %" PRIu64 " read len: %u - %d",
			a_fs_file->meta->addr, a_block_num, block_size,
			lastError);
		return -1;
	}
	file_handle_entry->seek_pos += nread;
#else
	// otherwise, not used; ensure used to prevent warning
	(void)len_to_read;
#endif

	// Copy the block into the cache
	memcpy(cache->cache[cache_next], buf, block_size);
	cache->cache_len[cache_next] = block_size;
	cache->cache_age[cache_next] = LOGICAL_IMG_CACHE_AGE;
	cache->cache_off[cache_next] = a_block_num;
	logical_img_info->cache_inum[cache_next] = a_fs_file->meta->addr;

	// If we didn't read the expected number of bytes, return an error
#ifdef TSK_WIN32
	if (nread != len_to_read) {
		int lastError = GetLastError();
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_IMG_READ);
		tsk_error_set_errstr("logicalfs_read_block: file addr %" PRIuINUM
			" offset: %" PRIdOFF " read len: %u - %d",
			a_fs_file->meta->addr, a_block_num, block_size,
			lastError);
		return -1;
	}
#endif

	return block_size;
}

/*
* Reads data from a logical file.
*
* @param a_fs         File system
* @param a_fs_file    File being read
* @param a_offset     Starting offset
* @param a_len        Length to read
* @param a_buf        Holds bytes read from the file (should have length at least a_len)
*
* @return Number of bytes read or -1 on error.
*/
ssize_t
logicalfs_read(TSK_FS_INFO *a_fs, TSK_FS_FILE *a_fs_file, TSK_DADDR_T a_offset, size_t a_len, char *a_buf) {

	TSK_DADDR_T current_block_num = a_offset / a_fs->block_size;
	char block_buffer[LOGICAL_BLOCK_SIZE];
	size_t cnt;
	char *dest = a_buf;
	size_t bytes_left = a_len;
	size_t bytes_read = 0;
	size_t filler_len = 0;

	if ((a_fs == NULL) || (a_fs_file == NULL) || (a_fs_file->meta == NULL)) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_FS_ARG);
		tsk_error_set_errstr("logicalfs_read: Called with null arguments");
		return -1;
	}

	if (a_offset >= (TSK_DADDR_T)a_fs_file->meta->size) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_FS_ARG);
		tsk_error_set_errstr("logicalfs_read: Attempted to read offset beyond end of file (file addr: %"
			PRIuINUM ", file size: %" PRIdOFF ", offset: %" PRIuDADDR ")", a_fs_file->meta->addr, a_fs_file->meta->size, a_offset);
		return -1;
	}

	// Only attempt to read to the end of the file at most
	if (a_offset + a_len > (TSK_DADDR_T)a_fs_file->meta->size) {
		bytes_left = a_fs_file->meta->size - a_offset;
		filler_len = a_offset + a_len - a_fs_file->meta->size;

		// Fill in the end of the buffer
		if (filler_len > 0) {
			memset(dest + bytes_left, 0, filler_len);
		}
	}

	// Read bytes prior to the first block boundary
	if (a_offset % a_fs->block_size != 0) {
		// Read in the smaller of the requested length and the bytes at the end of the block
		size_t len_to_read = a_fs->block_size - (a_offset % a_fs->block_size);
		if (len_to_read > bytes_left) {
			len_to_read = bytes_left;
		}
		cnt = logicalfs_read_block(a_fs, a_fs_file, current_block_num, block_buffer);
		if (cnt != a_fs->block_size) {
			// Error already set
			return cnt;
		}
		memcpy(dest, block_buffer + (a_offset % a_fs->block_size), len_to_read);
		dest += len_to_read;
		bytes_read += len_to_read;
		bytes_left -= len_to_read;
		current_block_num++;
	}
	// Check if we're done
	if (bytes_left == 0) {
		return bytes_read;
	}

	// Read complete blocks
	while (bytes_left >= a_fs->block_size) {
		cnt = logicalfs_read_block(a_fs, a_fs_file, current_block_num, dest);
		if (cnt != a_fs->block_size) {
			// Error already set
			return cnt;
		}
		dest += a_fs->block_size;
		bytes_read += a_fs->block_size;
		bytes_left -= a_fs->block_size;
		current_block_num++;
	}

	// Check if we're done
	if (bytes_left == 0) {
		return bytes_read;
	}

	// Read the final, incomplete block
	cnt = logicalfs_read_block(a_fs, a_fs_file, current_block_num, block_buffer);
	if (cnt != a_fs->block_size) {
		// Error already set
		return cnt;
	}
	memcpy(dest, block_buffer, bytes_left);
	dest += bytes_left;
	bytes_read += bytes_left;

	return bytes_read;
}

/**
* Print details about the file system to a file handle.
*
* @param fs File system to print details on
* @param hFile File handle to print text to
*
* @returns 1 on error and 0 on success
*/
static uint8_t
logicalfs_fsstat(TSK_FS_INFO * fs, FILE * hFile)
{
	LOGICALFS_INFO * dirfs = (LOGICALFS_INFO*)fs;
	tsk_fprintf(hFile, "FILE SYSTEM INFORMATION\n");
	tsk_fprintf(hFile, "--------------------------------------------\n");

	tsk_fprintf(hFile, "File System Type: Logical Directory\n");
	tsk_fprintf(hFile,
		"Base Directory Path: %" PRIttocTSK "\n",
		dirfs->base_path);
	return 0;
}

static uint8_t
logicalfs_fscheck(TSK_FS_INFO * /*fs*/, FILE * /*hFile*/)
{
	tsk_error_reset();
	tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
	tsk_error_set_errstr("fscheck not supported for logical file systems");
	return 1;
}

/**
* Print details on a specific file to a file handle.
*
* @param fs File system file is located in
* @param hFile File handle to print text to
* @param inum Address of file in file system
* @param numblock The number of blocks in file to force print (can go beyond file size)
* @param sec_skew Clock skew in seconds to also print times in
*
* @returns 1 on error and 0 on success
*/
static uint8_t
logicalfs_istat(
  [[maybe_unused]] TSK_FS_INFO *fs,
  [[maybe_unused]] TSK_FS_ISTAT_FLAG_ENUM flags,
  [[maybe_unused]] FILE * hFile,
  [[maybe_unused]] TSK_INUM_T inum,
  [[maybe_unused]] TSK_DADDR_T numblock,
  [[maybe_unused]] int32_t sec_skew)
{
	tsk_error_reset();
	tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
	tsk_error_set_errstr("istat not supported for logical file systems");
	return 1;
}

/* logicalfs_close - close a logical file system */
static void
logicalfs_close(TSK_FS_INFO *fs)
{
	if (fs != NULL) {
		fs->tag = 0;
		tsk_fs_free(fs);
	}
}

static uint8_t
logicalfs_jentry_walk(TSK_FS_INFO * /*info*/, int /*entry*/,
	TSK_FS_JENTRY_WALK_CB /*cb*/, void * /*fn*/)
{
	tsk_error_reset();
	tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
	tsk_error_set_errstr("Journal support for logical directory is not implemented");
	return 1;
}

static uint8_t
logicalfs_jblk_walk(TSK_FS_INFO * /*info*/, TSK_DADDR_T /*daddr*/,
	TSK_DADDR_T /*daddrt*/, int /*entry*/, TSK_FS_JBLK_WALK_CB /*cb*/,
	void * /*fn*/)
{
	tsk_error_reset();
	tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
	tsk_error_set_errstr("Journal support for logical directory is not implemented");
	return 1;
}

static uint8_t
logicalfs_jopen(TSK_FS_INFO * /*info*/, TSK_INUM_T /*inum*/)
{
	tsk_error_reset();
	tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
	tsk_error_set_errstr("Journal support for logical directory is not implemented");
	return 1;
}

int
logicalfs_name_cmp(TSK_FS_INFO * a_fs_info, const char *s1, const char *s2)
{
#ifdef TSK_WIN32
	return strcasecmp(s1, s2);
#else
	return tsk_fs_unix_name_cmp(a_fs_info, s1, s2);
#endif
}

TSK_FS_INFO *
logical_fs_open(TSK_IMG_INFO * img_info) {

	LOGICALFS_INFO *logical_fs_info = NULL;
	TSK_FS_INFO *fs = NULL;
	IMG_LOGICAL_INFO *logical_img_info = NULL;

#ifndef TSK_WIN32
	tsk_error_reset();
	tsk_error_set_errno(TSK_ERR_FS_ARG);
	tsk_error_set_errstr("logical_fs_open: logical file systems currently only enabled on Windows");
	return NULL;
#endif

	if (img_info->itype != TSK_IMG_TYPE_LOGICAL) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_FS_ARG);
		tsk_error_set_errstr("logical_fs_open: image must be of type TSK_IMG_TYPE_DIR");
		return NULL;
	}
	logical_img_info = (IMG_LOGICAL_INFO *)img_info;

	if ((logical_fs_info = (LOGICALFS_INFO *)tsk_fs_malloc(sizeof(LOGICALFS_INFO))) == NULL)
		return NULL;

	fs = &(logical_fs_info->fs_info);
	logical_fs_info->base_path = logical_img_info->base_path; // To avoid having to always go through TSK_IMG_INFO

	fs->tag = TSK_FS_INFO_TAG;
	fs->ftype = TSK_FS_TYPE_LOGICAL;
	fs->flags = (TSK_FS_INFO_FLAG_ENUM)0;
	fs->img_info = img_info;
	fs->offset = 0;
	fs->endian = TSK_LIT_ENDIAN;
	fs->duname = "None";

	// Metadata info
	fs->last_inum = 0; // Will set at the end
	fs->root_inum = LOGICAL_ROOT_INUM;
	fs->first_inum = LOGICAL_ROOT_INUM;
	fs->inum_count = 0;

	// Block info
	fs->dev_bsize = 0;
	fs->block_size = LOGICAL_BLOCK_SIZE;
	fs->block_pre_size = 0;
	fs->block_post_size = 0;
	fs->block_count = 0;
	fs->first_block = 0;
	fs->last_block = INT64_MAX;
	fs->last_block_act = INT64_MAX;

	// Set the generic function pointers. Most will be no-ops for now.
	fs->inode_walk = logicalfs_inode_walk;
	fs->block_walk = logicalfs_block_walk;
	fs->block_getflags = logicalfs_block_getflags;

	fs->get_default_attr_type = logicalfs_get_default_attr_type;
	fs->load_attrs = logicalfs_load_attrs;

	fs->file_add_meta = logicalfs_file_add_meta;
	fs->dir_open_meta = logicalfs_dir_open_meta;
	fs->fsstat = logicalfs_fsstat;
	fs->fscheck = logicalfs_fscheck;
	fs->istat = logicalfs_istat;
	fs->name_cmp = logicalfs_name_cmp;

	fs->close = logicalfs_close;

	// Journal functions - also no-ops.
	fs->jblk_walk = logicalfs_jblk_walk;
	fs->jentry_walk = logicalfs_jentry_walk;
	fs->jopen = logicalfs_jopen;

	// Calculate the last inum
	fs->last_inum = find_max_inum(logical_fs_info);

	// We don't really care about the last inum, but if traversing the
	// folders to calculate it fails then we're going to encounter
	// the same error when using the logical file system.
	if (fs->last_inum == LOGICAL_INVALID_INUM) {
		logicalfs_close(fs);
		return NULL;
	}

	return fs;
}
