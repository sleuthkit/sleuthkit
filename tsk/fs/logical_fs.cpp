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

#include <vector>
#include <map>
#include <algorithm>
#include <string>
#include <set>
#include <string.h>
#include <cwctype>
#include <assert.h>
#include <chrono>   // TEMP: for sort-timing instrumentation; remove when done

#include "tsk_fs_i.h"
#include "tsk_fs.h"
#include "tsk_logical_fs.h"
#include "tsk/img/logical_img.h"

#ifdef TSK_WIN32
#include <windows.h>
#endif

using std::vector;
using std::string;
using std::wstring;

// Forward declaration: load_dir_and_file_lists_win uses this comparator when sorting
// before caching, but the function bodies live further down. Keep these signatures in
// sync with the definitions below.
#ifdef TSK_WIN32
bool case_insensitive_compare(const std::wstring& a, const std::wstring& b);
#else
bool case_insensitive_compare(const std::string& a, const std::string& b);
#endif

static uint8_t
logicalfs_inode_walk(TSK_FS_INFO *fs, TSK_INUM_T start_inum,
	TSK_INUM_T end_inum, TSK_FS_META_FLAG_ENUM flags,
	TSK_FS_META_WALK_CB a_action, void *a_ptr)
{
	tsk_error_reset();
	tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
	tsk_error_set_errstr("block_walk for logical directory is not implemented");
	return 1;
}

static uint8_t
logicalfs_block_walk(TSK_FS_INFO *a_fs, TSK_DADDR_T a_start_blk,
	TSK_DADDR_T a_end_blk, TSK_FS_BLOCK_WALK_FLAG_ENUM a_flags,
	TSK_FS_BLOCK_WALK_CB a_action, void *a_ptr)
{
	tsk_error_reset();
	tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
	tsk_error_set_errstr("block_walk for logical directory is not implemented");
	return 1;
}

static TSK_FS_BLOCK_FLAG_ENUM
logicalfs_block_getflags(TSK_FS_INFO *fs, TSK_DADDR_T a_addr)
{
	return TSK_FS_BLOCK_FLAG_UNUSED;
}

static TSK_FS_ATTR_TYPE_ENUM
logicalfs_get_default_attr_type(const TSK_FS_FILE * /*a_file*/)
{
	return TSK_FS_ATTR_TYPE_DEFAULT;
}

/**
* Check if the given path contains the folder separator
*
* @param path  The path to test
*
* @return true if path contains folder separator, false otherwise
*/
static bool
contains_folder_separator(const TSK_TCHAR* path) {
	if (path == NULL) {
		return false;
	}

#ifdef TSK_WIN32
	TSK_TCHAR slash = '\\';
#else
	TSK_TCHAR slash = '/';
#endif
	return TSTRCHR(path, slash) != NULL;
}

/**
* Test whether child_path is a subfolder under parent_path.
*
* @param parent_path  Parent path
* @param child_path   Child path
*
* @return true if child_path is a subfolder of parent_path
*/
static bool
path_is_subfolder(const TSK_TCHAR* parent_path, const TSK_TCHAR* child_path) {

	if (parent_path == NULL || child_path == NULL) {
		return false;
	}

	size_t parent_path_len = TSTRLEN(parent_path);
	if (parent_path_len + 1 >= TSTRLEN(child_path)) {
		return false;
	}

#ifdef TSK_WIN32
	if (0 != _wcsnicmp(parent_path, child_path, parent_path_len)) {
		return false;
	}
#endif

	// Make sure child_path is (parent_path)/(rest)
#ifdef TSK_WIN32
	TSK_TCHAR slash = '\\';
#else
	TSK_TCHAR slash = '/';
#endif
	return child_path[parent_path_len] == slash;
}

/**
* Return a pointer to full_path starting after the path_start string.
* Assumes full_path starts with path_start and a slash.
*
* Ex:
*   full_path:  dir1/dir2/dir3/dir4
*   path_start: dir1/dir2
*   Returns:    dir3/dir4
*
* @param full_path  The full path
* @param path_start The parent path that should be removed (should not include trailing slash)
*
* @return Pointer to remaining string, NULL on error
*/
static const TSK_TCHAR*
get_end_of_path(const TSK_TCHAR* full_path, const TSK_TCHAR* path_start) {
	if (full_path == NULL || path_start == NULL) {
		return NULL;
	}

	if (TSTRLEN(path_start) + 1 >= TSTRLEN(full_path)) {
		return NULL;
	}

	// +1 for trailing slash
	return &(full_path[TSTRLEN(path_start) + 1]);
}

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
	helper->target_inum = LOGICAL_INVALID_INUM;
	size_t target_path_len = TSTRLEN(target_path) + 1;
	helper->target_path = (TSK_TCHAR*)tsk_malloc(sizeof(TSK_TCHAR) * target_path_len);
	if (helper->target_path == NULL) {
		free(helper);
		return NULL;
	}
	TSTRNCPY(helper->target_path, target_path, target_path_len);
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
			tsk_fprintf(stderr, "convert_wide_string_to_utf8: error converting logical file name to UTF-8\n");
		snprintf(dest, maxUTF8len, "%s", invalidName);
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
 * @return The search path with wildcard appended, Ex. C:\Windows\* (must be freed by caller)
 */
TSK_TCHAR * create_search_path(const TSK_TCHAR *base_path) {
#ifdef TSK_WIN32
	// base_path is always \\?\-prefixed (set at logical_open time) so no
	// long-path conversion is needed here — just append the wildcard.
	size_t base_len = TSTRLEN(base_path);
	TSK_TCHAR *searchPath = (TSK_TCHAR *)tsk_malloc(sizeof(TSK_TCHAR) * (base_len + 3));
	if (searchPath == NULL) {
		return NULL;
	}
	TSTRNCPY(searchPath, base_path, base_len + 1);
	TSTRNCAT(searchPath, L"\\*", 3);
	return searchPath;
#else
	size_t len = TSTRLEN(base_path);
	TSK_TCHAR *searchPath = (TSK_TCHAR *)tsk_malloc(sizeof(TSK_TCHAR) * (len + 3));
	if (searchPath == NULL) {
		return NULL;
	}
	TSTRNCPY(searchPath, base_path, len + 1);
	TSTRNCAT(searchPath, "/*", 3);
	return searchPath;
#endif
}

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
/*
 * Currently uses FindFirstFileW/FindNextFileW which is compatible with XP+.
 * For future optimization on Windows 7+, could switch to FindFirstFileEx with
 * FIND_FIRST_EX_LARGE_FETCH flag to internally batch multiple directory entries
 * per syscall. This would improve performance for very large directories
 * (1000+ files), reducing syscall overhead by 50-300%. However, XP compatibility
 * would need to be handled via conditional compilation or runtime version checks
 * if that optimization is pursued.
 *
 * Caching: when logical_img_info is non-NULL and dir_inum is valid, this function
 * consults the dir_file_list_cache for LOAD_FILES_ONLY callers. On hit, the cached
 * sorted file_names is returned without disk I/O. On miss, file_names is sorted
 * after enumeration and inserted into the cache. The cache currently stores only
 * file names (not dir names), so it is bypassed for LOAD_ALL and LOAD_DIRS_ONLY
 * callers. Callers without a valid dir_inum (or that pass NULL for logical_img_info)
 * bypass caching entirely - the function behaves like a raw enumerator.
 */
static TSK_RETVAL_ENUM
load_dir_and_file_lists_win(
	IMG_LOGICAL_INFO* logical_img_info,
	TSK_INUM_T dir_inum,
	const TSK_TCHAR *base_path,
	vector<wstring>& file_names,
	vector<wstring>& dir_names,
	LOGICALFS_DIR_LOADING_MODE mode) {

	if (logical_img_info == nullptr) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_FS_GENFS);
		tsk_error_set_errstr("load_dir_and_file_lists: Error building search path for directory %. Nullptr passed in." PRIttocTSK, base_path);
		return TSK_ERR;
	}

	// The dir_file_list_cache currently only stores file names, so it can only
	// don't attempt to look up when just returning dirs
	bool can_cache = (dir_inum != LOGICAL_INVALID_INUM
		&& mode != LOGICALFS_LOAD_DIRS_ONLY);

	// ──── Cache lookup ────
	bool file_cache_hit = false;
	if (can_cache) {
		TSK_IMG_INFO* img_info = &logical_img_info->img_info;
		tsk_take_lock(&img_info->cache_lock);
		for (int i = 0; i < DIR_FILE_LIST_CACHE_LEN; i++) {
			DIR_FILE_CACHE_ENTRY* entry = &logical_img_info->dir_file_list_cache.entries[i];
			if (entry->dir_inum != dir_inum) {
				continue;
			}

			// Cache hit: copy the cached file list
			file_cache_hit = true;
			file_names.clear();
			for (size_t j = 0; j < entry->file_count; j++) {
				file_names.push_back(entry->file_names[j]);
			}

			// LOAD_FILES_ONLY callers don't need the dir list, so we can short-circuit
			// before enumerating. LOAD_ALL callers still need the dir list - fall
			// through so the Win32 enumeration below populates dir_names.
			if (mode == LOGICALFS_LOAD_FILES_ONLY) {
				tsk_release_lock(&img_info->cache_lock);
				return TSK_OK;
			}
			break;
		}

		tsk_release_lock(&img_info->cache_lock);
	}

	// ──── Cache miss (or caching disabled): enumerate from disk ────
	WIN32_FIND_DATAW fd;
	HANDLE hFind;

	// Create the search string (base_path + "\*"). create_search_path handles
	// both short and long paths internally (applies \\?\ prefix when necessary).
	TSK_TCHAR* search_path_wildcard = create_search_path(base_path);
	if (search_path_wildcard == NULL) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_FS_GENFS);
		tsk_error_set_errstr("load_dir_and_file_lists: Error building search path for directory %" PRIttocTSK, base_path);
		return TSK_ERR;
	}

	hFind = ::FindFirstFileW(search_path_wildcard, &fd);
	if (hFind == INVALID_HANDLE_VALUE) {
		free(search_path_wildcard);
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_FS_GENFS);
		tsk_error_set_errstr("load_dir_and_file_lists: Error looking up contents of directory %" PRIttocTSK, base_path);
		return TSK_ERR;
	}

	do {
		if (shouldTreatAsDirectory(fd.dwFileAttributes)) {
			if (mode == LOGICALFS_LOAD_ALL || mode == LOGICALFS_LOAD_DIRS_ONLY) {
				// For the moment at least, skip . and ..
				if (0 != wcsncmp(fd.cFileName, L"..", 3) && 0 != wcsncmp(fd.cFileName, L".", 3)) {
					dir_names.push_back(wstring(fd.cFileName));
				}
			}
		}
		else {
			if (!file_cache_hit && (mode == LOGICALFS_LOAD_ALL || mode == LOGICALFS_LOAD_FILES_ONLY)) {
				// For now, consider everything else to be a file
				file_names.push_back(wstring(fd.cFileName));
			}
		}
	} while (::FindNextFileW(hFind, &fd));

	::FindClose(hFind);
	free(search_path_wildcard);

	// Need to sort to keep Inums consistent
	// TEMP: instrument sort time to evaluate whether it's worth optimizing.
	// Remove this block + the <chrono> include when measurement is done.
	{
		static long long total_sort_us = 0;
		static long sort_call_count = 0;
		static size_t total_items_sorted = 0;
		auto t_start = std::chrono::high_resolution_clock::now();

		if (!file_cache_hit) {
			sort(file_names.begin(), file_names.end(), case_insensitive_compare);
		}
		sort(dir_names.begin(), dir_names.end(), case_insensitive_compare);

		auto t_end = std::chrono::high_resolution_clock::now();
		long long elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(
			t_end - t_start).count();
		total_sort_us += elapsed_us;
		sort_call_count++;
		total_items_sorted += file_names.size() + dir_names.size();

		// Print a summary every 1000 calls so we get a feel without flooding stderr.
		if (sort_call_count % 1000 == 0) {
			tsk_fprintf(stderr,
				"[sort timing] calls=%ld total_us=%lld avg_us=%.2f total_items=%" PRIuSIZE " avg_items=%.1f\n",
				sort_call_count, total_sort_us,
				(double)total_sort_us / (double)sort_call_count,
				total_items_sorted,
				(double)total_items_sorted / (double)sort_call_count);
			fflush(stderr);
		}
	}

	// ──── Cache file list if needed ────
	// Skip caching dirs with 0 or 1 files. Cost of caching exceeds the benefit
    // for trivially small directories.
	if (!file_cache_hit && can_cache && file_names.size() > 1) {

		// Build the replacement file_names array in local temporaries FIRST.
		// Only evict the existing slot once every allocation has succeeded; that
		// way a malloc failure leaves the previous occupant intact and the caller
		// still gets valid data via the output vector below.
		TSK_TCHAR** new_file_names = (TSK_TCHAR**)tsk_malloc(sizeof(TSK_TCHAR*) * file_names.size());
		if (new_file_names == NULL) {
			// Cache write failed; caller already has the data.
			return TSK_OK;
		}

		bool alloc_ok = true;
		size_t alloc_failed_at = 0;
		for (size_t j = 0; j < file_names.size(); j++) {
			size_t name_len = file_names[j].length() + 1;
			new_file_names[j] = (TSK_TCHAR*)tsk_malloc(sizeof(TSK_TCHAR) * name_len);
			if (new_file_names[j] == NULL) {
				alloc_ok = false;
				alloc_failed_at = j;
				break;
			}
			TSTRNCPY(new_file_names[j], file_names[j].c_str(), name_len);
		}

		if (!alloc_ok) {
			// Free partial temporaries and return - cache slot untouched.
			for (size_t k = 0; k < alloc_failed_at; k++) {
				free(new_file_names[k]);
			}
			free(new_file_names);
			return TSK_OK;
		}

		// All allocations succeeded - swap into the cache.
		TSK_IMG_INFO* img_info = &logical_img_info->img_info;
		tsk_take_lock(&img_info->cache_lock);

		int insert_idx = logical_img_info->dir_file_list_cache.next_insert_index;
		DIR_FILE_CACHE_ENTRY* entry = &logical_img_info->dir_file_list_cache.entries[insert_idx];

		// Free the previous occupant's data
		if (entry->file_names != NULL) {
			for (size_t j = 0; j < entry->file_count; j++) {
				free(entry->file_names[j]);
			}
			free(entry->file_names);
		}

		// Install the new data
		entry->file_names = new_file_names;
		entry->file_count = file_names.size();
		entry->dir_inum = dir_inum;
		logical_img_info->dir_file_list_cache.next_insert_index =
			(insert_idx + 1) % DIR_FILE_LIST_CACHE_LEN;

		tsk_release_lock(&img_info->cache_lock);
	}

	return TSK_OK;
}
#endif

/*
 * Convert a full OS path into a path relative to the logical file system's base_path.
 * Cache entries store paths without the base_path prefix to save memory and to keep
 * LOGICAL_INUM_CACHE_MAX_PATH_LEN evaluating only the meaningful portion of the path.
 *
 * The caller MUST guarantee that 'path' starts with logical_fs_info->base_path. This
 * is verified by an assertion in debug builds. Violating this precondition advances
 * the returned pointer past the end of 'path' (or into the wrong substring), leading
 * to silent memory corruption or wrong cache matches.
 *
 * @param logical_fs_info The logical file system (must have a non-NULL base_path)
 * @param path            A full path that starts with logical_fs_info->base_path
 *
 * @return Pointer into 'path' just past the base_path prefix
 */
static const TSK_TCHAR*
get_path_relative_to_base(const LOGICALFS_INFO* logical_fs_info, const TSK_TCHAR* path) {
	size_t base_len = TSTRLEN(logical_fs_info->base_path);
#ifdef TSK_WIN32
	assert(_wcsnicmp(path, logical_fs_info->base_path, base_len) == 0);
#else
	assert(strncmp(path, logical_fs_info->base_path, base_len) == 0);
#endif
	return path + base_len;
}

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
find_closest_path_match_in_cache(LOGICALFS_INFO *logical_fs_info, const TSK_TCHAR *target_path, TSK_TCHAR **best_path, TSK_INUM_T *best_inum) {
	// TEMP cs: time hit vs miss in the inum_cache prefix scan. Remove when done.
#ifdef TSK_WIN32
	static LARGE_INTEGER cs_pm_freq = {0};
	if (cs_pm_freq.QuadPart == 0) QueryPerformanceFrequency(&cs_pm_freq);
	static long long cs_pm_hit_us = 0, cs_pm_miss_us = 0;
	static long cs_pm_hits = 0, cs_pm_misses = 0;
	LARGE_INTEGER cs_pm_t0, cs_pm_t1;
	QueryPerformanceCounter(&cs_pm_t0);
#endif

	TSK_IMG_INFO* img_info = logical_fs_info->fs_info.img_info;
	IMG_LOGICAL_INFO* logical_img_info = (IMG_LOGICAL_INFO*)img_info;
	tsk_take_lock(&(img_info->cache_lock));

	*best_inum = LOGICAL_INVALID_INUM;
	*best_path = NULL;
	int best_match_index = -1;
	size_t longest_match = 0;

	// Cache entries store paths relative to base_path. Strip the base prefix from target_path
	// so comparisons are performed entirely in relative-path space.
	const TSK_TCHAR *relative_target = get_path_relative_to_base(logical_fs_info, target_path);
	size_t base_len = TSTRLEN(logical_fs_info->base_path);
	size_t target_len = TSTRLEN(relative_target);

	for (int i = 0; i < LOGICAL_INUM_CACHE_LEN; i++) {
		if (logical_img_info->inum_cache[i].inum == LOGICAL_INVALID_INUM) {
			break; // Entries are packed from index 0; first empty slot means no more entries.
		}

		// This should not happen
		if (logical_img_info->inum_cache[i].path == NULL) {
			continue;
		}

		// Skip entries that can't beat our current best match or are longer than the target
		size_t cache_path_len = logical_img_info->inum_cache[i].path_len;
		if ((cache_path_len > target_len) || (cache_path_len <= longest_match)) {
			continue;
		}

		size_t matching_len = 0;
#ifdef TSK_WIN32
		if (0 == _wcsnicmp(relative_target, logical_img_info->inum_cache[i].path, cache_path_len)) {
			matching_len = cache_path_len;
		}
#endif

		// Exact match - can't do better, stop scanning
		if (matching_len == target_len) {
			longest_match = matching_len;
			best_match_index = i;
			break;
		}

		// Partial match - longer than current best and a valid path prefix (not just a substring)
		if (matching_len > longest_match &&
				(relative_target[matching_len] == L'/' || relative_target[matching_len] == L'\\')) {
			longest_match = matching_len;
			best_match_index = i;
		}
	}

	// If we found a full or partial match, mark it as recently used and reconstruct the full OS path
	if (best_match_index >= 0) {
		logical_img_info->inum_cache[best_match_index].last_used = ++logical_img_info->inum_cache_clock;
		*best_inum = logical_img_info->inum_cache[best_match_index].inum;
		size_t relative_len = logical_img_info->inum_cache[best_match_index].path_len;
		size_t best_path_len = base_len + relative_len + 1;
		*best_path = (TSK_TCHAR*)tsk_malloc(sizeof(TSK_TCHAR) * best_path_len);
		if (*best_path == NULL) {
			tsk_release_lock(&(img_info->cache_lock));
			return TSK_ERR;
		}
		TSTRNCPY(*best_path, logical_fs_info->base_path, base_len + 1);
		TSTRNCAT(*best_path, logical_img_info->inum_cache[best_match_index].path, relative_len + 1);
	}

	tsk_release_lock(&(img_info->cache_lock));

#ifdef TSK_WIN32
	// TEMP cs: accumulate prefix-scan timing by outcome
	QueryPerformanceCounter(&cs_pm_t1);
	long long cs_pm_elapsed = ((cs_pm_t1.QuadPart - cs_pm_t0.QuadPart) * 1000000) / cs_pm_freq.QuadPart;
	if (best_match_index >= 0) {
		cs_pm_hit_us += cs_pm_elapsed;
		cs_pm_hits++;
	} else {
		cs_pm_miss_us += cs_pm_elapsed;
		cs_pm_misses++;
	}
	if ((cs_pm_hits + cs_pm_misses) % 1000 == 0) {
		tsk_fprintf(stderr,
			"[cache_scan prefix] hits=%ld total_us=%lld avg=%.2f | misses=%ld total_us=%lld avg=%.2f\n",
			cs_pm_hits, cs_pm_hit_us, cs_pm_hits ? (double)cs_pm_hit_us / (double)cs_pm_hits : 0.0,
			cs_pm_misses, cs_pm_miss_us, cs_pm_misses ? (double)cs_pm_miss_us / (double)cs_pm_misses : 0.0);
		fflush(stderr);
	}
#endif
	return TSK_OK;
}

/*
 * Finds closest sibling match for the given folder.
 * If best_path is not NULL, caller must free.
 *
 * This method does not alter cache ages.
 *
 * @param logical_fs_info The logical file system
 * @param target_path     The full path being searched for
 * @param parent_path     The parent path that we found in the cache
 * @param parent_inum     The addr of the parent path
 * @param best_name       The best match found in the cache - file name only. (NULL if none are found, must be freed by caller otherwise)
 * @param best_inum       The inum matching the best path found. LOGICAL_INVALID_INUM if none are found.
 *
 * @return TSK_ERR if an error occurred, TSK_OK otherwise
 */
static TSK_RETVAL_ENUM
find_closest_sibling_match_in_cache(LOGICALFS_INFO* logical_fs_info, const TSK_TCHAR* target_path, const TSK_TCHAR* parent_path, TSK_INUM_T parent_inum, TSK_TCHAR** best_name, TSK_INUM_T* best_inum) {
	// TEMP cs: time hit vs miss in the inum_cache sibling scan. Remove when done.
#ifdef TSK_WIN32
	static LARGE_INTEGER cs_sb_freq = {0};
	if (cs_sb_freq.QuadPart == 0) QueryPerformanceFrequency(&cs_sb_freq);
	static long long cs_sb_hit_us = 0, cs_sb_miss_us = 0;
	static long cs_sb_hits = 0, cs_sb_misses = 0;
	LARGE_INTEGER cs_sb_t0, cs_sb_t1;
	QueryPerformanceCounter(&cs_sb_t0);
#endif
	TSK_IMG_INFO* img_info = logical_fs_info->fs_info.img_info;
	IMG_LOGICAL_INFO* logical_img_info = (IMG_LOGICAL_INFO*)img_info;
	tsk_take_lock(&(img_info->cache_lock));

	*best_inum = LOGICAL_INVALID_INUM;
	*best_name = NULL;

	int best_match_index = -1;
	TSK_INUM_T highest_inum = LOGICAL_INVALID_INUM;

	// Cache entries store paths relative to base_path. Strip the base prefix from the
	// caller-supplied full OS paths so comparisons are performed in relative-path space.
	const TSK_TCHAR *relative_target = get_path_relative_to_base(logical_fs_info, target_path);
	const TSK_TCHAR *relative_parent = get_path_relative_to_base(logical_fs_info, parent_path);

	for (int i = 0; i < LOGICAL_INUM_CACHE_LEN; i++) {
		if (logical_img_info->inum_cache[i].inum == LOGICAL_INVALID_INUM) {
			break; // Entries are packed from index 0; first empty slot means no more entries.
		}
		if (logical_img_info->inum_cache[i].path != NULL
			&& logical_img_info->inum_cache[i].inum > parent_inum
			&& logical_img_info->inum_cache[i].inum > highest_inum) {

			// This entry is useful if:
			// - path is directly under the target's parent folder
			// - path comes before the target path alphabetically
			// - inum is larger than our previous best match
			if (!path_is_subfolder(relative_parent, logical_img_info->inum_cache[i].path)) {
				continue;
			}

			const TSK_TCHAR* rest = get_end_of_path(logical_img_info->inum_cache[i].path, relative_parent);
			if (contains_folder_separator(rest)) {
				continue;
			}

			if (TSTRICMP(relative_target, logical_img_info->inum_cache[i].path) > 0) {
				highest_inum = logical_img_info->inum_cache[i].inum;
				best_match_index = i;
			}
		}
	}

	// If we found something, store the values
	if (best_match_index >= 0) {

		const TSK_TCHAR* name = get_end_of_path(logical_img_info->inum_cache[best_match_index].path, relative_parent);
		if (name == NULL) {
			if (tsk_verbose) {
				tsk_fprintf(stderr, "find_closest_sibling_match_in_cache: get_end_of_path returned null for child: %" PRIttocTSK " parent: %" PRIttocTSK "\n",
					logical_img_info->inum_cache[best_match_index].path, relative_parent);
			}
			tsk_release_lock(&(img_info->cache_lock));
			return TSK_ERR;
		}
		size_t name_len = TSTRLEN(name) + 1;
		*best_name = (TSK_TCHAR*)tsk_malloc(sizeof(TSK_TCHAR) * name_len);
		if (*best_name == NULL) {
			tsk_release_lock(&(img_info->cache_lock));
			return TSK_ERR;
		}
		TSTRNCPY(*best_name, name, name_len);
		*best_inum = logical_img_info->inum_cache[best_match_index].inum;
	}

	tsk_release_lock(&(img_info->cache_lock));

#ifdef TSK_WIN32
	// TEMP cs: accumulate sibling-scan timing by outcome
	QueryPerformanceCounter(&cs_sb_t1);
	long long cs_sb_elapsed = ((cs_sb_t1.QuadPart - cs_sb_t0.QuadPart) * 1000000) / cs_sb_freq.QuadPart;
	if (best_match_index >= 0) {
		cs_sb_hit_us += cs_sb_elapsed;
		cs_sb_hits++;
	} else {
		cs_sb_miss_us += cs_sb_elapsed;
		cs_sb_misses++;
	}
	if ((cs_sb_hits + cs_sb_misses) % 1000 == 0) {
		tsk_fprintf(stderr,
			"[cache_scan sibling] hits=%ld total_us=%lld avg=%.2f | misses=%ld total_us=%lld avg=%.2f\n",
			cs_sb_hits, cs_sb_hit_us, cs_sb_hits ? (double)cs_sb_hit_us / (double)cs_sb_hits : 0.0,
			cs_sb_misses, cs_sb_miss_us, cs_sb_misses ? (double)cs_sb_miss_us / (double)cs_sb_misses : 0.0);
		fflush(stderr);
	}
#endif
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
	// TEMP cs: time hit vs miss in the inum_cache reverse-lookup scan. Remove when done.
#ifdef TSK_WIN32
	static LARGE_INTEGER cs_in_freq = {0};
	if (cs_in_freq.QuadPart == 0) QueryPerformanceFrequency(&cs_in_freq);
	static long long cs_in_hit_us = 0, cs_in_miss_us = 0;
	static long cs_in_hits = 0, cs_in_misses = 0;
	LARGE_INTEGER cs_in_t0, cs_in_t1;
	QueryPerformanceCounter(&cs_in_t0);
#endif

	TSK_IMG_INFO* img_info = logical_fs_info->fs_info.img_info;
	IMG_LOGICAL_INFO* logical_img_info = (IMG_LOGICAL_INFO*)img_info;
	tsk_take_lock(&(img_info->cache_lock));
	TSK_TCHAR *target_path = NULL;
	for (int i = 0; i < LOGICAL_INUM_CACHE_LEN; i++) {
		if (logical_img_info->inum_cache[i].inum == LOGICAL_INVALID_INUM) {
			break; // Entries are packed from index 0; first empty slot means no more entries.
		}
		if ((target_path == NULL) && (logical_img_info->inum_cache[i].inum == target_inum)) {
			// Mark as recently used and reconstruct the full OS path by prepending base_path
			logical_img_info->inum_cache[i].last_used = ++logical_img_info->inum_cache_clock;
			size_t base_len = TSTRLEN(logical_fs_info->base_path);
			size_t target_path_len = base_len + logical_img_info->inum_cache[i].path_len + 1;
			target_path = (TSK_TCHAR*)tsk_malloc(sizeof(TSK_TCHAR) * target_path_len);
			if (target_path == NULL) {
				tsk_release_lock(&(img_info->cache_lock));
				return NULL;
			}
			TSTRNCPY(target_path, logical_fs_info->base_path, base_len + 1);
			TSTRNCAT(target_path, logical_img_info->inum_cache[i].path, target_path_len - base_len);
		}
	}

	tsk_release_lock(&(img_info->cache_lock));

#ifdef TSK_WIN32
	// TEMP cs: accumulate inum-lookup-scan timing by outcome
	QueryPerformanceCounter(&cs_in_t1);
	long long cs_in_elapsed = ((cs_in_t1.QuadPart - cs_in_t0.QuadPart) * 1000000) / cs_in_freq.QuadPart;
	if (target_path != NULL) {
		cs_in_hit_us += cs_in_elapsed;
		cs_in_hits++;
	} else {
		cs_in_miss_us += cs_in_elapsed;
		cs_in_misses++;
	}
	if ((cs_in_hits + cs_in_misses) % 1000 == 0) {
		tsk_fprintf(stderr,
			"[cache_scan inum_lookup] hits=%ld total_us=%lld avg=%.2f | misses=%ld total_us=%lld avg=%.2f\n",
			cs_in_hits, cs_in_hit_us, cs_in_hits ? (double)cs_in_hit_us / (double)cs_in_hits : 0.0,
			cs_in_misses, cs_in_miss_us, cs_in_misses ? (double)cs_in_miss_us / (double)cs_in_misses : 0.0);
		fflush(stderr);
	}
#endif
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

	// Store only the path relative to base_path so that the base path prefix doesn't waste
	// space in every entry or eat into LOGICAL_INUM_CACHE_MAX_PATH_LEN unnecessarily.
	const TSK_TCHAR *relative_path = get_path_relative_to_base(logical_fs_info, path);

	// If the relative path is very long then don't cache it to make sure the cache stays reasonably small.
	if (TSTRLEN(relative_path) > LOGICAL_INUM_CACHE_MAX_PATH_LEN) {
		return TSK_OK;
	}

	TSK_IMG_INFO* img_info = logical_fs_info->fs_info.img_info;
	IMG_LOGICAL_INFO* logical_img_info = (IMG_LOGICAL_INFO*)img_info;
	tsk_take_lock(&(img_info->cache_lock));

	// Single pass: check for an existing entry, track the first empty slot, and track the LRU
	// candidate — all at once so we never walk the array more than once.
	int next_slot = -1;
	uint32_t oldest_tick = UINT32_MAX;
	for (int i = 0; i < LOGICAL_INUM_CACHE_LEN; i++) {
		if (logical_img_info->inum_cache[i].inum == LOGICAL_INVALID_INUM) {
			// First empty slot — use it and stop looking for a victim.
			next_slot = i;
			break;
		}
		if (logical_img_info->inum_cache[i].inum == inum) {
			// Already cached — refresh timestamp if this is a priority insert and return.
			if (always_cache) {
				logical_img_info->inum_cache[i].last_used = ++logical_img_info->inum_cache_clock;
			}
			tsk_release_lock(&(img_info->cache_lock));
			return TSK_OK;
		}
		if (logical_img_info->inum_cache[i].last_used < oldest_tick) {
			next_slot = i;
			oldest_tick = logical_img_info->inum_cache[i].last_used;
		}
	}

	// If the always_cache flag is not set, only continue if we've found an empty slot (no eviction)
	if (next_slot < 0 || (!always_cache && logical_img_info->inum_cache[next_slot].inum != LOGICAL_INVALID_INUM)) {
		tsk_release_lock(&(img_info->cache_lock));
		return TSK_OK;
	}
	// Allocate the new path buffer BEFORE evicting the old entry.
	// If tsk_malloc fails after clear_inum_cache_entry, the slot would be left as
	// LOGICAL_INVALID_INUM in the middle of the array, creating a hole that causes
	// all the break-on-first-invalid scan loops to miss valid entries beyond it.
	size_t cache_path_len = TSTRLEN(relative_path) + 1;
	TSK_TCHAR* new_path = (TSK_TCHAR*)tsk_malloc(sizeof(TSK_TCHAR) * cache_path_len);
	if (new_path == NULL) {
		tsk_release_lock(&(img_info->cache_lock));
		return TSK_ERR;
	}

	clear_inum_cache_entry(logical_img_info, next_slot);

	// Copy the relative path (without base_path prefix)
	logical_img_info->inum_cache[next_slot].path = new_path;
	TSTRNCPY(logical_img_info->inum_cache[next_slot].path, relative_path, cache_path_len);
	logical_img_info->inum_cache[next_slot].path_len = cache_path_len - 1;  // cache_path_len includes NUL
	logical_img_info->inum_cache[next_slot].inum = inum;
	logical_img_info->inum_cache[next_slot].last_used = ++logical_img_info->inum_cache_clock;
	tsk_release_lock(&(img_info->cache_lock));
	return TSK_OK;
}

// This should be done with a template, but I'm lazy.
// Windows version
#ifdef TSK_WIN32
bool case_insensitive_compare(const std::wstring& a, const std::wstring& b) {
	return std::lexicographical_compare(
		a.begin(), a.end(),
		b.begin(), b.end(),
		[](wchar_t a, wchar_t b) {
		  return std::towlower(a) < std::towlower(b);
		}
	);
}
#else
bool case_insensitive_compare(const string& a, const string& b) {
	return std::lexicographical_compare(
		a.begin(), a.end(),
		b.begin(), b.end(),
		[](char a, char b) {
		  return std::tolower(a) < std::tolower(b);
		}
	);
}
#endif

/*
 * Main recursive method for walking the directories. Will load and sort all directories found
 * in parent_path, assign an inum to each and check if this is what we're searching for, calling
 * this method recursively if not.
 *
 * @param logical_fs_info   LOGICALFS_INFO object
 * @param parent_path       The full path on disk to the directory to open
 * @param last_inum_ptr     Pointer to the last assigned inum. Will be updated for every directory found
 * @param sibling_name      Name of sibling file to help limit search (use NULL if no sibling file is known)
 * @param sibling_inum      Address of sibling file (use LOGICAL_INVALID_INUM if no sibling file is known)
 * @param search_helper     Contains information on what type of search is being performed and will store the results in most cases.
 *
 * @return TSK_OK if successfull, TSK_ERR otherwise
 */
static TSK_RETVAL_ENUM
search_directory_recursive(LOGICALFS_INFO *logical_fs_info, const TSK_TCHAR * parent_path, TSK_INUM_T *last_inum_ptr,
	const TSK_TCHAR* sibling_name, TSK_INUM_T sibling_inum, LOGICALFS_SEARCH_HELPER* search_helper) {

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
		// Use the per-directory file-name-list cache to avoid enumerating the same
		// directory once per file. Without this, resolving K files in one directory
		// costs K OS enumerations + K sorts instead of 1. load_dir_and_file_lists_win
		// handles the cache check + insert internally when given a valid inum.
		IMG_LOGICAL_INFO* logical_img_info_cache = (IMG_LOGICAL_INFO*)logical_fs_info->fs_info.img_info;
		vector<wstring> dir_names_unused;
		if (TSK_OK != load_dir_and_file_lists_win(logical_img_info_cache, *last_inum_ptr,
				parent_path, file_names, dir_names_unused, LOGICALFS_LOAD_FILES_ONLY)) {
			// Error message already set
			return TSK_ERR;
		}
#endif

		// Look for the file corresponding to the given inum
		size_t file_index = (search_helper->target_inum & LOGICAL_INUM_FILE_MASK) - 1;
		if (file_names.size() <= file_index) {
			tsk_error_reset();
			tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
			tsk_error_set_errstr("search_directory_recusive - inum %" PRIuINUM " not found", search_helper->target_inum);
			return TSK_ERR;
		}

		search_helper->target_found = true;
		size_t parent_len = TSTRLEN(parent_path) + 1;
		size_t found_path_len = parent_len + TSTRLEN(file_names[file_index].c_str());
		search_helper->found_path = (TSK_TCHAR*)tsk_malloc(sizeof(TSK_TCHAR) * (found_path_len + 1));
		TSTRNCPY(search_helper->found_path, parent_path, parent_len);
#ifdef TSK_WIN32
		TSTRNCAT(search_helper->found_path, L"\\", 2);
#else
		TSTRNCAT(search_helper->found_path, "/", 2);
#endif
		TSTRNCAT(search_helper->found_path, file_names[file_index].c_str(), TSTRLEN(file_names[file_index].c_str()) + 1);
		return TSK_OK;
	}

#ifdef TSK_WIN32
	// LOAD_DIRS_ONLY: caching doesn't apply (cache only stores file names today), pass
	// NULL/LOGICAL_INVALID_INUM to bypass the cache path.
	IMG_LOGICAL_INFO* logical_img_info_cache = (IMG_LOGICAL_INFO*)logical_fs_info->fs_info.img_info;
	if (TSK_OK != load_dir_and_file_lists_win(logical_img_info_cache, LOGICAL_INVALID_INUM,
			parent_path, file_names, dir_names, LOGICALFS_LOAD_DIRS_ONLY)) {
		// Error message already set
		return TSK_ERR;
	}
#endif


	// Set up the beginning of full path to the file on disk
	// The directoy name being added should generally be less than 270 characters, but if necessary we will
	// make more space available.
	size_t allocated_dir_name_len = 270;
	size_t parent_path_base_len = TSTRLEN(parent_path) + 1;
	TSK_TCHAR* current_path = (TSK_TCHAR*)tsk_malloc(sizeof(TSK_TCHAR) * (parent_path_base_len + 1 + allocated_dir_name_len));
	if (current_path == NULL)
		return TSK_ERR;
	TSTRNCPY(current_path, parent_path, parent_path_base_len);
#ifdef TSK_WIN32
	TSTRNCAT(current_path, L"\\", 2);
#else
	TSTRNCAT(current_path, "/", 2);
#endif
	size_t parent_path_len = TSTRLEN(current_path);

	// If we were given a sibling directory, look for it in the list so we can start the search there
	size_t starting_dir_index = 0;
	if (sibling_inum != LOGICAL_INVALID_INUM && sibling_name != NULL) {
		for (size_t i = 0; i < dir_names.size(); i++) {
#ifdef TSK_WIN32
			if (0 == _wcsicmp(dir_names[i].c_str(), sibling_name)) {
				// Found it. Save the index and adjust the last inum (LOGICAL_INUM_DIR_INC will get added to last_inum_ptr)
				starting_dir_index = i;
				*last_inum_ptr = sibling_inum - LOGICAL_INUM_DIR_INC;
				break;
			}
#endif
		}
	}

	for (size_t i = starting_dir_index; i < dir_names.size(); i++) {

		// If we don't have space for this name, increase the size of the buffer
		if (TSTRLEN(dir_names[i].c_str()) > allocated_dir_name_len) {
			free(current_path);
			allocated_dir_name_len = TSTRLEN(dir_names[i].c_str()) + 20;
			current_path = (TSK_TCHAR*)tsk_malloc(sizeof(TSK_TCHAR) * (parent_path_base_len + 1 + allocated_dir_name_len));
			if (current_path == NULL)
				return TSK_ERR;
			TSTRNCPY(current_path, parent_path, parent_path_base_len);
#ifdef TSK_WIN32
			TSTRNCAT(current_path, L"\\", 2);
#else
			TSTRNCAT(current_path, "/", 2);
#endif
		}

		// Append the current directory name to the parent path
		TSTRNCPY(current_path + parent_path_len, dir_names[i].c_str(), allocated_dir_name_len + 1);
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
		// For LOGICALFS_SEARCH_BY_INUM we opportunistically cache every visited directory with always_cache=false
		// (i.e. only if a free slot exists) so that subsequent inum searches benefit from prior traversals without
		// risking a stampede that evicts more useful entries.
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
		else if (search_helper->search_type == LOGICALFS_SEARCH_BY_INUM) {
			// Opportunistically cache every directory visited during an inum search.
			// always_cache=false means we only use a free slot - we don't evict useful entries.
			// With a large enough LOGICAL_INUM_CACHE_LEN this warms the cache so that the
			// next inum search for a nearby directory hits the cache instead of re-traversing.
			add_directory_to_cache(logical_fs_info, current_path, current_inum, false);
		}

		// Check if we've found it
		if ((search_helper->search_type == LOGICALFS_SEARCH_BY_PATH)
			&& (TSTRICMP(current_path, search_helper->target_path) == 0)) {
			search_helper->target_found = true;
			search_helper->found_inum = current_inum;
			free(current_path);
			return TSK_OK;
		}

		if ((search_helper->search_type == LOGICALFS_SEARCH_BY_INUM)
				&& (current_inum == search_helper->target_inum)) {
			search_helper->target_found = true;
			size_t found_path_size = TSTRLEN(current_path) + 1;
			search_helper->found_path = (TSK_TCHAR*)tsk_malloc(sizeof(TSK_TCHAR) * found_path_size);
			if (search_helper->found_path == NULL)
				return TSK_ERR;
			TSTRNCPY(search_helper->found_path, current_path, found_path_size);
			free(current_path);
			return TSK_OK;
		}
		TSK_RETVAL_ENUM result = search_directory_recursive(logical_fs_info, current_path, last_inum_ptr, NULL, LOGICAL_INVALID_INUM, search_helper);
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
		size_t base_path_len = TSTRLEN(logical_fs_info->base_path) + 1;
		path = (TSK_TCHAR*)tsk_malloc(sizeof(TSK_TCHAR) * base_path_len);
		if (path == NULL)
			return NULL;
		TSTRNCPY(path, logical_fs_info->base_path, base_path_len);
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
		if (cache_path != NULL) {
			free(cache_path);
		}
		return NULL;
	}

	// Run the search
	TSK_RETVAL_ENUM result = search_directory_recursive(logical_fs_info, starting_path, &starting_inum, NULL, LOGICAL_INVALID_INUM, search_helper);

	if (cache_path != NULL) {
		free(cache_path);
		cache_path = nullptr;
		starting_path = nullptr;
	}

	if ((result != TSK_OK) || (!search_helper->target_found)) {
		TSK_INUM_T target_inum = search_helper->target_inum;
		free_search_helper(search_helper);
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
		tsk_error_set_errstr("load_path_from_inum - failed to find path corresponding to inum %" PRIuINUM, target_inum);
		return NULL;
	}

	// Copy the path
	size_t found_len = TSTRLEN(search_helper->found_path) + 1;
	path = (TSK_TCHAR*)tsk_malloc(sizeof(TSK_TCHAR) * found_len);
	if (path == NULL) {
		free_search_helper(search_helper);
		return NULL;
	}
	TSTRNCPY(path, search_helper->found_path, found_len);
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
	// path is built from base_path which is always \\?\-prefixed — no conversion needed.
	HANDLE hFind = ::FindFirstFileW(path, &fd);

	free(path);
	path = nullptr;

	if (hFind != INVALID_HANDLE_VALUE) {
		TSK_RETVAL_ENUM result = populate_fs_file_from_win_find_data(&fd, a_fs_file);
		::FindClose(hFind);
		return result;
	}
	else {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_FS_GENFS);
		tsk_error_set_errstr("logicalfs_file_add_meta: Error loading directory %" PRIttocTSK, path);
		return TSK_ERR;
	}
#endif
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
	TSK_RETVAL_ENUM result = search_directory_recursive(logical_fs_info, logical_fs_info->base_path, &last_assigned_inum, NULL, LOGICAL_INVALID_INUM, search_helper);
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
	IMG_LOGICAL_INFO* img_info_fmi = (IMG_LOGICAL_INFO*)logical_fs_info->fs_info.img_info;
	if (TSK_OK != load_dir_and_file_lists_win(img_info_fmi, last_assigned_inum,
			path, file_names, dir_names, LOGICALFS_LOAD_FILES_ONLY)) {
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
* Find the inum corresponding to the given dir path
*
* @param logical_fs_info The logical file system
* @param base_path  Will be loaded with path corresponding to the inum
* @param dir_path   Size of base_path
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
	size_t base_len = TSTRLEN(base_path) + 1;
	size_t len = base_len + dir_path.length();
	TSK_TCHAR *path_buf = (TSK_TCHAR*)tsk_malloc(sizeof(TSK_TCHAR) *(len + 2));
	TSTRNCPY(path_buf, base_path, base_len);
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
	TSK_TCHAR* sibling_name = NULL;
	TSK_INUM_T sibling_inum = LOGICAL_INVALID_INUM;

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

		// If the starting path is the parent of our target, check if there's an entry in the cache for another
		// folder directly under the parent that comes before our target. This will primarily speed up opening large directories
		// since each folder is looked up in order.
		// Ex:
		//   Target dir:  /a/b/50
		//   Best match:  /a/b
		//   Check if we have something like /a/b/40 in the cache (we can't use anything deeper like /a/b/40/1 - has to be at the same level)
		const TSK_TCHAR* rest = get_end_of_path(path_buf, starting_path);
		bool haveParentFolder = !contains_folder_separator(rest);
		if (haveParentFolder) {
			find_closest_sibling_match_in_cache(logical_fs_info, path_buf, starting_path, starting_inum, &sibling_name, &sibling_inum);
		}
	}

	// Create the struct that holds search params and results
	LOGICALFS_SEARCH_HELPER *search_helper = create_path_search_helper(path_buf);
	free(path_buf);
	if (search_helper == NULL) {
		free(cache_path);
		cache_path = NULL;
		free(sibling_name);
		sibling_name = NULL;
		return LOGICAL_INVALID_INUM;
	}

	// Run the search
	result = search_directory_recursive(logical_fs_info, starting_path, &starting_inum, sibling_name, sibling_inum, search_helper);

	// Free resources now that the search is complete
	free(cache_path);
	cache_path = NULL;
	free(sibling_name);
	sibling_name = NULL;

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
logicalfs_dir_open_meta(TSK_FS_INFO *a_fs, TSK_FS_DIR ** a_fs_dir,
	TSK_INUM_T a_addr, int recursion_depth)
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
	// We need to decrease the chance of this missing the cache or it can be expensive
	TSK_TCHAR* path = load_path_from_inum(logical_fs_info, a_addr);
	if (path == NULL) {
		return TSK_ERR;
	}

#ifdef TSK_WIN32

	WIN32_FIND_DATAW fd;
	HANDLE hFind = ::FindFirstFileW(path, &fd);
	if (hFind == INVALID_HANDLE_VALUE) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_FS_GENFS);
		tsk_error_set_errstr("logicalfs_dir_open_meta: Error loading directory %" PRIttocTSK, path);
		free(path);
		return TSK_ERR;
	}

	if ((fs_dir->fs_file = tsk_fs_file_alloc(a_fs)) == NULL) {
		free(path);
		::FindClose(hFind);
		return TSK_ERR;
	}

	if ((fs_dir->fs_file->meta = tsk_fs_meta_alloc(0)) == NULL) {
		free(path);
		::FindClose(hFind);
		return TSK_ERR;
	}

	TSK_RETVAL_ENUM result = populate_fs_file_from_win_find_data(&fd, fs_dir->fs_file);
	::FindClose(hFind);

	if (result != TSK_OK) {
		// Error message already set
		free(path);
		return TSK_ERR;
	}

#endif

#ifdef TSK_WIN32
	vector<wstring> file_names;
	vector<wstring> dir_names;
	// LOAD_ALL: caching doesn't apply yet (cache only stores file names, not dir names),
	// so pass NULL/LOGICAL_INVALID_INUM to bypass the cache path. Future work could extend
	// the cache to also store dir names, which would let this call benefit too.
	IMG_LOGICAL_INFO* img_info_lfp = (IMG_LOGICAL_INFO*)a_fs->img_info;
	if (TSK_OK != load_dir_and_file_lists_win(img_info_lfp, a_addr,
			path, file_names, dir_names, LOGICALFS_LOAD_ALL)) {
		// Error message already set
		free(path);
		return TSK_ERR;
	}
#else
	vector<string> file_names;
	vector<string> dir_names;
#endif

	// Add the folders
	// CR: This is an area of concern regarding performance
	for (auto it = begin(dir_names); it != end(dir_names); ++it) {
		TSK_INUM_T dir_inum = get_inum_from_directory_path(logical_fs_info, path, *it);
		if (dir_inum == LOGICAL_INVALID_INUM) {
			tsk_error_reset();
			tsk_error_set_errno(TSK_ERR_FS_GENFS);
			tsk_error_set_errstr("logicalfs_dir_open_meta: Error looking up inum from path");
			free(path);
			return TSK_ERR;
		}

		TSK_FS_NAME *fs_name;

#ifdef TSK_WIN32
		char *utf8Name = convert_wide_string_to_utf8(it->c_str());
		if (utf8Name == NULL) {
			tsk_error_reset();
			tsk_error_set_errno(TSK_ERR_FS_UNICODE);
			tsk_error_set_errstr("logicalfs_dir_open_meta: Error converting wide string");
			free(path);
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

	// TEMP: cumulative timing for the suspect hot-path phases. Remove this block
	// (and the QueryPerformanceCounter calls scattered below) when measurement
	// is done. Search for "TEMP rb" to find every related insertion.
#ifdef TSK_WIN32
	static LARGE_INTEGER rb_freq = {0};
	if (rb_freq.QuadPart == 0) {
		QueryPerformanceFrequency(&rb_freq);
	}
	static long long rb_total_func_us = 0;
	static long long rb_total_blockcache_us = 0;
	static long long rb_total_loadpath_us = 0;
	static long long rb_total_createfile_us = 0;
	static long long rb_total_seek_us = 0;
	static long long rb_total_read_us = 0;
	static long rb_call_count = 0;
	static long rb_block_cache_hits = 0;
	static long rb_handle_cache_hits = 0;
	static long rb_handle_cache_misses = 0;
	static long rb_seeks_performed = 0;
	LARGE_INTEGER rb_t_func_start, rb_t_blockcache_end, rb_t_loadpath_start, rb_t_loadpath_end;
	LARGE_INTEGER rb_t_createfile_start, rb_t_createfile_end;
	LARGE_INTEGER rb_t_seek_start, rb_t_seek_end, rb_t_read_start, rb_t_read_end;
	LARGE_INTEGER rb_t_func_end;
	QueryPerformanceCounter(&rb_t_func_start);
#endif

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
	TSK_IMG_INFO* img_info = a_fs->img_info;
	LOGICALFS_INFO *logical_fs_info = (LOGICALFS_INFO*)a_fs;
	tsk_take_lock(&(img_info->cache_lock));

	// Check if this block is in the cache
	int cache_next = 0;         // index to lowest age cache (to use next)
	bool match_found = 0;
	for (int cache_index = 0; cache_index < TSK_IMG_INFO_CACHE_NUM; cache_index++) {

		// Look into the in-use cache entries
		if (img_info->cache_len[cache_index] > 0) {
			if ((logical_img_info->cache_inum[cache_index] == a_fs_file->meta->addr)
				// check if non-negative and cast to uint to avoid signed/unsigned comparison warning
				&& (img_info->cache_off[cache_index] >= 0 && (TSK_DADDR_T)img_info->cache_off[cache_index] == a_block_num)) {
				// We found it
				memcpy(buf, img_info->cache[cache_index], block_size);
				match_found = true;

				// reset its "age" since it was useful
				img_info->cache_age[cache_index] = LOGICAL_IMG_CACHE_AGE;

				// we don't break out of the loop so that we update all ages
			}
			else {
				// Decrease its "age" since it was not useful.
				// We don't let used ones go below 1 so that they are not
				// confused with entries that have never been used.
				if (img_info->cache_age[cache_index] > 2) {
					img_info->cache_age[cache_index]--;
				}

				// See if this is the most eligible replacement
				if ((img_info->cache_len[cache_next] > 0)
					&& (img_info->cache_age[cache_index] <
						img_info->cache_age[cache_next])) {
					cache_next = cache_index;
				}
			}
		}
	}

#ifdef TSK_WIN32
	QueryPerformanceCounter(&rb_t_blockcache_end);   // TEMP rb
	rb_total_blockcache_us +=
		((rb_t_blockcache_end.QuadPart - rb_t_func_start.QuadPart) * 1000000) / rb_freq.QuadPart;
#endif

	// If we found the block in the cache, we're done
	if (match_found) {
#ifdef TSK_WIN32
		// TEMP rb: count block-cache hits but don't print here - main summary covers it
		rb_block_cache_hits++;
		rb_call_count++;
		QueryPerformanceCounter(&rb_t_func_end);
		rb_total_func_us +=
			((rb_t_func_end.QuadPart - rb_t_func_start.QuadPart) * 1000000) / rb_freq.QuadPart;
#endif
		tsk_release_lock(&(img_info->cache_lock));
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
#ifdef TSK_WIN32
	if (file_handle_entry != NULL) {
		rb_handle_cache_hits++;   // TEMP rb
	}
#endif

	// If we didn't find it, open the file and save to the cache
	if (file_handle_entry == NULL) {
#ifdef TSK_WIN32
		rb_handle_cache_misses++;   // TEMP rb
		QueryPerformanceCounter(&rb_t_loadpath_start);   // TEMP rb
#endif
		// Load the path
		TSK_TCHAR* path = load_path_from_inum(logical_fs_info, a_fs_file->meta->addr);
		if (path == NULL) {
			tsk_release_lock(&(img_info->cache_lock));
			tsk_error_reset();
			tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
			tsk_error_set_errstr("logicalfs_read_block: Failed to resolve path for inum %" PRIuINUM, a_fs_file->meta->addr);
			return TSK_ERR;
		}

#ifdef TSK_WIN32
		QueryPerformanceCounter(&rb_t_loadpath_end);   // TEMP rb
		rb_total_loadpath_us +=
			((rb_t_loadpath_end.QuadPart - rb_t_loadpath_start.QuadPart) * 1000000) / rb_freq.QuadPart;

		// Open the file. path is built from base_path which is always \\?\-prefixed.
		QueryPerformanceCounter(&rb_t_createfile_start);   // TEMP rb
		HANDLE fd = CreateFileW(path, FILE_READ_DATA,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0,
			NULL);
		QueryPerformanceCounter(&rb_t_createfile_end);   // TEMP rb
		rb_total_createfile_us +=
			((rb_t_createfile_end.QuadPart - rb_t_createfile_start.QuadPart) * 1000000) / rb_freq.QuadPart;
		if (fd == INVALID_HANDLE_VALUE) {
			tsk_release_lock(&(img_info->cache_lock));
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
		rb_seeks_performed++;   // TEMP rb
		QueryPerformanceCounter(&rb_t_seek_start);   // TEMP rb
		LARGE_INTEGER li;
		li.QuadPart = a_block_num * block_size;

		li.LowPart = SetFilePointer(file_handle_entry->fd, li.LowPart,
			&li.HighPart, FILE_BEGIN);
		QueryPerformanceCounter(&rb_t_seek_end);   // TEMP rb
		rb_total_seek_us +=
			((rb_t_seek_end.QuadPart - rb_t_seek_start.QuadPart) * 1000000) / rb_freq.QuadPart;

		if ((li.LowPart == INVALID_SET_FILE_POINTER) &&
			(GetLastError() != NO_ERROR)) {

			tsk_release_lock(&(img_info->cache_lock));
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
	QueryPerformanceCounter(&rb_t_read_start);   // TEMP rb
	if (FALSE == ReadFile(file_handle_entry->fd, buf, (DWORD)len_to_read, &nread, NULL)) {
		tsk_release_lock(&(img_info->cache_lock));
		int lastError = GetLastError();
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_IMG_READ);
		tsk_error_set_errstr("logicalfs_read_block: file addr %" PRIuINUM
			" offset: %" PRIu64 " read len: %" PRIuSIZE " - %d",
			a_fs_file->meta->addr, a_block_num, (size_t)block_size,
			lastError);
		return -1;
	}
	QueryPerformanceCounter(&rb_t_read_end);   // TEMP rb
	rb_total_read_us +=
		((rb_t_read_end.QuadPart - rb_t_read_start.QuadPart) * 1000000) / rb_freq.QuadPart;
	file_handle_entry->seek_pos += nread;
#else
	// otherwise, not used; ensure used to prevent warning
	(void)len_to_read;
#endif

	// Copy the block into the cache
	memcpy(img_info->cache[cache_next], buf, block_size);
	img_info->cache_len[cache_next] = block_size;
	img_info->cache_age[cache_next] = LOGICAL_IMG_CACHE_AGE;
	img_info->cache_off[cache_next] = a_block_num;
	logical_img_info->cache_inum[cache_next] = a_fs_file->meta->addr;

	tsk_release_lock(&(img_info->cache_lock));

#ifdef TSK_WIN32
	// TEMP rb: final accounting + periodic summary
	rb_call_count++;
	QueryPerformanceCounter(&rb_t_func_end);
	rb_total_func_us +=
		((rb_t_func_end.QuadPart - rb_t_func_start.QuadPart) * 1000000) / rb_freq.QuadPart;
	if (rb_call_count % 1000 == 0) {
		tsk_fprintf(stderr,
			"[read_block timing] calls=%ld total_func_us=%lld avg_us=%.2f | "
			"block_cache hits=%ld | handle_cache hits=%ld misses=%ld | seeks=%ld\n"
			"  phases: blockcache=%lld load_path=%lld create_file=%lld seek=%lld read=%lld\n",
			rb_call_count, rb_total_func_us,
			(double)rb_total_func_us / (double)rb_call_count,
			rb_block_cache_hits, rb_handle_cache_hits, rb_handle_cache_misses, rb_seeks_performed,
			rb_total_blockcache_us, rb_total_loadpath_us, rb_total_createfile_us,
			rb_total_seek_us, rb_total_read_us);
		fflush(stderr);
	}
#endif

	// If we didn't read the expected number of bytes, return an error
#ifdef TSK_WIN32
	if (nread != len_to_read) {
		int lastError = GetLastError();
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_IMG_READ);
		tsk_error_set_errstr("logicalfs_read_block: file addr %" PRIuINUM
			" offset: %" PRIdOFF " read len: %" PRIuSIZE " - %d",
			a_fs_file->meta->addr, a_block_num, (size_t)block_size,
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
		bytes_left = (size_t)(a_fs_file->meta->size - a_offset);
		filler_len = (size_t)(a_offset + a_len - a_fs_file->meta->size);

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
logicalfs_istat(TSK_FS_INFO *fs, TSK_FS_ISTAT_FLAG_ENUM flags, FILE * hFile, TSK_INUM_T inum,
	TSK_DADDR_T numblock, int32_t sec_skew)
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
	// TODO: Logical folder sets from Windows (e.g. KAPE) are always case-insensitive regardless of
	// what OS the collector is running on. The non-Windows path delegates to tsk_fs_unix_name_cmp
	// which is a case-sensitive strcmp, meaning path lookups will fail for mixed-case paths when
	// the collector is built on Linux/Mac.
	return tsk_fs_unix_name_cmp(a_fs_info, s1, s2);
#endif
}

/*
 * Probe the host filesystem for a path inside a logical FS image. See header for
 * docs. Used by tsk_fs_path2inum's logical-FS fast path to short-circuit lookups
 * for paths that don't exist on disk and to dispatch file vs. directory resolution.
 *
 * Implementation notes:
 *   - Only valid for Windows logical FS — returns NOT_FOUND for any other case
 *   - Converts UTF-8 a_path to UTF-16 via tsk_UTF8toUTF16 (TSK's portable converter,
 *     same family as the inverse-direction tsk_UTF16toUTF8_lclorder used elsewhere
 *     in this file)
 *   - Replaces '/' with '\\' (required for the \\?\ long-path namespace)
 *   - Joins with base_path (which is always \\?\-prefixed) — no further conversion needed
 */
TSK_LOGICAL_PATH_TYPE
tsk_logical_fs_check_path(TSK_FS_INFO *a_fs, const TSK_TCHAR *a_path_wide) {
	if (a_fs == NULL || a_path_wide == NULL || a_fs->ftype != TSK_FS_TYPE_LOGICAL) {
		return TSK_LOGICAL_PATH_NOT_FOUND;
	}

	// Paths must start with '\'. Empty strings and paths without a leading '\'
	// are rejected. Pass "\" to look up the root.
	if (a_path_wide[0] != L'\\') {
		return TSK_LOGICAL_PATH_NOT_FOUND;
	}

#ifdef TSK_WIN32
	LOGICALFS_INFO* logical_fs_info = (LOGICALFS_INFO*)a_fs;

	// Build full host path: base_path + a_path_wide.
	// base_path is always \\?\-prefixed so the result is long-path safe without
	// any further conversion. full_path always starts with '\' so no separator
	// injection is needed. Root case ("\") produces "base_path\" which
	// GetFileAttributesW handles correctly.
	std::wstring full_path = logical_fs_info->base_path;
	full_path += a_path_wide;

	DWORD attribs = GetFileAttributesW(full_path.c_str());
	if (attribs == INVALID_FILE_ATTRIBUTES) {
		return TSK_LOGICAL_PATH_NOT_FOUND;
	}
	if (attribs & FILE_ATTRIBUTE_DIRECTORY) {
		return TSK_LOGICAL_PATH_DIRECTORY;
	}
	return TSK_LOGICAL_PATH_FILE;
#else
	return TSK_LOGICAL_PATH_NOT_FOUND;
#endif
}

/*
 * Logical-FS path → inum resolver. Caller is expected to have already probed
 * the path with tsk_logical_fs_check_path and pass the result via path_type so
 * the existence-check syscall isn't repeated.
 *
 * Resolution strategy:
 *   - DIRECTORY paths: forward to get_inum_from_directory_path (cache-aware
 *     SEARCH_BY_PATH walk; returns the directory's inum)
 *   - FILE paths: split off the trailing filename, resolve the parent directory
 *     via get_inum_from_directory_path, then enumerate the parent and find the
 *     filename's index in the sorted list. The file inum is parent_inum | (idx + 1)
 *     because that's the same encoding logicalfs_dir_open_meta would assign.
 *
 * @returns -1 on (system) error, 0 if found, and 1 if not found.
 */
int8_t
tsk_logical_fs_path2inum(TSK_FS_INFO *a_fs, const TSK_TCHAR *a_path_wide,
    TSK_LOGICAL_PATH_TYPE path_type, TSK_INUM_T *a_result) {

	if (a_fs == NULL || a_path_wide == NULL || a_result == NULL) {
		return -1;
	}
	if (a_fs->ftype != TSK_FS_TYPE_LOGICAL) {
		return -1;
	}
	if (path_type == TSK_LOGICAL_PATH_NOT_FOUND) {
		return 1;
	}

#ifdef TSK_WIN32
	LOGICALFS_INFO *logical_fs_info = (LOGICALFS_INFO*)a_fs;

	// Root path: empty, or a single backslash - return root_inum directly.
	// (get_inum_from_directory_path doesn't handle the empty-relative-path case.)
	if (a_path_wide[0] == L'\0' ||
		(a_path_wide[0] == L'\\' && a_path_wide[1] == L'\0')) {
		*a_result = a_fs->root_inum;
		return 0;
	}

	// Strip the leading '\'. get_inum_from_directory_path joins base_path + "\" + dir_path,
	// so dir_path must not carry its own leading separator.
	std::wstring relative_path = a_path_wide + 1;

	// ── Directory path: one-shot resolution via the existing wrapper ──
	if (path_type == TSK_LOGICAL_PATH_DIRECTORY) {
		TSK_INUM_T inum = get_inum_from_directory_path(logical_fs_info,
			logical_fs_info->base_path, relative_path);
		if (inum == LOGICAL_INVALID_INUM) {
			return 1;
		}
		*a_result = inum;
		return 0;
	}

	// ── File path: split, resolve parent, look up filename in parent's file list ──
	size_t last_slash = relative_path.find_last_of(L'\\');
	std::wstring parent_relative;
	std::wstring filename;
	if (last_slash == std::wstring::npos) {
		// File lives directly under root (e.g. "/foo")
		parent_relative.clear();
		filename = relative_path;
	} else {
		parent_relative = relative_path.substr(0, last_slash);
		filename = relative_path.substr(last_slash + 1);
	}

	// Resolve parent dir → inum. Empty parent_relative means file is in root.
	TSK_INUM_T parent_inum;
	if (parent_relative.empty()) {
		parent_inum = a_fs->root_inum;
	} else {
		parent_inum = get_inum_from_directory_path(logical_fs_info, logical_fs_info->base_path, parent_relative);
		if (parent_inum == LOGICAL_INVALID_INUM) {
			return 1;
		}
	}

	// Build the full host path to the parent dir for load_dir_and_file_lists_win.
	std::wstring parent_full_path = logical_fs_info->base_path;
	if (!parent_relative.empty()) {
		parent_full_path += L'\\';
		parent_full_path += parent_relative;
	}

	// Enumerate parent's files (just files - we don't need the dir list).
	// Pass logical_img_info + parent_inum so load_dir_and_file_lists_win can use the
	// dir_file_list_cache. This is the hot path for body-file workloads where many
	// files share the same parent directory - without this, every file lookup re-
	// enumerates the parent directory from disk.
	std::vector<std::wstring> file_names;
	std::vector<std::wstring> dir_names_unused;
	IMG_LOGICAL_INFO* img_info_lfp = (IMG_LOGICAL_INFO*)a_fs->img_info;
	if (TSK_OK != load_dir_and_file_lists_win(img_info_lfp, parent_inum,
			parent_full_path.c_str(),
			file_names, dir_names_unused, LOGICALFS_LOAD_FILES_ONLY)) {
		return 1;
	}

	// Find the filename in the sorted list (case-insensitive).
	for (size_t i = 0; i < file_names.size(); i++) {
		if (_wcsicmp(file_names[i].c_str(), filename.c_str()) == 0) {
			// File inum encoding: high 32 bits = parent dir id, low 32 bits = (index + 1).
			// parent_inum already has the dir id in the high bits and zeros in the low.
			*a_result = parent_inum | ((TSK_INUM_T)i + 1);
			return 0;
		}
	}

	// Filename wasn't in the parent's file list. Shouldn't happen if path_type was
	// FILE (since GetFileAttributesW already confirmed the path), but possible if
	// the host filesystem changed between the probe and now.
	return 1;
#else
	return 1;
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
	fs->inode_walk = logicalfs_inode_walk; // NOP
	fs->block_walk = logicalfs_block_walk; // NOP
	fs->block_getflags = logicalfs_block_getflags; // NOP

	fs->get_default_attr_type = logicalfs_get_default_attr_type; // NOP
	fs->load_attrs = logicalfs_load_attrs;

	fs->file_add_meta = logicalfs_file_add_meta;
	fs->dir_open_meta = logicalfs_dir_open_meta;
	fs->fsstat = logicalfs_fsstat;
	fs->fscheck = logicalfs_fscheck; // NOP
	fs->istat = logicalfs_istat; // NOP
	fs->name_cmp = logicalfs_name_cmp;

	fs->close = logicalfs_close;

	// Journal functions - also no-ops.
	fs->jblk_walk = logicalfs_jblk_walk; // NOP
	fs->jentry_walk = logicalfs_jentry_walk; // NOP
	fs->jopen = logicalfs_jopen; // NOP

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
