/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
**
** TASK
v** Copyright (c) 2002-2003 Brian Carrier, @stake Inc.  All rights reserved
**
** Copyright (c) 1997,1998,1999, International Business Machines
** Corporation and others. All Rights Reserved.
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
#include <filesystem>

#include "tsk_fs_i.h"
#include "tsk_logical_fs.h"
#include "tsk_fs.h"
#include "tsk/img/logical_img.h"

#ifdef TSK_WIN32
#include <Windows.h>
#endif

using std::vector;
using std::string;
using std::wstring;

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
	return TSK_FS_ATTR_TYPE_NOT_FOUND;
}

static uint8_t
logicalfs_load_attrs(TSK_FS_FILE *file)
{
	tsk_error_reset();
	tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
	tsk_error_set_errstr("load_attrs for logical directory is not implemented");
	return 1;
}

/*
 * Convert a FILETIME to a timet
 *
 * @param ft The FILETIME to convert
 *
 * @return The converted timet
 */
time_t filetime_to_timet(FILETIME const& ft) 
{ 
	ULARGE_INTEGER ull;    
	ull.LowPart = ft.dwLowDateTime;    
	ull.HighPart = ft.dwHighDateTime;    
	return ull.QuadPart / 10000000ULL - 11644473600ULL; 
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
	helper->target_inum = target_inum;
	helper->found_path[0] = '\0';
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
	printf("Search helper size: %lld\n", sizeof(LOGICALFS_SEARCH_HELPER));
	printf("Search helper path: %ws (%lld)\n", target_path, TSTRLEN(target_path));
	fflush(stdout);
	LOGICALFS_SEARCH_HELPER *helper = (LOGICALFS_SEARCH_HELPER *)tsk_malloc(sizeof(LOGICALFS_SEARCH_HELPER));
	if (helper == NULL)
		return NULL;

	helper->target_found = false;
	helper->search_type = LOGICALFS_SEARCH_BY_PATH;
	TSTRNCPY(helper->target_path, target_path, TSTRLEN(target_path) + 1);
	helper->found_inum = LOGICAL_INVALID_INUM;
	printf("Returning helper\n");
	fflush(stdout);
	return helper;
}

/*
 * Convert a wide string to UTF8.
 * 
 * @param source The wide string to convert.
 * 
 * @return The converted string (must be freed by caller). NULL if conversion fails.
 */
#ifdef TSK_WIN32
static char*
convert_wide_string_to_utf8(const wchar_t *source) {

	UTF16 *utf16 = (UTF16 *)source;

	size_t ilen = wcslen(source);
	size_t maxUTF8len = ilen * 4;
	char *dest = (char*)tsk_malloc(maxUTF8len);
	UTF8 *utf8 = (UTF8*)dest;

	TSKConversionResult retVal =
		tsk_UTF16toUTF8_lclorder((const UTF16 **)&utf16,
			&utf16[ilen], &utf8,
			&utf8[maxUTF8len], TSKlenientConversion);

	if (retVal != TSKconversionOK) {
		return NULL;
	}
	return dest;
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
		return TSK_ERR;
	}
	printf("Loading win find data\n");
	fflush(stdout);
	// Set the timestamps
	a_fs_file->meta->crtime = filetime_to_timet(fd->ftCreationTime);
	a_fs_file->meta->atime = filetime_to_timet(fd->ftLastAccessTime);
	a_fs_file->meta->mtime = filetime_to_timet(fd->ftLastWriteTime);

	printf("Setting mode\n");
	fflush(stdout);
	// Set the type
	if (fd->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
		a_fs_file->meta->type = TSK_FS_META_TYPE_DIR;
	}
	else {
		a_fs_file->meta->type = TSK_FS_META_TYPE_REG;
	}

	// Set the file size
	LARGE_INTEGER ull;
	ull.LowPart = fd->nFileSizeLow;
	ull.HighPart = fd->nFileSizeHigh;
	a_fs_file->meta->size = ull.QuadPart;

	printf("Preparing to set name\n");
	fflush(stdout);
	/*
	// Set the name
	if ((a_fs_file->meta->name2 = (TSK_FS_META_NAME_LIST *) tsk_malloc(sizeof(TSK_FS_META_NAME_LIST))) == NULL) {
		return TSK_ERR;
	}
	printf("Allocated name2")
	a_fs_file->meta->name2->next = NULL;
	char *utf8Name = convert_wide_string_to_utf8(fd->cFileName);
	if (utf8Name != NULL) {
		strncpy(a_fs_file->meta->name2->name, utf8Name, TSK_FS_META_NAME_LIST_NSIZE);
		free(utf8Name);
	}
	else {
		a_fs_file->meta->name2->name[0] = '\0';
	}*/
	printf("Done with win data load\n");
	fflush(stdout);

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
	searchPath = (TSK_TCHAR *)tsk_malloc(sizeof(TSK_TCHAR) * (len + 4));
	if (searchPath == NULL) {
		return NULL;
	}
	TSTRNCPY(searchPath, base_path, len + 1);
	TSTRNCAT(searchPath, L"/*", 3);
	return searchPath;
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
static TSK_RETVAL_ENUM
load_dir_and_file_lists_win(const TSK_TCHAR *base_path, vector<wstring>& file_names, vector<wstring>& dir_names, LOGICALFS_DIR_LOADING_MODE mode) {

	WIN32_FIND_DATA fd;
	HANDLE hFind;

	// Create the search string (base path + "/*")
	TSK_TCHAR * search_path_wildcard = create_search_path(base_path);
	if (search_path_wildcard == NULL) {
		return TSK_ERR;
	}

	// Look up all files and folders in the base directory 
	hFind = ::FindFirstFile(search_path_wildcard, &fd);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
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
		} while (::FindNextFile(hFind, &fd));
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
search_directory_recusive(const TSK_TCHAR * parent_path, TSK_INUM_T *last_inum_ptr, LOGICALFS_SEARCH_HELPER* search_helper) {

#ifdef TSK_WIN32
	vector<wstring> file_names;
	vector<wstring> dir_names;
#else
	vector<string> file_names;
	vector<string> dir_names;
#endif

	//if (search_helper->search_type == )

#ifdef TSK_WIN32
	if (TSK_OK != load_dir_and_file_lists_win(parent_path, file_names, dir_names, LOGICALFS_LOAD_DIRS_ONLY)) {
		// Error message already set
		return TSK_ERR;
	}
#endif

	
	// Sort the directory names
	sort(dir_names.begin(), dir_names.end());
		
	// Set up the beginning of full path to the file on disk
	TSK_TCHAR current_path[MAX_LOGICAL_NAME_LEN + 1];
	TSTRNCPY(current_path, parent_path, TSTRLEN(parent_path) + 1);
	TSTRNCAT(current_path, L"/", 2);
	size_t parent_path_len = TSTRLEN(current_path);
	size_t path_len_left = MAX_LOGICAL_NAME_LEN - parent_path_len;

	for (int i = 0; i < dir_names.size();i++) {
		// Append the current directory name to the parent path
		TSTRNCPY(current_path + parent_path_len, dir_names[i].c_str(), TSTRLEN(dir_names[i].c_str()) + 1);
		if (LOGICAL_DEBUG_PRINT) printf( "Assigning 0x%llx to dir %ws\n", (*last_inum_ptr) + 1, current_path);
		TSK_INUM_T current_inum = *last_inum_ptr + LOGICAL_INUM_DIR_INC;
		*last_inum_ptr = current_inum;

		// Check if we've found it
		if ((search_helper->search_type == LOGICALFS_SEARCH_BY_PATH)
#ifdef TSK_WIN32
			&& (wcsncmp(current_path, search_helper->target_path, MAX_LOGICAL_NAME_LEN) == 0)) {
#else
			&& (strncmp(current_path, search_helper->target_path, MAX_LOGICAL_NAME_LEN) == 0)) {
#endif
			search_helper->target_found = true;
			search_helper->found_inum = current_inum;
			return TSK_OK;
		}
		printf("Comparing inum %llx with target %llx\n", current_inum, search_helper->target_inum);
		if ((search_helper->search_type == LOGICALFS_SEARCH_BY_INUM)
			&& (current_inum == (search_helper->target_inum & 0xffff0000))) {

			// If we were looking for a directory, we're done
			if (current_inum == search_helper->target_inum) {
				search_helper->target_found = true;
				printf("### Copying %zd characters into search_helper->found_path (%ws)\n", TSTRLEN(current_path), current_path);
				TSTRNCPY(search_helper->found_path, current_path, TSTRLEN(current_path) + 1);
				return TSK_OK;
			}
			printf("Looking for file\n");
			// Otherwise the file we're looking for should be in this folder. Load the files now.
			// Using the LOGICALFS_LOAD_FILES_ONLY mode will prevent dir_names from being altered.
			if (TSK_OK != load_dir_and_file_lists_win(current_path, file_names, dir_names, LOGICALFS_LOAD_FILES_ONLY)) {
				// Error message already set
				return TSK_ERR;
			}
			printf("Found %zd files\n", file_names.size());
			sort(file_names.begin(), file_names.end());

			// Look for the file corresponding to the given inum
			size_t file_index = search_helper->target_inum & 0xffff - 1;
			if (file_names.size() <= file_index) {
				tsk_error_reset();
				tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
				tsk_error_set_errstr("search_directory_recusive - inum not found"); // TODO
				return TSK_ERR;
			}
			search_helper->target_found = true;
			TSTRNCPY(search_helper->found_path, current_path, TSTRLEN(current_path) + 1);
			TSTRNCAT(search_helper->found_path, L"/", 2);
			TSTRNCAT(search_helper->found_path, file_names[file_index].c_str(), TSTRLEN(file_names[file_index].c_str()) + 1);
			return TSK_OK;
		}

		TSK_RETVAL_ENUM result = search_directory_recusive(current_path, last_inum_ptr, search_helper);
		if (result != TSK_OK) {
			return result;
		}
		if (search_helper->target_found) {
			return TSK_OK;
		}
	}
	return TSK_OK;
}

/*
 * Find the path corresponding to the given inum
 *
 * @param logical_fs_info The logical file system
 * @param a_addr          The inum to search for
 * @param base_path       Will be loaded with path corresponding to the inum
 * @param base_path_len   Size of base_path
 *
 * @return TSK_OK if successful, TSK_ERR otherwise 
 */
static TSK_RETVAL_ENUM
load_base_path(LOGICALFS_INFO *logical_fs_info, TSK_INUM_T a_addr, TSK_TCHAR *base_path, size_t base_path_len) {
	if (a_addr == logical_fs_info->fs_info.root_inum) {
		// No need to do a search - it's just the root folder
		TSTRNCPY(base_path, logical_fs_info->base_path, TSTRLEN(logical_fs_info->base_path) + 1);
		return TSK_OK;
	}

	// Create the struct that holds search params and results
	LOGICALFS_SEARCH_HELPER *search_helper = create_inum_search_helper(a_addr);
	if (search_helper == NULL) {
		return TSK_ERR;
	}

	// Run the search
	TSK_INUM_T last_assigned_inum = logical_fs_info->fs_info.root_inum;
	TSK_RETVAL_ENUM result = search_directory_recusive(logical_fs_info->base_path, &last_assigned_inum, search_helper);

	if ((result != TSK_OK) || (!search_helper->target_found)) {
		printf("### Bailing out of load_base_path???\n");
		free(search_helper);
		return TSK_ERR;
	}

	// Copy the path
	TSTRNCPY(base_path, search_helper->found_path, TSTRLEN(search_helper->found_path) + 1);
	free(search_helper);
	return TSK_OK;
}


static uint8_t
logicalfs_file_add_meta(TSK_FS_INFO *a_fs, TSK_FS_FILE * a_fs_file,
	TSK_INUM_T inum)
{
	LOGICALFS_INFO *logical_fs_info = (LOGICALFS_INFO*)a_fs;
	printf("file_add_meta for %llx\n", inum);
	
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
	
	// Get the full path to the given file
	printf("Loading path for inum\n");
	fflush(stdout);
	TSK_TCHAR base_path[MAX_LOGICAL_NAME_LEN + 1];
	TSK_RETVAL_ENUM result = load_base_path(logical_fs_info, inum, base_path, MAX_LOGICAL_NAME_LEN);
	if (result != TSK_OK) {
		printf("Not ok\n");
		fflush(stdout);
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
		tsk_error_set_errstr("logicalfs_file_add_meta - Error loading directory %" PRIttocTSK, base_path);
		return TSK_ERR;
	}

#ifdef TSK_WIN32
	// Load the file
	printf("Loading file\n");
	fflush(stdout);
	WIN32_FIND_DATA fd;
	HANDLE hFind = ::FindFirstFile(base_path, &fd);
	if (hFind != INVALID_HANDLE_VALUE) {

		TSK_RETVAL_ENUM result = populate_fs_file_from_win_find_data(&fd, a_fs_file);
		::FindClose(hFind);
		printf("Ready to return\n");
		fflush(stdout);
		return result;
	}
	else {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_FS_GENFS);
		tsk_error_set_errstr("logicalfs_dir_open_meta: Error loading directory %" PRIttocTSK, base_path);
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
	printf("### Loading max inum ###\n");
	fflush(stdout);
	// Create the struct that holds search params and results
	LOGICALFS_SEARCH_HELPER *search_helper = create_max_inum_search_helper();
	if (search_helper == NULL) {
		return LOGICAL_INVALID_INUM;
	}

	// Run the search to get the maximum directory inum
	TSK_INUM_T last_assigned_inum = logical_fs_info->fs_info.root_inum;
	TSK_RETVAL_ENUM result = search_directory_recusive(logical_fs_info->base_path, &last_assigned_inum, search_helper);
	free(search_helper);

	if (result != TSK_OK) {
		printf("### Max inum - search_directory_recursive failed\n");
		fflush(stdout);
		return LOGICAL_INVALID_INUM;
	}

	// The maximum inum will be the inum of the last file in that folder. We don't care which file it is, 
	// so just getting a count is sufficient. First we need the path on disk corresponding to the last
	// directory inum.
	TSK_TCHAR base_path[MAX_LOGICAL_NAME_LEN + 1];
	result = load_base_path(logical_fs_info, last_assigned_inum, base_path, MAX_LOGICAL_NAME_LEN);
	if (result != TSK_OK) {
		printf("### Max inum - failed to look up path for inum %llx\n", last_assigned_inum);
		fflush(stdout);
		return LOGICAL_INVALID_INUM;
	}

	printf("### base_path: ");
	for (int i = 0; i < 20; i++) {
		if (isascii(base_path[i] & 0xff)) {
			printf("%c ", base_path[i] & 0xff);
		}
		else {
			printf("%x ", base_path[i]);
		}
	}
	printf("\n");

	// Finally we need to get a count of files in that last folder. The max inum is the 
	// folder inum plus the number of files (if none, it'll just be the folder inum).
#ifdef TSK_WIN32
	vector<wstring> file_names;
	vector<wstring> dir_names;
	if (TSK_OK != load_dir_and_file_lists_win(base_path, file_names, dir_names, LOGICALFS_LOAD_FILES_ONLY)) {
		printf("### Max inum - loading files for path %ws failed\n", base_path);
		fflush(stdout);
		return LOGICAL_INVALID_INUM;
	}
#else
	vector<string> file_names;
	vector<string> dir_names;
#endif
	last_assigned_inum += file_names.size();
	printf("### Last inum: 0x%llx\n", last_assigned_inum);
	fflush(stdout);
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
get_inum_from_directory_path(LOGICALFS_INFO *logical_fs_info, TSK_TCHAR *base_path, wstring& dir_path) {

	// Get the full path on disk by combining the base path for the logical image with the relative path in dir_path
	printf("Making path\n");
	fflush(stdout);
	size_t len = TSTRLEN(base_path) + dir_path.length() + 1;
	TSK_TCHAR *path_buf = (TSK_TCHAR*)tsk_malloc(sizeof(TSK_TCHAR) *(len + 2));
	TSTRNCPY(path_buf, base_path, TSTRLEN(base_path) + 1);
	TSTRNCAT(path_buf, L"/", 2);
	TSTRNCAT(path_buf, dir_path.c_str(), TSTRLEN(dir_path.c_str()) + 1);

	// Create the struct that holds search params and results
	printf("Making search helper\n");
	fflush(stdout);
	LOGICALFS_SEARCH_HELPER *search_helper = create_path_search_helper(path_buf);
	free(path_buf);
	if (search_helper == NULL) {
		return LOGICAL_INVALID_INUM;
	}

	// Run the search
	printf("Running search\n");
	fflush(stdout);
	TSK_INUM_T last_assigned_inum = logical_fs_info->fs_info.root_inum;
	TSK_RETVAL_ENUM result = search_directory_recusive(logical_fs_info->base_path, &last_assigned_inum, search_helper);

	// Return the target inum if found
	TSK_INUM_T target_inum;
	if ((result != TSK_OK) || (!search_helper->target_found)) {
		target_inum = LOGICAL_INVALID_INUM;
	}
	else {
		target_inum = search_helper->found_inum;
	}
	free(search_helper);
	printf("Returning from get_inum_from_directory_path\n");
	fflush(stdout);
	return target_inum;
}

static TSK_RETVAL_ENUM
logicalfs_dir_open_meta(TSK_FS_INFO *a_fs, TSK_FS_DIR ** a_fs_dir,
	TSK_INUM_T a_addr, int recursion_depth)
{
	TSK_FS_DIR *fs_dir;
	LOGICALFS_INFO *logical_fs_info = (LOGICALFS_INFO*)a_fs;
	

	if (LOGICAL_DEBUG_PRINT) printf("logicalfs_dir_open_meta - addr: 0x%llx, recursion depth: %d\n", a_addr, recursion_depth);

	if (recursion_depth != 1) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
		tsk_error_set_errstr("logicalfs_dir_open_meta: Recursion is not currently supported"
			PRIuINUM, a_addr);
		return TSK_ERR;
	}
	else if (a_fs_dir == NULL) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_FS_ARG);
		tsk_error_set_errstr("logicalfs_dir_open_meta: NULL fs_dir argument given");
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
	TSK_TCHAR base_path[MAX_LOGICAL_NAME_LEN + 1];
	load_base_path(logical_fs_info, a_addr, base_path, MAX_LOGICAL_NAME_LEN);

#ifdef TSK_WIN32
	// Look up the base folder and populate the fs_file field
	WIN32_FIND_DATA fd;
	HANDLE hFind = ::FindFirstFile(base_path, &fd);
	if (hFind != INVALID_HANDLE_VALUE) {
		if ((fs_dir->fs_file = tsk_fs_file_alloc(a_fs)) == NULL)
			return TSK_ERR;

		if ((fs_dir->fs_file->meta = tsk_fs_meta_alloc(0)) == NULL)
			return TSK_ERR;
		TSK_RETVAL_ENUM result = populate_fs_file_from_win_find_data(&fd, fs_dir->fs_file);
		::FindClose(hFind);
		if (result != TSK_OK) {
			tsk_error_reset();
			tsk_error_set_errno(TSK_ERR_FS_GENFS);
			tsk_error_set_errstr("logicalfs_dir_open_meta: Error loading directory %" PRIttocTSK, base_path);
			return TSK_ERR;
		}
		
	}
	else {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_FS_GENFS);
		tsk_error_set_errstr("logicalfs_dir_open_meta: Error loading directory %" PRIttocTSK, base_path);
		return TSK_ERR;
	}
#endif

	printf("Loading dirs\n");
	fflush(stdout);
#ifdef TSK_WIN32
	vector<wstring> file_names;
	vector<wstring> dir_names;
	if (TSK_OK != load_dir_and_file_lists_win(base_path, file_names, dir_names, LOGICALFS_LOAD_ALL)) {
		// Error message already set
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
	if (LOGICAL_DEBUG_PRINT) printf( "\nlogicalfs_dir_open_meta - adding %lld folders\n", dir_names.size());
	fflush(stdout);
	for (auto it = begin(dir_names); it != end(dir_names); ++it) {
		printf("Getting inum from path\n");
		fflush(stdout);
		TSK_INUM_T dir_inum = get_inum_from_directory_path(logical_fs_info, base_path, *it);
		printf("Got inum\n");
		fflush(stdout);
		TSK_FS_NAME *fs_name;

		printf("Adding folder with inum %llx\n", dir_inum);
		fflush(stdout);
#ifdef TSK_WIN32
		char *utf8Name = convert_wide_string_to_utf8(it->c_str());
		printf("finshed conversion\n");
		fflush(stdout);
#else
		char *utf8Name = *it;
#endif
		size_t name_len = strlen(utf8Name);
		if (LOGICAL_DEBUG_PRINT) printf("strlen name_buf = %zd", name_len);
		fflush(stdout);
		if ((fs_name = tsk_fs_name_alloc(name_len, 0)) == NULL) {
#ifdef TSK_WIN32
			if (utf8Name != NULL) {
				free(utf8Name);
			}
#endif
			return TSK_ERR;
		}

		fs_name->type = TSK_FS_NAME_TYPE_DIR;
		fs_name->par_addr = a_addr;
		fs_name->meta_addr = dir_inum;
		strncpy(fs_name->name, utf8Name, name_len);
#ifdef TSK_WIN32
		if (utf8Name != NULL) {
			free(utf8Name);
		}
#endif
		if (tsk_fs_dir_add(fs_dir, fs_name)) {
			tsk_fs_name_free(fs_name);
			return TSK_ERR;
		}
		tsk_fs_name_free(fs_name);
	}

	// Add the files
	if (LOGICAL_DEBUG_PRINT) printf( "\nlogicalfs_dir_open_meta - adding %lld files\n", file_names.size());
	fflush(stdout);
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
		fs_name->par_addr = a_addr;
		fs_name->meta_addr = file_inum;
		if (LOGICAL_DEBUG_PRINT) printf("Assigning 0x%llx to file %ws\n", file_inum, it->c_str());
#ifdef TSK_WIN32
		strncpy(fs_name->name, utf8Name, name_len);
		free(utf8Name);
#else
		strncpy(fs_name->name, it->c_str(), name_len);
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

TSK_FS_INFO *
logical_fs_open(TSK_IMG_INFO * img_info) {

	LOGICALFS_INFO *logical_fs_info = NULL;
	TSK_FS_INFO *fs = NULL;
	IMG_LOGICAL_INFO *logical_img_info = NULL;

	if (LOGICAL_DEBUG_PRINT) printf( "logical_fs_open\n");
	fflush(stdout);

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
	fs->block_size = 0;
	fs->block_pre_size = 0;
	fs->block_post_size = 0;
	fs->block_count = 0;
	fs->first_block = 0;
	fs->last_block_act = 0;

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
	fs->name_cmp = tsk_fs_unix_name_cmp;

	fs->close = logicalfs_close;

	// Journal functions - also no-ops.
	fs->jblk_walk = logicalfs_jblk_walk;
	fs->jentry_walk = logicalfs_jentry_walk;
	fs->jopen = logicalfs_jopen;

	// Calculate the last inum
	fs->last_inum = find_max_inum(logical_fs_info);

	return fs;
}
