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

using namespace std;

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

static uint8_t
logicalfs_inode_lookup(TSK_FS_INFO *a_fs, TSK_FS_FILE * a_fs_file,
	TSK_INUM_T inum)
{
	tsk_error_reset();
	tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
	tsk_error_set_errstr("inode_lookup not supported for logical file systems");
	return 1;
}

time_t  filetime_to_timet(FILETIME const& ft) 
{ 
	ULARGE_INTEGER ull;    
	ull.LowPart = ft.dwLowDateTime;    
	ull.HighPart = ft.dwHighDateTime;    
	return ull.QuadPart / 10000000ULL - 11644473600ULL; 
}

TSK_FS_FILE*
create_fs_file_from_find_data(const WIN32_FIND_DATA* fd, TSK_FS_INFO *a_fs) {
	TSK_FS_FILE* fs_file;
	TSKConversionResult conv_result = TSKconversionOK;

	printf( "create_fs_file_from_find_data\n");
	fflush(stdout);
	if ((fs_file = tsk_fs_file_alloc(a_fs)) == NULL)
		return NULL;

	if ((fs_file->meta = tsk_fs_meta_alloc(0)) == NULL)
		return NULL;

	printf( "create_fs_file_from_find_data - setting timestamps\n");
	fflush(stdout);
	fs_file->meta->crtime = filetime_to_timet(fd->ftCreationTime);
	fs_file->meta->atime = filetime_to_timet(fd->ftLastAccessTime); 
	fs_file->meta->mtime = filetime_to_timet(fd->ftLastWriteTime);

	if (fd->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
		fs_file->meta->type = TSK_FS_META_TYPE_DIR;
	}
	else {
		fs_file->meta->type = TSK_FS_META_TYPE_REG;
	}

	printf( "create_fs_file_from_find_data - setting file size\n");
	fflush(stdout);
	LARGE_INTEGER ull;
	ull.LowPart = fd->nFileSizeLow;
	ull.HighPart = fd->nFileSizeHigh;
	fs_file->meta->size = ull.QuadPart;

	printf( "create_fs_file_from_find_data - converting file name\n");
	fflush(stdout);
	if ((fs_file->meta->name2 = (TSK_FS_META_NAME_LIST *) tsk_malloc(sizeof(TSK_FS_META_NAME_LIST))) == NULL) {
		return NULL;
	}
	fs_file->meta->name2->next = NULL; // TODO revisit this
	conv_result = tsk_UTF16toUTF8(a_fs->endian,
		(const UTF16**)&fd->cFileName, 
		(const UTF16*)(fd->cFileName + wcslen(fd->cFileName)),
		(UTF8 **)(uintptr_t)&fs_file->meta->name2->name,
		(UTF8 *)((uintptr_t)fs_file->meta->name2->name + sizeof(fs_file->meta->name2->name)), 
		TSKlenientConversion);

	if (conv_result != TSKconversionOK) {
		fs_file->meta->name2->name[0] = '\0';
	}

	return fs_file;
}

TSK_TCHAR * createSearchPath(const TSK_TCHAR *base_path) {
	size_t len = TSTRLEN(base_path);
	TSK_TCHAR * searchPath;
	searchPath = (TSK_TCHAR *)tsk_malloc(sizeof(TSK_TCHAR) * (len + 5)); // TODO reduce
	if (searchPath == NULL) {
		return NULL;
	}
	TSTRNCPY(searchPath, base_path, len + 1);
	TSTRNCAT(searchPath, L"/*", 3);
	return searchPath;
}

// Most basic version - run through every directory from root until we find the right one.
// Returns target inum or invalid if not found yet.
static TSK_INUM_T
get_inum_from_directory_path(LOGICALFS_INFO *logical_fs_info, const TSK_TCHAR * parent_path, 
		TSK_INUM_T *next_inum_ptr, const TSK_TCHAR * target_path) {

#ifdef TSK_WIN32
	WIN32_FIND_DATA fd;
	HANDLE hFind;
	TSK_TCHAR current_path[MAX_LOGICAL_NAME_LEN + 1];

	TSK_TCHAR * searchPath = createSearchPath(parent_path);
	if (searchPath == NULL) {
		return TSK_ERR;
	}
	//vector<TSK_TCHAR *> dir_names;
	std::vector<wstring> dir_names;
	hFind = ::FindFirstFile(searchPath, &fd);
	if (hFind != INVALID_HANDLE_VALUE) {
		//vector<wstring> dir_names;
		do {
			if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				// For the moment at least, skip . and ..
				if (0 != wcsncmp(fd.cFileName, L"..", 3) && 0 != wcsncmp(fd.cFileName, L".", 3)) {
					dir_names.push_back(wstring(fd.cFileName));
				}
			}
		} while (::FindNextFile(hFind, &fd));
		::FindClose(hFind);
		
		sort(dir_names.begin(), dir_names.end());
		
		TSTRNCPY(current_path, parent_path, MAX_LOGICAL_NAME_LEN - 2);
		TSTRNCAT(current_path, L"/", 2);
		size_t parent_path_len = TSTRLEN(current_path);
		size_t path_len_left = MAX_LOGICAL_NAME_LEN - parent_path_len;

		for (int i = 0; i < dir_names.size();i++) {
			TSTRNCPY(current_path + parent_path_len, dir_names[i].c_str(), path_len_left - TSTRLEN(dir_names[i].c_str()));
			printf( "Assigning 0x%llx to %ws\n", *next_inum_ptr, current_path);
			TSK_INUM_T current_inum = *next_inum_ptr;

			// Check if we've found it
			if (wcsncmp(current_path, target_path, MAX_LOGICAL_NAME_LEN) == 0) {
				return current_inum;
			}

			(*next_inum_ptr)++;
			TSK_INUM_T result = get_inum_from_directory_path(logical_fs_info, current_path, next_inum_ptr, target_path);
			if (result != LOGICAL_INVALID_INUM) {
				return result;
			}
		}
	}
	else {
	}
#endif
	return LOGICAL_INVALID_INUM;
}

// Most basic version - run through every directory from root until we find the right one.
static TSK_INUM_T 
get_inum_from_directory_path(LOGICALFS_INFO *logical_fs_info, wstring& dir_path) {
	TSK_TCHAR path_buf[MAX_LOGICAL_NAME_LEN + 1];
	TSTRNCPY(path_buf, logical_fs_info->base_path, MAX_LOGICAL_NAME_LEN);
	TSTRNCAT(path_buf, L"/", 2);
	TSTRNCAT(path_buf, dir_path.c_str(), MAX_LOGICAL_NAME_LEN);
	TSK_INUM_T next_inum = logical_fs_info->fs_info.root_inum + 1;
	TSK_INUM_T dir_inum = get_inum_from_directory_path(logical_fs_info, logical_fs_info->base_path, &next_inum, path_buf);
	if (dir_inum == LOGICAL_INVALID_INUM) {
		printf( "get_inum_from_directory_path: Did not find it\n");
		fflush(stdout);
		return LOGICAL_INVALID_INUM;
	}
	return dir_inum;
}

static TSK_RETVAL_ENUM
logicalfs_dir_open_meta(TSK_FS_INFO *a_fs, TSK_FS_DIR ** a_fs_dir,
	TSK_INUM_T a_addr, int recursion_depth)
{

	TSK_FS_DIR *fs_dir;
	LOGICALFS_INFO *logical_fs_info = (LOGICALFS_INFO*)a_fs;
	char name_buf[MAX_LOGICAL_NAME_LEN + 1];
	

	printf("logicalfs_dir_open_meta - addr: 0x%llx, recursion depth: %d\n", a_addr, recursion_depth);
	fflush(stdout);

	if (a_addr != a_fs->root_inum || recursion_depth != 1) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
		tsk_error_set_errstr("logicalfs_dir_open_meta: Only opening the root folder with no recursion is currently supported"
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
	
#ifdef TSK_WIN32
	WIN32_FIND_DATA fd;
	// First look up the base folder
	HANDLE hFind = ::FindFirstFile(logical_fs_info->base_path, &fd);
	if (hFind != INVALID_HANDLE_VALUE) {
		fs_dir->fs_file = create_fs_file_from_find_data(&fd, a_fs);
		::FindClose(hFind);
	}

	printf( "logicalfs_dir_open_meta - Trying to read files in directory\n");
	fflush(stdout);
	size_t len = TSTRLEN(logical_fs_info->base_path);
	TSK_TCHAR * searchPath;
	searchPath = (TSK_TCHAR *)tsk_malloc(sizeof(TSK_TCHAR) * (len + 5)); // TODO reduce
	if (searchPath == NULL) {
		return TSK_ERR;
	}
	TSTRNCPY(searchPath, logical_fs_info->base_path, len + 1);
	TSTRNCAT(searchPath, L"/*", 3);
	printf( "logicalfs_dir_open_meta - Search path: %ws\n", searchPath);
	hFind = ::FindFirstFile(searchPath, &fd);
	if (hFind != INVALID_HANDLE_VALUE) {
		vector<string> file_names;
		vector<wstring> dir_names;
		printf( "logicalfs_dir_open_meta - File is valid!\n");
		do {
			printf( "logicalfs_dir_open_meta - Found : %ws\n", fd.cFileName);

			if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				// For the moment at least, skip . and ..
				if (0 != wcsncmp(fd.cFileName, L"..", 3) && 0 != wcsncmp(fd.cFileName, L".", 3)) {
					printf( "   dir\n");
					dir_names.push_back(fd.cFileName);
				}
				else {
					printf( "   skipping\n");
				}
			} else {
				// For now, consider everything else to be a file
				printf( "   file\n");
				wcstombs(name_buf, fd.cFileName, MAX_LOGICAL_NAME_LEN);
				file_names.push_back(string(name_buf));
			}
		} while (::FindNextFile(hFind, &fd));
		::FindClose(hFind);

		sort(file_names.begin(), file_names.end());
		sort(dir_names.begin(), dir_names.end());

		// Add the folders
		printf( "\nlogicalfs_dir_open_meta - adding %lld folders\n", dir_names.size());
		for (auto it = begin(dir_names); it != end(dir_names); ++it) {
			TSK_INUM_T dir_inum = get_inum_from_directory_path(logical_fs_info, *it);
			printf( "logicalfs_dir_open_meta - found inum 0x%llx for file %ws\n", dir_inum, it->c_str());
			fflush(stdout);
		}

		// Add the files
		printf( "\nlogicalfs_dir_open_meta - adding %lld files\n", file_names.size());
		TSK_INUM_T file_inum = a_addr | 1; // First inum is directory inum in the high part, 1 in the low part
		for (auto it = begin(file_names); it != end(file_names); ++it) {
			TSK_FS_NAME *fs_name;
			if ((fs_name = tsk_fs_name_alloc(MAX_LOGICAL_NAME_LEN, 0)) == NULL) {
				// TODO free other stuff
				return TSK_ERR;
			}

			fs_name->type = TSK_FS_NAME_TYPE_REG;
			fs_name->par_addr = a_addr;
			fs_name->meta_addr = file_inum;
			strncpy(fs_name->name, it->c_str(), MAX_LOGICAL_NAME_LEN);
			if (tsk_fs_dir_add(fs_dir, fs_name)) {
				// TODO free other stuff
				tsk_fs_name_free(fs_name);
				return TSK_ERR;
			}
			tsk_fs_name_free(fs_name);

			file_inum++;
		}
	}
	else {
		printf( "logicalfs_dir_open_meta - File is not valid\n");
	}
#endif

	tsk_error_reset();
	tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
	tsk_error_set_errstr("dir_open_meta for logical directory is not implemented yet");
	return TSK_ERR;
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

	LOGICALFS_INFO *dirfs = NULL;
	TSK_FS_INFO *fs = NULL;
	IMG_LOGICAL_INFO *dir_info = NULL;

	printf( "logical_fs_open\n");
	fflush(stdout);

	if (img_info->itype != TSK_IMG_TYPE_LOGICAL) {
		tsk_error_reset();
		tsk_error_set_errno(TSK_ERR_FS_ARG);
		tsk_error_set_errstr("logical_fs_open: image must be of type TSK_IMG_TYPE_DIR");
		return NULL;
	}
	dir_info = (IMG_LOGICAL_INFO *)img_info;

	if ((dirfs = (LOGICALFS_INFO *)tsk_fs_malloc(sizeof(LOGICALFS_INFO))) == NULL)
		return NULL;

	fs = &(dirfs->fs_info);
	dirfs->base_path = dir_info->base_path; // To avoid having to always go through TSK_IMG_INFO

	fs->tag = TSK_FS_INFO_TAG;
	fs->ftype = TSK_FS_TYPE_LOGICAL;
	fs->flags = (TSK_FS_INFO_FLAG_ENUM)0;
	fs->img_info = img_info;
	fs->offset = 0;
	fs->endian = TSK_LIT_ENDIAN;
	fs->duname = "None";

	// Metadata info
	fs->last_inum = 0;
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

	fs->file_add_meta = logicalfs_inode_lookup;
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

	return fs;
}
