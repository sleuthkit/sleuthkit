/*
** The Sleuth Kit
**
** Copyright (c) 2022 Basis Technology Corp.  All rights reserved
** Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
**
** This software is distributed under the Common Public License 1.0
**
*/

/* 
 * Contains the logical directory image-specific functions and structures.
 */

#ifndef _LOGICAL_H
#define _LOGICAL_H

#ifdef __cplusplus
extern "C" {
#endif

#define LOGICAL_IMG_DEBUG_PRINT 0
#define LOGICAL_IMG_CACHE_AGE   1000
#define LOGICAL_FILE_HANDLE_CACHE_LEN 10
#define LOGICAL_INUM_CACHE_LEN 20000
#define LOGICAL_INUM_CACHE_MAX_PATH_LEN 500
#define LOGICAL_INVALID_INUM 0
#define DIR_FILE_LIST_CACHE_LEN 500  ///< Max number of cached directory file lists

	typedef struct {
#ifdef TSK_WIN32
		HANDLE fd;
#else
		int fd;
#endif
		TSK_INUM_T inum;
		TSK_OFF_T seek_pos;
	} LOGICAL_FILE_HANDLE_CACHE;

	typedef struct {
		TSK_INUM_T inum;
		TSK_TCHAR *path;
		size_t path_len;     ///< Cached length of path (in TCHARs, excluding NUL), avoids TSTRLEN() in scan loops
		uint64_t last_used;  ///< Logical-clock tick of last access; 0 = empty slot. Used for LRU eviction. uint64_t so it cannot wrap in any realistic run.
	} LOGICAL_INUM_CACHE;

	typedef struct {
		TSK_INUM_T dir_inum;           ///< Directory inode (LOGICAL_INVALID_INUM = empty slot)
		TSK_TCHAR** file_names;        ///< Array of file name pointers (wide strings)
		size_t file_count;             ///< Number of files in this directory
	} DIR_FILE_CACHE_ENTRY;

	typedef struct {
		DIR_FILE_CACHE_ENTRY entries[DIR_FILE_LIST_CACHE_LEN];  ///< Fixed-size FIFO cache
		int next_insert_index;  ///< Round-robin insertion point
	} DIR_FILE_LIST_CACHE;

    typedef struct {
		TSK_IMG_INFO img_info;
		/**
		 * Fully resolved, \\?\-prefixed host path that represents the root of
		 * the logical image, set at logical_open time. Invariants:
		 *   - Never has a trailing separator.
		 *   - Consumers that build child paths MUST prepend their own '\\' before
		 *     appending the relative component (the inum cache stores relative
		 *     paths that start without a separator).
		 *   - Drive-root inputs like "C:\" are NOT a supported use case — they
		 *     resolve to "\\?\C:" which several Win32 APIs reject. Logical
		 *     images are expected to point at a real directory subtree.
		 */
		TSK_TCHAR * base_path;
		uint8_t is_winobj;

		// Goes with the cache handling in tsk_img.h.
		// To cache blocks, we need to keep track of both the file inum and the offset,
		// so we need one additional array to track logical file data.
		TSK_INUM_T cache_inum[TSK_IMG_INFO_CACHE_NUM];    ///< starting byte offset of corresponding cache entry (r/w shared - lock)

		// Cache a number of open file handles (protected by cache_lock)
		LOGICAL_FILE_HANDLE_CACHE file_handle_cache[LOGICAL_FILE_HANDLE_CACHE_LEN];     /* small number of fds for open images */
		int next_file_handle_cache_slot;

		// Cache a number of inums / directory path pairs (protected by cache_lock)
		LOGICAL_INUM_CACHE inum_cache[LOGICAL_INUM_CACHE_LEN];
		uint64_t inum_cache_clock;  ///< Monotonically-increasing LRU clock; incremented on each cache access (protected by cache_lock). uint64_t so it cannot wrap in any realistic run.

		// Cache of sorted file lists per directory (FIFO, protected by cache_lock)
		DIR_FILE_LIST_CACHE dir_file_list_cache;

    } IMG_LOGICAL_INFO;

	extern TSK_IMG_INFO *logical_open(int a_num_img,
		const TSK_TCHAR * const a_images[], unsigned int a_ssize);

	extern void
		clear_inum_cache_entry(IMG_LOGICAL_INFO *logical_img_info, int index);

#ifdef __cplusplus
}
#endif
#endif
