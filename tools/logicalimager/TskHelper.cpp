/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2010-2019 Brian Carrier.  All Rights reserved
**
** This software is distributed under the Common Public License 1.0
**
*/

#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <codecvt>

#include "tsk/base/tsk_base_i.h"
#include "tsk/fs/tsk_fs_i.h"
#include "TskHelper.h"

static std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;

Path2InumCacheData::Path2InumCacheData(TSK_INUM_T a_inum, TSK_FS_DIR *a_tsk_fs_dir) {
    m_inum = a_inum;
    m_tsk_fs_dir = a_tsk_fs_dir;
    m_fs_name_flags = TSK_FS_NAME_FLAG_ALLOC;
}

TskHelper::TskHelper()
{
    reset();
}

TskHelper::~TskHelper()
{
}

void TskHelper::reset() {
    releasePath2InumCache();
    m_img_info = NULL;
    m_FSInfoList.clear();
    m_path2InumCache.clear();
}

/**
* toUpper: convert string to uppercase
* @param srcStr to convert
* @return uppercase string
*/
std::string TskHelper::toUpper(const std::string &srcStr) {
    std::string outStr(srcStr);
    std::transform(srcStr.begin(), srcStr.end(), outStr.begin(), ::toupper);

    return outStr;
}

/**
* Convert from UTF-16 to UTF-8.
* Returns empty string on error
*/
std::string TskHelper::toNarrow(const std::wstring & a_utf16Str) {
    try {
        std::string narrow = converter.to_bytes(a_utf16Str);
        return narrow;
    }
    catch (...) {
        return "";
    }
}

/**
* Convert from UTF-8 to UTF-16.
* Returns empty string on error
*/
std::wstring TskHelper::toWide(const std::string &a_utf8Str) {
    try {
        std::wstring wide = converter.from_bytes(a_utf8Str);
        return wide;
    }
    catch (...) {
        return L"";
    }
}

/**
* toLower: convert string to lowercase
* @param srcStr to convert
* @return lowercase string
*/
std::string TskHelper::toLower(const std::string &srcStr) {
    std::string outStr(srcStr);
    std::transform(srcStr.begin(), srcStr.end(), outStr.begin(), ::tolower);

    return outStr;
}

std::string TskHelper::intToStr(long l)
{
    std::stringstream ss;
    ss << l;
    return ss.str();
}

std::string TskHelper::stripExt(const char *a_name) {
    std::string nameNoExt;
    std::string nameStr = std::string(a_name);

    size_t dotPos = nameStr.rfind(".");
    if (dotPos != std::string::npos)
        nameNoExt = nameStr.substr(0, dotPos);
    else
        nameNoExt = nameStr;

    return nameNoExt;
}

/**
* @param curFileName File name that we are currently evaluating against target
* @param targetFileName File name that we want to match against
* @param ignoreExt True if we are ignoring extensions in file name
* @param a_fs File System that files are coming from
* @returns true if match
*/
bool TskHelper::compareNames(const char *curFileName, const char *targetFileName, bool ignoreExt, TSK_FS_INFO *a_fs) {
    const char *nameToMatch;
    std::string nameNoExt;

    if (ignoreExt) {
        nameNoExt = stripExt(curFileName);
        nameToMatch = nameNoExt.c_str();
    }
    else
        nameToMatch = curFileName;

    if (a_fs->name_cmp(a_fs, nameToMatch, targetFileName) == 0) {
        return true;
    }
    else {
        return false;
    }
}

/*
* Check if the bigStr begins with lilStr
*/

bool TskHelper::startsWith(const std::string &bigStr, const std::string &lilStr) {
    return lilStr.length() <= bigStr.length()
        && equal(lilStr.begin(), lilStr.end(), bigStr.begin());
}

/**
 * \ingroup fslib
 *
 * Find the meta data address for a given file name (UTF-8).
 * The basic idea of the function is to break the given name into its
 * subdirectories and start looking for each (starting in the root
 * directory).
 *
 * @param a_fs FS to analyze
 * @param a_path UTF-8 path of file to search for
 * @param anyExtension If true AND the path does not have an extension, then match any file with the same name, but different extension.  If false, then exact match is always done.
 * @param [out] a_result Meta data address, and TSK_FS_NAME_FLAGS of the file
 * @param [out] a_fs_name Copy of name details (or NULL if details not wanted)
 * @param [out] a_fs_file TSK_FS_FILE data if result is 0 (or NULL if file data not wanted). The caller should free the a_fs_file.
 * @returns -1 on (system) error, 0 if found, 1 if not found, 2 if the file path is found but the inode has been reallocated
 */
int
TskHelper::path2Inum(TSK_FS_INFO *a_fs, const char *a_path, bool anyExtension,
    TSKFileNameInfo &a_result, TSK_FS_NAME *a_fs_name, TSK_FS_FILE **a_fs_file) {
    char *cpath;
    size_t clen;
    char *cur_name_to_match;              // The "current" directory or file we are looking for
    char *cur_attr_to_match;             // The "current" attribute of the dir we are looking for
    TSK_INUM_T next_meta;
    uint8_t is_done;

    // std::cout << "TskHlprPath2Inum: Looking for " << a_path << " in FS " << a_fs->offset << std::endl;

    a_result.setINUM(0);
    *a_fs_file = NULL;

    std::string path_matched;
    bool ignoreExt = false;
    TSK_FS_DIR *starting_fs_dir = NULL;


    // copy path to a buffer that we can modify
    clen = strlen(a_path) + 1;
    if ((cpath = (char *)tsk_malloc(clen)) == NULL) {
        return -1;
    }
    strncpy(cpath, a_path, clen);

    //cerr << getNowTimeStr() << "  TSKHlprPath2inum(): Looking for = " << std::string(a_path) << endl;

    // check if we will be looking for an extension
    if (anyExtension) {
        // check if they gave us an extension
        if (stripExt(a_path).compare(a_path) == 0) {
            ignoreExt = true;
        }
    }

    // Get the first part of the directory path. 
    cur_name_to_match = (char *)strtok_r(cpath, "/", &strtok_last);
    cur_attr_to_match = NULL;

    /* If there is no token, then only a '/' was given */
    if (cur_name_to_match == NULL) {
        free(cpath);
        a_result.setINUM(a_fs->root_inum);

        // create the dummy entry if needed
        if (a_fs_name) {
            a_fs_name->meta_addr = a_fs->root_inum;
            // Note that we are not filling in meta_seq -- we could, we just aren't

            a_fs_name->type = TSK_FS_NAME_TYPE_DIR;
            a_fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
            if (a_fs_name->name)
                a_fs_name->name[0] = '\0';
            if (a_fs_name->shrt_name)
                a_fs_name->shrt_name[0] = '\0';
        }
        return 0;
    }

    /* If this is NTFS, seperate out the attribute of the current directory */
    if (TSK_FS_TYPE_ISNTFS(a_fs->ftype)
        && ((cur_attr_to_match = strchr(cur_name_to_match, ':')) != NULL)) {
        *(cur_attr_to_match) = '\0';
        cur_attr_to_match++;
    }

    std::string targetPathAsString = std::string(a_path);
    std::string targetPathSubString = std::string(a_path);
    bool bCacheHit = false;

    /* Try to find the full path or a subset of it in the cache
     * start with looking up the full path and if that is not found, then
     * strip away directories until we find something. */
    while ((targetPathSubString.length() > 0) && (!bCacheHit))
    {
        const Path2InumCacheData *pInumCacheData = lookupPathToInumCache(a_fs, targetPathSubString.c_str());

        // found in cache
        if (NULL != pInumCacheData) {

            bCacheHit = true;
            TSK_INUM_T inum = pInumCacheData->getInum();

            // We looked up the full path and found it - we're done.
            if (targetPathSubString.length() == targetPathAsString.length()) {
                a_result.setINUM(inum);
                a_result.setFSNameFlags(pInumCacheData->getFSNameFlag());
                *a_fs_file = NULL;
                free(cpath);
                return 0;
            }

            // We looked up a parent folder.  Store it as a starting point
            // for the next phase of look ups.
            else {
                // set the starting dir and inum for the loop below
                starting_fs_dir = pInumCacheData->getFSDir();
                next_meta = inum;

                std::string remainderPath = targetPathAsString.substr(targetPathSubString.length() + std::string("/").length());
                strcpy(cpath, remainderPath.c_str());
                path_matched = targetPathSubString; // matched so far

                // what is the next item in the path to find
                cur_name_to_match = (char *)strtok_r(cpath, "/", &strtok_last);
                cur_attr_to_match = NULL;

                /* This happens when we need to map to a folder and they
                * specify a trailing / at the end. */
                if (cur_name_to_match == NULL) {
                    a_result.setINUM(inum);
                    *a_fs_file = NULL;
                    free(cpath);
                    return 0;
                }
            }
        }
        else { // path not found in cache, go up one level in the path and search in cache again

            size_t lastSlashPos = targetPathSubString.find_last_of("/");
            if ((std::string::npos != lastSlashPos)) {
                targetPathSubString = targetPathSubString.substr(0, lastSlashPos);
            }
            else {
                targetPathSubString.clear();
            }
        }
    }

    if (!bCacheHit) {

        // initialize the first place to look, the root dir
        next_meta = a_fs->root_inum;
        path_matched.clear();
    }

    // we loop until we know the outcome and then exit. 
    // everything should return from inside the loop.
    is_done = 0;
    while (is_done == 0) {
        size_t i;
        const TSK_FS_NAME *fs_name_best = NULL; // set to the best match in the given folder

        TSK_FS_DIR *fs_dir = NULL;
        bool bIsCachedFSDir = false;

        if (NULL != starting_fs_dir) {	// if we found a partial cache hit, then use the cached TSK_FS_DIR as a starting point 
            fs_dir = starting_fs_dir;
            bIsCachedFSDir = true;      // remember this is a cached TSK_FS_DIR, so we don't close it
            starting_fs_dir = NULL;		// not valid for subsequent iterations
        }
        else {
            // open the next directory in the recursion
            if ((fs_dir = tsk_fs_dir_open_meta(a_fs, next_meta)) == NULL) {
                free(cpath);
                return -1;
            }
        }

        /* Verify this is indeed a directory.  We had one reported
         * problem where a file was a disk image and opening it as
         * a directory found the directory entries inside of the file
         * and this caused problems... */
        if (fs_dir->fs_file->meta->type != TSK_FS_META_TYPE_DIR) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_GENFS);
            tsk_error_set_errstr("Address %" PRIuINUM
                " is not for a directory\n", next_meta);
            free(cpath);
            return -1;
        }

        // cycle through each entry and find the best match
        for (i = 0; i < tsk_fs_dir_getsize(fs_dir); i++) {

            const TSK_FS_NAME *fs_name = NULL;
            uint8_t found_name = 0;

            if ((fs_name = tsk_fs_dir_get_name(fs_dir, i)) == NULL) {
                if (!bIsCachedFSDir) {
                    tsk_fs_dir_close(fs_dir);		// fs-dir may be cached - can't close it
                }
                free(cpath);
                return -1;
            }

            if (fs_name->name == NULL) {
                continue;
            }
            else if ((fs_name->type == TSK_FS_NAME_TYPE_DIR) && (TSK_FS_ISDOT(fs_name->name))) {
                continue;
            }
            // deleted names that point to 0 are not pointing to a valid meta data structure,
            // so skip them since we only want to return valid addresses from this method
            else if ((fs_name->flags & TSK_FS_NAME_FLAG_UNALLOC) && (fs_name->meta_addr == 0)) {
                continue;
            }

            // cache any files that we see in windows/system32 because we so often look for these
            // Main idea was to cache any file in a subfolder of windows/system32.
            if ((fs_name->flags & TSK_FS_NAME_FLAG_ALLOC) &&
                (fs_name->type == TSK_FS_NAME_TYPE_REG) &&
                startsWith(toLower(path_matched), "windows/system32")) {

                Path2InumCacheData *pCacheData = new Path2InumCacheData(fs_name->meta_addr, NULL);
                pCacheData->setFSNameFlag(fs_name->flags);

                std::string tmp = path_matched;
                tmp.append("/");
                tmp.append(fs_name->name);
                if (addPathToInumCache(a_fs, tmp, pCacheData) == false) {
                    // it was already in the cache
                    delete (pCacheData);
                }
            }

            /*
             * Check if this is the name that we are currently looking for,
             * as identified in 'cur_name_to_match'
             */

             /* FAT and NTFS gets a case insensitive comparisons and look for short name */
            if (TSK_FS_TYPE_ISFAT(a_fs->ftype) || TSK_FS_TYPE_ISNTFS(a_fs->ftype)) {
                bool found_base = false;

                if (compareNames(fs_name->name, cur_name_to_match, ignoreExt, a_fs))
                    found_base = true;

                if ((found_base == false) && (fs_name->shrt_name)) {
                    if (compareNames(fs_name->shrt_name, cur_name_to_match, ignoreExt, a_fs))
                        found_base = true;
                }

                if (found_base) {
                    // if we have FAT or NTFS with no attribute specified, we're good
                    if (TSK_FS_TYPE_ISFAT(a_fs->ftype) || (cur_attr_to_match == NULL)) {
                        found_name = 1;
                    }
                    // otherwise, match the attribute name now
                    else {
                        TSK_FS_FILE *fs_file_tmp1 = tsk_fs_file_open_meta(a_fs, NULL, fs_name->meta_addr);
                        if (fs_file_tmp1) {
                            if (fs_file_tmp1->meta) {
                                int cnt, i;

                                // cycle through the attributes
                                cnt = tsk_fs_file_attr_getsize(fs_file_tmp1);
                                for (i = 0; i < cnt; i++) {
                                    const TSK_FS_ATTR *fs_attr =
                                        tsk_fs_file_attr_get_idx(fs_file_tmp1, i);
                                    if (!fs_attr)
                                        continue;

                                    if ((fs_attr->name)
                                        && (a_fs->name_cmp(a_fs, fs_attr->name,
                                            cur_attr_to_match) == 0)) {
                                        found_name = 1;
                                    }
                                }
                            }
                            tsk_fs_file_close(fs_file_tmp1);
                        }
                    }
                }
            }  // not NTFS or FAT
            else {
                if (compareNames(fs_name->name, cur_name_to_match, ignoreExt, a_fs))
                    found_name = 1;
            }

            // If we didn't find the match, go to the next entry in the dir
            if (found_name == 0) {
                continue;
            }

            // if we found something, see if it is better than what we already have
            // if this is our first hit in this folder, it wins
            if (fs_name_best == NULL) {
                fs_name_best = fs_name;
            }
            // if we found an allocated entry, it replaces whatever was there
            else if (fs_name->flags & TSK_FS_NAME_FLAG_ALLOC) {
                fs_name_best = fs_name;
            }
            // we found an unallocated entry 
            else {
                // if the existing 'best' is alloc, it wins
                if (fs_name_best->flags & TSK_FS_NAME_FLAG_ALLOC) {
                    // no-op
                }
                // if the existing 'best' has meta address of 0, we win
                else if (fs_name_best->meta_addr == 0) {
                    fs_name_best = fs_name;
                }
                // the 'best' is equivalent to ours. Keep the original.
                else {
                    // no-op
                }
            }

            // if we matched on an alloc entry, we're done with this directory
            if (fs_name->flags & TSK_FS_NAME_FLAG_ALLOC) {
                break;
            }
        }

        // we found a hit in the directory, now process it
        if (fs_name_best) {
            const char *pname = cur_name_to_match; // save a copy of the current name pointer

            // update path_matched
            if (path_matched.length() == 0) {
                path_matched = cur_name_to_match;
            }
            else {
                path_matched.append("/");
                path_matched.append(cur_name_to_match);
            }

            // save the matched path and its inum/TSK_FS_DIR to cache 
            if (fs_name_best->flags & TSK_FS_NAME_FLAG_ALLOC) {
                TSK_FS_DIR *cache_fs_dir = NULL;
                Path2InumCacheData *pCacheData = NULL;
                if (fs_name_best->type == TSK_FS_NAME_TYPE_DIR) { // if the matched path is a dir, save the TSK_FS_DIR in cache
                    if ((cache_fs_dir = tsk_fs_dir_open_meta(a_fs, fs_name_best->meta_addr)) != NULL) {
                        pCacheData = new Path2InumCacheData(fs_name_best->meta_addr, cache_fs_dir);
                    }
                }
                else { // is a file not a dir, cache the inum alone
                    pCacheData = new Path2InumCacheData(fs_name_best->meta_addr, NULL);
                    pCacheData->setFSNameFlag(fs_name_best->flags);
                }

                if (pCacheData) {
                    if (addPathToInumCache(a_fs, path_matched, pCacheData) == false) {
                        // it was already in the cache
                        delete (pCacheData);
                    }
                }
            }

            // advance to the next dir / file name
            cur_name_to_match = (char *)strtok_r(NULL, "/", &(strtok_last));
            cur_attr_to_match = NULL;

            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "Found it (%s), now looking for %s\n", pname, cur_name_to_match);

            /* That was the last name in the path -- we found the file! */
            if (cur_name_to_match == NULL) {

                // Make sure the matched file hasn't been deleted and reallocated.
                bool isReallocated = false;
                if ((fs_name_best->flags & TSK_FS_NAME_FLAG_UNALLOC)) {
                    TSK_FS_FILE *fs_file2 = tsk_fs_file_open_meta(a_fs, NULL, fs_name_best->meta_addr);
                    if (NULL != fs_file2) {
                        if ((fs_file2->meta->flags & TSK_FS_NAME_FLAG_ALLOC) && (fs_file2->meta->seq != fs_name_best->meta_seq)) { // MFT entry has been reallocated
                            isReallocated = true;
                        }
                        else if ((fs_file2->meta->flags & TSK_FS_NAME_FLAG_UNALLOC) && (fs_file2->meta->seq + 1 != fs_name_best->meta_seq)) { // MFT entry has been reallocated 
                            isReallocated = true;

                        }
                    }
                    else {
                        isReallocated = true; // should this should be a different return code?
                    }
                    tsk_fs_file_close(fs_file2);
                }

                if (!isReallocated) {	// found a match and it isn't reallocated !! - return this
                    a_result.setINUM(fs_name_best->meta_addr);
                    a_result.setFSNameFlags(fs_name_best->flags);

                    // make a copy if one was requested
                    if (a_fs_name) {
                        tsk_fs_name_copy(a_fs_name, fs_name_best);
                    }

                    // return the TSK_FS_FILE if one was requested
                    *a_fs_file = tsk_fs_file_open_meta(a_fs, NULL, fs_name_best->meta_addr);
                }

                //cerr << getNowTimeStr() << "TSKHlprPath2inum(): Found = " << std::string(a_path) << endl;

                if (!bIsCachedFSDir) {
                    tsk_fs_dir_close(fs_dir);
                }
                free(cpath);

                return (isReallocated) ? 2 : 0;
            }

            // update the attribute field, if needed
            if (TSK_FS_TYPE_ISNTFS(a_fs->ftype)
                && ((cur_attr_to_match = strchr(cur_name_to_match, ':')) != NULL)) {
                *(cur_attr_to_match) = '\0';
                cur_attr_to_match++;
            }

            // update the value for the next directory to open
            next_meta = fs_name_best->meta_addr;
        }

        // no hit in directory
        else {
            is_done = 1;
        }

        if (!bIsCachedFSDir) {
            tsk_fs_dir_close(fs_dir);
        }
        fs_dir = NULL;  
    }

    // std::out << "TSKHlprPath2inum(): Not found = " << std::string(a_path) << std::endl;

    free(cpath);
    return 1;
}

/**
* lookupPathToInumCache - lookup the given <fs,path> in the cache and return corresponding inum & TSK_FS_DIR
*
* @param input a_fs TSK_FS_INFO for the file system containing the file
* @param input a_path pathname of file/dir to lookup
* @returns Path2InumCacheData* if the given path is found in the cache , NULL otherwise.
*/
const Path2InumCacheData* TskHelper::lookupPathToInumCache(const TSK_FS_INFO *a_fs, const char *a_path) {

    TSK_OFF_T fs_off = a_fs->offset;
    std::string lcPath = toLower(a_path);

    auto itr = m_path2InumCache.find(make_pair(fs_off, lcPath));
    if (itr != m_path2InumCache.end()) {
        const Path2InumCacheData* pCacheData = (*itr).second;
        return pCacheData;
    }
    else
        return NULL;
}

/**
* addPathToInumCache - adds the given <fs,path> & corresponding inum & TSK_FS_DIR to cache map
*
* @param input a_fs TSK_FS_INFO for the file system contaning the file
* @param input a_path pathname of file/dir
* @param input a_cacheData Inum and TSK_FS_DIR *, if applicable
* @returns TRUE if successfuly added to cache , false otherwise.
*/

bool TskHelper::addPathToInumCache(const TSK_FS_INFO *a_fs, const std::string &a_path, const Path2InumCacheData *a_cacheData) {
    TSK_OFF_T fs_off = a_fs->offset;
    std::string lcPath = toLower(a_path);

    if (m_path2InumCache.find(make_pair(fs_off, lcPath)) == m_path2InumCache.end()) {
        m_path2InumCache.insert(make_pair(make_pair(fs_off, lcPath), a_cacheData));
        return true;
    }
    else {
        return false;
    }
}

/**
* releasePath2InumCache - Frees up all data in the Path/Inum cache.
*
* @returns 0 on success, -1 on failure
*/
int TskHelper::releasePath2InumCache() {
    for (auto itr = m_path2InumCache.begin(); itr != m_path2InumCache.end(); itr++) {
        const Path2InumCacheData* pCacheData = (*itr).second;
        TSK_FS_DIR * fs_dir = pCacheData->getFSDir();
        if (NULL != fs_dir) {
            tsk_fs_dir_close(fs_dir);
        }
        delete pCacheData;
    }
    m_path2InumCache.clear();
    return 0;
}

void TskHelper::addFSInfo(TSK_FS_INFO *a_fs_info) {
    if (a_fs_info) {
        m_FSInfoList.push_back(a_fs_info);
    }
}

TSK_FS_INFO *TskHelper::getFSInfo(TSK_OFF_T offset) {
    for (auto itr = m_FSInfoList.begin(); itr != m_FSInfoList.end(); itr++) {
        if ((*itr)->offset == offset) {
            return (*itr);
        }
    }
    return NULL;
}

const std::list<TSK_FS_INFO *> TskHelper::getFSInfoList() {
    return m_FSInfoList;
}

void TskHelper::replaceAll(std::string &str, const std::string &from, const std::string &to) {
    if (from.empty())
        return;
    size_t start_pos = 0;
    while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length();
    }
}

/**
* replaceAll - replaces all occurences of 'from' string with the 'to' string, in the given input string, starting the search from specified position
*
* @param input str - input string to examine and modified
* @param input from - string to search for
* @param input to -  string to replace with
* @param input pos - starting position for search
*
* @returns
*/
void TskHelper::replaceAll(std::string &str, const std::string &from, const std::string &to, size_t pos) {
    if (from.empty() || pos >= str.length())
        return;
    size_t start_pos = pos;
    while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length();
    }
}
