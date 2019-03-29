/***************************************************************************
** This data and information is proprietary to, and a valuable trade secret
** of, Basis Technology Corp.  It is given in confidence by Basis Technology
** and may only be used as permitted under the license agreement under which
** it has been distributed, and in no other way.
**
** Copyright (c) 2014-2016 Basis Technology Corp. All rights reserved.
**
** The technical data and information provided herein are provided with
** `limited rights', and the computer software provided herein is provided
** with `restricted rights' as those terms are defined in DAR and ASPR
** 7-104.9(a).
***************************************************************************/

#pragma once

#include <string>
#include <list>
#include <map>
#include "tsk/auto/tsk_auto.h"

typedef std::pair<TSK_OFF_T, std::string> Path2InumCacheKey;

/**
 * Path2InumCacheData encapsulates data cached to help speed up file searches by pathname
 * For files - inum and the TSK_FS_NAME_FLAG_ENUM is cached
 * For direcories  - inum and TSK_FS_DIR is cached to speed up subsequent lookups along the same path
 */
class Path2InumCacheData {
public:
    Path2InumCacheData(TSK_INUM_T a_inum, TSK_FS_DIR *a_tsk_fs_dir);
    
    void setFSNameFlag(TSK_FS_NAME_FLAG_ENUM a_flag) {m_fs_name_flags = a_flag;};

    TSK_INUM_T getInum() const { return m_inum; }
    TSK_FS_DIR *getFSDir() const { return m_tsk_fs_dir; }
    TSK_FS_NAME_FLAG_ENUM getFSNameFlag() const { return m_fs_name_flags; }

private:
    TSK_INUM_T m_inum;
    TSK_FS_DIR *m_tsk_fs_dir;
    TSK_FS_NAME_FLAG_ENUM m_fs_name_flags;
};

typedef std::map<Path2InumCacheKey, const Path2InumCacheData *> Path2InumCache;

class TSKFileNameInfo {
public:
    TSKFileNameInfo() {
        m_inum = 0;
        m_flags = TSK_FS_NAME_FLAG_ALLOC;
    };

    void setINUM(TSK_INUM_T a_inum) { m_inum =  a_inum;};
    void setFSNameFlags(TSK_FS_NAME_FLAG_ENUM a_flags) { m_flags =  a_flags;};

    TSK_INUM_T getINUM() const { return m_inum;};
    TSK_FS_NAME_FLAG_ENUM getFSNameFlags() const { return m_flags;};

private:
    TSK_INUM_T m_inum;                    // meta address.
    TSK_FS_NAME_FLAG_ENUM m_flags;        // name flags
};

class TskHelper {
public:
    static TskHelper& getInstance() {
        static TskHelper instance; 
        return instance;
    }

    void reset(void);

    void addFSInfo(TSK_FS_INFO * fs_info);
    TSK_FS_INFO * getFSInfo(TSK_OFF_T offset);
    const std::list<TSK_FS_INFO *> getFSInfoList();

    void setImgInfo(TSK_IMG_INFO *a_img_info) { m_img_info = a_img_info; }

    int path2Inum(TSK_FS_INFO *a_fs, const char *a_path, TSKFileNameInfo &a_result, TSK_FS_NAME *a_fs_name, TSK_FS_FILE **a_fs_file);

private:
    std::string toLower(const std::string &srcStr);
    std::string stripExt(const char *a_path);    // strip the extension from the given name, if any
    bool compareNames(const char *curFileName, const char *cur_dir, bool ignoreExt, TSK_FS_INFO *a_fs);

    const Path2InumCacheData *lookupPathToInumCache(const TSK_FS_INFO *a_fs, const char *a_path);
    bool addPathToInumCache(const TSK_FS_INFO *a_fs, const std::string a_path, const Path2InumCacheData *a_cacheData);
    int releasePath2InumCache();

    TskHelper();  
    ~TskHelper();
    TskHelper(TskHelper const&);             

    TSK_IMG_INFO *m_img_info;

    std::list<TSK_FS_INFO *> m_FSInfoList;     // a list of FileSystem found on the target

    Path2InumCache m_path2InumCache;
};
