/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2010-2019 Brian Carrier.  All Rights reserved
**
** This software is distributed under the Common Public License 1.0
**
*/

/**
* \file RegistryLoader.h
* Contains the class definitions for Registry Loader.
*/

#pragma once

#include "RegParser.h"
#include "RegFileInfo.h"

class RegistryLoader {
public:
    RegistryLoader();
    ~RegistryLoader();
    RegFileInfo *getSAMHive();
    RegFileInfo *getSystemHive();
    RegFileInfo *getSoftwareHive();
    RegFileInfo *getSecurityHive();
    std::list<RegFileInfo *>getUsrClassHives();
    std::list<RegFileInfo *>getNtUserHives();

    static RegistryLoader &getInstance()
    {
        static RegistryLoader    instance;
        return instance;
    }

    void freeHives();

private:
    bool m_sysHivesLoaded = false;
    bool m_userHivesLoaded = false;
    std::list<RegFileInfo *> m_regSystemFiles;
    std::list<RegFileInfo *> m_regNtUserFiles;
    std::list<RegFileInfo *> m_regUsrClassFiles;

    int findUsrClassRegFile(TSK_FS_INFO *a_fs_info, const std::string &aUserDirPathName);
    int findNTUserRegFilesInDir(TSK_FS_INFO *a_fs_info, TSK_INUM_T a_dir_inum, const std::string &a_path, const std::string &aUserDirName);
    int findUserRegFiles(TSK_FS_INFO *a_fs_info, const std::string &a_starting_dir);
    int findUserRegFiles(TSK_FS_INFO *a_fs_info);
    int findSystemRegFiles(TSK_FS_INFO *a_fs_info);
    void loadSystemHives();
    void loadUserHives();
};
