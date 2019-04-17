#pragma once
#include "RegParser.h"
#include "RegFileInfo.h"

class RegistryLoader
{
private:
    bool m_sysHivesLoaded = false;
    bool m_userHivesLoaded = false;
    std::list<RegFileInfo *> m_regSystemFiles;
    std::list<RegFileInfo *> m_regNtUserFiles;
    std::list<RegFileInfo *> m_regUsrClassFiles;

    int findUsrclassRegFile(TSK_FS_INFO * a_fs_info, const string aUserDirPathName);
    int findNTUserRegFilesInDir(TSK_FS_INFO * a_fs_info, TSK_INUM_T a_dir_inum, const string& a_path, const string aUserDirName);
    int findUserRegFiles(TSK_FS_INFO * a_fs_info, const string a_starting_dir);
    int findUserRegFiles(TSK_FS_INFO * a_fs_info);
    int findSystemRegFiles(TSK_FS_INFO * a_fs_info);
    void loadSystemHives();
    void loadUserHives();

public:
    RegistryLoader();
    ~RegistryLoader();
    RegFileInfo *getSAMHive();
    RegFileInfo *getSystemHive();
    RegFileInfo *getSoftwareHive();
    RegFileInfo *getSecurityHive();
    std::list<RegFileInfo *>getUsrClassHives();
    std::list<RegFileInfo *>getNtUserHives();

    static RegistryLoader& getInstance()
    {
        static RegistryLoader    instance;
        return instance;
    }

    void freeHives();
};
