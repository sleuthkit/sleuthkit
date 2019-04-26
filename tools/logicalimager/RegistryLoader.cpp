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
#include <sstream>

#include "RegistryLoader.h"
#include "TskHelper.h"

/** Responsible for loading and caching registry hives for the various modules that will need it. */

RegistryLoader::RegistryLoader() {
}

RegistryLoader::~RegistryLoader() {
    freeHives();
}

/**
* Free the registry hives loaded into memory.
*/
void RegistryLoader::freeHives() {
    for (auto itr = m_regSystemFiles.begin(); itr != m_regSystemFiles.end(); itr++) {
        RegFileInfo *regFile = (*itr);
        delete regFile;
    }
    m_regSystemFiles.clear();

    for (auto itr = m_regUsrClassFiles.begin(); itr != m_regUsrClassFiles.end(); itr++) {
        RegFileInfo *regFile = (*itr);
        delete regFile;
    }
    m_regUsrClassFiles.clear();

    for (auto itr = m_regNtUserFiles.begin(); itr != m_regNtUserFiles.end(); itr++) {
        RegFileInfo *regFile = (*itr);
        delete regFile;
    }
    m_regNtUserFiles.clear();

    m_userHivesLoaded = false;
    m_sysHivesLoaded = false;
}

/**
* Resolve the given hostname to FQDN, if possible
* Only works if runnning on a live system, for an image returns the input hostname as FQDN
*
* @param input aHostName hostname to resolve
* @returns FQDN if success, original hostname if the name cannot be resolved.
*/
std::string getFQDN(const std::string &aHostName) {
    std::string sFQDN = aHostName;
    return sFQDN;
}

/**
* toNormalizedOutputPathName: Normalizes output pathname
*       - ensure there is no drive letter
*       - ensure if there is a UNC path it begins with "//"
*       - ensure all separators are fwd slashes, and there are no redundant separtors
*       - ensure all absolute paths begin with a "/" (FUTURE)
*
* @param input aPath
* @returns  fixed output pth
*/
std::string toNormalizedOutputPathName(const std::string &aPath) {
    std::string pathNameNoDrive("");

    char drive[_MAX_DRIVE];
    char dir[_MAX_DIR];
    char fname[_MAX_FNAME];
    char ext[_MAX_EXT];


    // if its a UNC path and not drive letter                                                                        
    if ((TskHelper::startsWith(aPath, "\\\\") || TskHelper::startsWith(aPath, "//")) &&
        aPath.find(":") == std::string::npos) {

        pathNameNoDrive = aPath;
        TskHelper::replaceAll(pathNameNoDrive, "\\", "/");         // change to unix style slash                            
        TskHelper::replaceAll(pathNameNoDrive, "//", "/", 2);      // fix any redundant slashes                             

                                                        // resolve UNC hostname to FQDN                                                                          
        size_t secondSlashPos = pathNameNoDrive.find_first_of("/", 2); // look for / after the hostname          
        if (std::string::npos != secondSlashPos) {
            std::string hostname = pathNameNoDrive.substr(2, secondSlashPos - 2);
            std::string targetPath = pathNameNoDrive.substr(secondSlashPos);
            std::string hostFQDN = getFQDN(hostname);

            pathNameNoDrive = "//" + hostFQDN + targetPath;
        }
        else {  // Theres a UNC hostname but no sharename/targetPath                                             
            std::string hostname = pathNameNoDrive.substr(2, std::string::npos);
            std::string hostFQDN = getFQDN(hostname);

            pathNameNoDrive = "//" + hostFQDN;
        }
        return pathNameNoDrive;
    }

    _splitpath_s(aPath.c_str(), drive, dir, fname, ext);

    pathNameNoDrive = std::string(dir) + std::string(fname) + std::string(ext);
    TskHelper::replaceAll(pathNameNoDrive, "\\", "/");    // change to fwd slashes so they can be looked up by TskAuto          

                                               // @TODO - remove this when fixing CT-2372                                                                       
    if (TskHelper::startsWith(pathNameNoDrive, "/")) {    // strip the leading slash                                            
        pathNameNoDrive.erase(0, 1);
    }

    TskHelper::replaceAll(pathNameNoDrive, "//", "/");         // fix any redundant slashes                                     
    return pathNameNoDrive;
}

/**
* Get the SAM hive
*
* @returns RegFileInfo pointer, or NULL if not found
*/
RegFileInfo *RegistryLoader::getSAMHive() {
    loadSystemHives();
    for (auto itr = m_regSystemFiles.begin(); itr != m_regSystemFiles.end(); itr++) {
        RegFileInfo *regFile = (*itr);
        if (regFile->getHiveType() == RegHiveType::SAM) {
            return regFile;
        }
    }
    return NULL;
}

/**
* Get the SYSTEM hive
*
* @returns RegFileInfo pointer, or NULL if not found
*/
RegFileInfo *RegistryLoader::getSystemHive() {
    loadSystemHives();
    for (auto itr = m_regSystemFiles.begin(); itr != m_regSystemFiles.end(); itr++) {
        RegFileInfo *regFile = (*itr);
        if (regFile->getHiveType() == RegHiveType::SYSTEM) {
            return regFile;
        }
    }
    return NULL;
}

/**
* Get the SOFTWARE hive
*
* @returns RegFileInfo pointer, or NULL if not found
*/
RegFileInfo *RegistryLoader::getSoftwareHive() {
    loadSystemHives();
    for (auto itr = m_regSystemFiles.begin(); itr != m_regSystemFiles.end(); itr++) {
        RegFileInfo *regFile = (*itr);
        if (regFile->getHiveType() == RegHiveType::SOFTWARE) {
            return regFile;
        }
    }
    return NULL;
}

/**
* Get the SECURITY hive
*
* @returns RegFileInfo pointer, or NULL if not found
*/
RegFileInfo *RegistryLoader::getSecurityHive() {
    loadSystemHives();
    for (auto itr = m_regSystemFiles.begin(); itr != m_regSystemFiles.end(); itr++) {
        RegFileInfo *regFile = (*itr);
        if (regFile->getHiveType() == RegHiveType::SECURITY) {
            return regFile;
        }
    }
    return NULL;
}

/**
* Get the Usr Class hive
*
* @returns a list of RegFileInfo pointers
*/
std::list<RegFileInfo *>RegistryLoader::getUsrClassHives() {
    loadUserHives();
    return m_regUsrClassFiles;
}

/**
* Get the NT User Class hive
*
* @returns a list of RegFileInfo pointers
*/
std::list<RegFileInfo *>RegistryLoader::getNtUserHives() {
    loadUserHives();
    return m_regNtUserFiles;
}

/**
* Lazy loading method for hives in system32
*
*/
void RegistryLoader::loadSystemHives() {
    if (m_sysHivesLoaded)
        return;

    m_sysHivesLoaded = true;
    const std::list<TSK_FS_INFO *> fsList = TskHelper::getInstance().getFSInfoList();
    for (auto itr = fsList.begin(); itr != fsList.end(); itr++) {
        TSK_FS_INFO *fs_info = (*itr);
        findSystemRegFiles(fs_info);
    }

    // Could put a log entry here if nothing was found...
}

/**
* Lazy loading method for hives in user folders
*
*/
void RegistryLoader::loadUserHives() {
    if (m_userHivesLoaded)
        return;

    m_userHivesLoaded = true;
    const std::list<TSK_FS_INFO *> fsList = TskHelper::getInstance().getFSInfoList();
    for (auto itr = fsList.begin(); itr != fsList.end(); itr++) {
        TSK_FS_INFO *fs_info = (*itr);
        findUserRegFiles(fs_info);
    }
}

/* Enumerate the System registry files and save the results to
 * class member variables.
 *
 * @param a_fs_info TSK_FS_INFO
 * @returns -1 on error, 0 on success
 */
int RegistryLoader::findSystemRegFiles(TSK_FS_INFO *a_fs_info) {
    const std::string SYS_REG_FILES_DIR = "/Windows/System32/config";

    TSKFileNameInfo filenameInfo;
    TSK_FS_FILE *fsFile;
    int8_t retval = TskHelper::getInstance().path2Inum(a_fs_info, SYS_REG_FILES_DIR.c_str(), false, filenameInfo, NULL, &fsFile);
    if (retval == -1) {
        std::cerr << "Error in finding system Registry files. System Registry files will not be analyzed." << std::endl;
        std::cerr << "findSystemRegFiles(): path2inum() failed for dir = " << SYS_REG_FILES_DIR << ", errno = " << tsk_error_get() << std::endl;
        return -1;
    }
    else if (retval > 0) { // not found   // @@@ ACTUALLY CHECK IF IT IS #2
        return 0;
    }

    // open the directory
    TSK_FS_DIR *fs_dir;
    if ((fs_dir = tsk_fs_dir_open_meta(a_fs_info, filenameInfo.getINUM())) == NULL) {
        std::cerr << "Error opening windows/system32/config folder. Some System Registry files may not be analyzed.";
        std::cerr << "findSystemRegFiles(): tsk_fs_dir_open_meta() failed for windows/system32/config folder.  dir inum = " << 
            filenameInfo.getINUM() << ", errno = " << tsk_error_get() << std::endl;
        return -1;
    }

    // cycle through each directory entry
    for (size_t i = 0; i < tsk_fs_dir_getsize(fs_dir); i++) {

        TSK_OFF_T off = 0;

        // get the entry
        const TSK_FS_NAME *fs_name;
        if ((fs_name = tsk_fs_dir_get_name(fs_dir, i)) == NULL) {
            std::cerr << "Error in finding System Registry files. Some System Registry files may not be analyzed." << std::endl;
            std::cerr << "findSystemRegFiles(): Error getting directory entry = " << i << " in dir inum = " << filenameInfo.getINUM() << 
                ", errno = " << tsk_error_get() << ", some System Registry files may not be analyzed." << std::endl;
            continue;
        }

        if (((fs_name->flags & TSK_FS_META_FLAG_ALLOC) == 0) || (fs_name->type != TSK_FS_NAME_TYPE_REG)) {
            continue;
        }

        std::string fName = fs_name->name;
        if ((0 == _stricmp("SYSTEM", fName.c_str())) || (0 == _stricmp("SOFTWARE", fName.c_str())) ||
            (0 == _stricmp("SECURITY", fName.c_str())) || (0 == _stricmp("SAM", fName.c_str()))) {

            RegHiveType::Enum hiveType = RegFileInfo::hiveNameToType(fName);

            // @@ FIX THE ERROR MSGS HERE
            TSK_FS_FILE *fs_file;
            if ((fs_file = tsk_fs_dir_get(fs_dir, i)) == NULL) {
                std::cerr << "Error in loading Registry file. The Registry file will not be analyzed." << std::endl;
                std::cerr <<  "findSystemRegFiles(): tsk_fs_dir_get failed for file = fs_file is null." << std::endl;
                continue;
            }

            RegParser *pRegParser = new RegParser(hiveType);
            if (0 != pRegParser->loadHive(fs_file, hiveType)) {
                std::cerr << "Error in loading Registry file. The Registry file will not be analyzed." << std::endl;
                std::cerr << "findSystemRegFiles(): loadHive() failed for file = " << fs_file->name->name << std::endl;
                continue;
            }

            RegFileInfo *pRegFileInfo = new RegFileInfo(fName, toNormalizedOutputPathName(SYS_REG_FILES_DIR), hiveType, 
                fs_file->fs_info->offset, fs_file->meta->addr, pRegParser);

            m_regSystemFiles.push_back(pRegFileInfo);
            tsk_fs_file_close(fs_file);
        }
    } // for
    tsk_fs_dir_close(fs_dir);
    return 0;
}

/** Enumerate the user registry hives in a given file system.
 * results are saved to class member variables.
 *
 * @param a_fs_info TSK_FS_INFO
 * @returns -1 on error and 0 on success
 */
int RegistryLoader::findUserRegFiles(TSK_FS_INFO *a_fs_info) {
    const std::string XP_USER_ROOT_DIR = "/Documents and Settings";
    const std::string WIN7_USER_ROOT_DIR = "/Users";

    // expect one will fail and the other will hopefully succeed
    int rc1 = findUserRegFiles(a_fs_info, XP_USER_ROOT_DIR.c_str());
    int rc2 = findUserRegFiles(a_fs_info, WIN7_USER_ROOT_DIR.c_str());

    return (rc1 == 0 || rc2 == 0) ? 0 : -1;
}

/** Enumerate the user registry hives in a given user folder.  Goes recursively into them.
 * Results are saved to class member variables.
 *
 * @param a_fs_info TSK_FS_INFO
 * @param a_starting_dir starting directory
 * @returns -1 on error, 0 on success (NOTE THERE IS A BUG IN THE CODE)
 */

int RegistryLoader::findUserRegFiles(TSK_FS_INFO *a_fs_info, const std::string &a_starting_dir) {
    TSK_FS_DIR *fs_dir;
    TSKFileNameInfo filenameInfo;
    TSK_FS_FILE *fsFile;
    int8_t retval = TskHelper::getInstance().path2Inum(a_fs_info, a_starting_dir.c_str(), false, filenameInfo, NULL, &fsFile);

    if (retval == -1) {
        std::cerr << "Error in finding User Registry files. Some User Registry files may not be analyzed." << std::endl;
        std::cerr << "findUserRegFiles(): tsk_fs_path2inum() failed for dir = " << a_starting_dir << ", errno = " << tsk_error_get() << std::endl;
        return -1;
    }
    else if (retval > 0) { // not found
        return 0;
    }

    // open the directory
    if ((fs_dir = tsk_fs_dir_open_meta(a_fs_info, filenameInfo.getINUM())) == NULL) {
        std::cerr << "Error in finding User Registry files. Some User Registry files may not be analyzed." << std::endl;
        std::cerr << "findUserRegFiles(): tsk_fs_dir_open_meta() failed for dir = " << a_starting_dir << ", errno = " << tsk_error_get() << std::endl;
        return -1;
    }

    // cycle through each (user folder) directory entry
    for (size_t i = 0; i < tsk_fs_dir_getsize(fs_dir); i++) {
        TSK_FS_FILE *fs_file;
        TSK_OFF_T off = 0;

        // get the entry
        if ((fs_file = tsk_fs_dir_get(fs_dir, i)) == NULL) {
            std::cerr << "Error in finding User Registry files. Some User Registry files may not be analyzed." << std::endl;
            std::cerr << "findUserRegFiles(): Error getting directory entry = " << i << " in dir inum = " << filenameInfo.getINUM() << 
                ", errno = " << tsk_error_get() << std::endl;
            continue;
        }

        if (fs_file->meta) {
            if (fs_file->meta->type == TSK_FS_META_TYPE_DIR) {
                if (TSK_FS_ISDOT(fs_file->name->name) == 0) {

                    // @@@ We are ignoring the return value here...  Only the last value will be returned
                    (void) findNTUserRegFilesInDir(a_fs_info, fs_file->name->meta_addr, a_starting_dir, fs_file->name->name);

                    std::string userHomeDirPath = a_starting_dir + "/" + fs_file->name->name;
                    retval = findUsrClassRegFile(a_fs_info, userHomeDirPath);
                }
            }
        }
        tsk_fs_file_close(fs_file);
    } // for
    return retval;
}

/** Enumerates NTUSER.dat files in a given folder.  Does not go recursive.
 * Results are stored in member class variables.
 *
 * @param a_fs_info File system being analyzed
 * @param a_dir_inum Metadata address for user directory.
 * @param a_userFolderPath Path to user folder
 * @param aUserDirName Name of user for folder
 * @returns -1 on error and 0 on success
 */
int RegistryLoader::findNTUserRegFilesInDir(TSK_FS_INFO *a_fs_info, TSK_INUM_T a_dir_inum, const std::string &a_userFolderPath, 
                                            const std::string &aUserDirName) {
    TSK_FS_DIR *fs_dir;

    // 1. open the directory
    if ((fs_dir = tsk_fs_dir_open_meta(a_fs_info, a_dir_inum)) == NULL) {
        std::cerr << "Error in finding NTUSER Registry files. Some User Registry files may not be analyzed." << std::endl;
        std::cerr << "findNTUserRegFilesInDir(): tsk_fs_dir_open_meta() failed for dir = " << aUserDirName << ", errno = " << tsk_error_get() << std::endl;
        return -1;
    }

    // 2. cycle through each directory entry
    for (size_t i = 0; i < tsk_fs_dir_getsize(fs_dir); i++) {

        TSK_OFF_T off = 0;

        // get the entry
        const TSK_FS_NAME *fs_name;
        if ((fs_name = tsk_fs_dir_get_name(fs_dir, i)) == NULL) {
            std::cerr << "Error in finding NTUSER Registry files. Some User Registry files may not be analyzed." << std::endl;
            std::cerr << "findNTUserRegFilesInDir(): Error getting directory entry = " << i << " in dir inum = " << a_dir_inum << 
                ", errno = " << tsk_error_get() << std::endl;
            continue;
        }

        if (((fs_name->flags & TSK_FS_META_FLAG_ALLOC) == 0) || (fs_name->type != TSK_FS_NAME_TYPE_REG)) {
            continue;
        }

        if ((0 == _stricmp("NTUSER.DAT", fs_name->name))) {
            std::string fName = fs_name->name;
            RegHiveType::Enum hiveType = RegFileInfo::hiveNameToType(fName);

            TSK_FS_FILE *fs_file;
            if ((fs_file = tsk_fs_dir_get(fs_dir, i)) == NULL) {
                std::cerr << "Error in loading Registry file. The Registry file will not be analyzed." << std::endl;
                std::cerr << "findNTUserRegFilesInDir(): tsk_fs_dir_get() failed for file = fs_file is null." << std::endl;
                continue;
            }

            RegParser *pRegParser = new RegParser(hiveType);
            if (0 != pRegParser->loadHive(fs_file, hiveType)) {
                std::cerr << "Error in loading Registry file. The Registry file will not be analyzed." << std::endl;
                std::cerr << "findNTUserRegFilesInDir(): loadHive() failed for file = " << fs_file->name->name << std::endl;
                continue;
            }
            RegFileInfo *pRegFileInfo = new RegFileInfo(fName, toNormalizedOutputPathName(a_userFolderPath + "/" + aUserDirName), hiveType, 
                fs_file->fs_info->offset, fs_file->meta->addr, pRegParser);

            // assume the folder name where the REG file is found is the username 
            if (aUserDirName.length() > 0) {
                if (_stricmp(aUserDirName.c_str(), "All Users") != 0) { // thats not a real username

                    std::string userName("");
                    size_t dotPos = aUserDirName.find_first_of(".");
                    if (std::string::npos != dotPos) {
                        userName = aUserDirName.substr(0, dotPos);
                    }
                    else {
                        userName = aUserDirName;
                    }
                    pRegFileInfo->setUserAccountName(userName);
                }
            }
            m_regNtUserFiles.push_back(pRegFileInfo);
            tsk_fs_file_close(fs_file);
        }
    } // for
    tsk_fs_dir_close(fs_dir);
    return 0;
}

/** Enumerates USRCLASS.DAT files in a given user folder.  Does not go recursive.
 * Results are stored in member class variables.
 *
 * @param a_fs_info File system being analyzed
 * @param aUserDirPathName Path to user folder
 * @returns -1 on error and 0 on success
 */
int RegistryLoader::findUsrClassRegFile(TSK_FS_INFO *a_fs_info, const std::string &aUserDirPathName) {

    // Look for usrclass.dat
    const std::string WIN7_USRCLASS_SUBDIR = "/AppData/Local/Microsoft/Windows";
    const std::string XP_USRCLASS_SUBDIR = "/Local Settings/Application Data/Microsoft/Windows";

    std::string usrClassSubdir("");
    if (TskHelper::startsWith(aUserDirPathName, "/Users")) {
        usrClassSubdir = aUserDirPathName + WIN7_USRCLASS_SUBDIR;
    }
    else {
        usrClassSubdir = aUserDirPathName + XP_USRCLASS_SUBDIR;
    }

    TSKFileNameInfo filenameInfo;
    TSK_FS_FILE *fsFile;
    int8_t retval = TskHelper::getInstance().path2Inum(a_fs_info, usrClassSubdir.c_str(), false, filenameInfo, NULL, &fsFile);

    if (retval == -1) {
        std::cerr << "Error in finding USRCLASS Registry files. Some User Registry files may not be analyzed." << std::endl;
        std::cerr << "findUsrClassRegFile(): tsk_fs_path2inum() failed for dir = " << usrClassSubdir << ", errno = " << tsk_error_get() << std::endl;
        return -1;
    }
    else if (retval == 0) {     //  found

        TSK_FS_DIR *fs_dir;

        // open the directory
        if ((fs_dir = tsk_fs_dir_open_meta(a_fs_info, filenameInfo.getINUM())) == NULL) {
            std::cerr << "Error in finding USRCLASS Registry files. Some User Registry files may not be analyzed." << std::endl;
            std::cerr << "findUsrClassRegFile(): tsk_fs_dir_open_meta() failed for dir inum = " << filenameInfo.getINUM() << 
                ", errno = " << tsk_error_get() << std::endl;
            return -1;
        }

        // cycle through each directory entry
        for (size_t i = 0; i < tsk_fs_dir_getsize(fs_dir); i++) {
            TSK_FS_FILE *fs_file;
            TSK_OFF_T off = 0;

            // get the entry
            if ((fs_file = tsk_fs_dir_get(fs_dir, i)) == NULL) {
                std::cerr << "Error in finding USRCLASS Registry files. Some User Registry files may not be analyzed." << std::endl;
                std::cerr << "findUsrClassRegFile(): Error getting directory entry = " << i << " in dir inum = " << filenameInfo.getINUM() << 
                    ", errno = " << tsk_error_get() << std::endl;
                continue;
            }

            // make sure it's got metadata and not only a name
            if (fs_file->meta) {
                if ((fs_file->meta->type == TSK_FS_META_TYPE_REG) && (fs_file->meta->flags & TSK_FS_META_FLAG_ALLOC)) {
                    if (fs_file->name) {
                        std::string fName = fs_file->name->name;

                        if ((0 == _stricmp("USRCLASS.DAT", fName.c_str()))) {

                            RegHiveType::Enum hiveType = RegFileInfo::hiveNameToType(fName);

                            RegParser *pRegParser = new RegParser(hiveType);
                            if (0 != pRegParser->loadHive(fs_file, hiveType)) {
                                std::cerr << "Error in loading Registry file. The Registry file will not be analyzed." << std::endl;
                                std::cerr << "findUsrClassRegFile(): loadHive() failed for file = " << fs_file->name->name << std::endl;
                                return -1;
                            }
                            RegFileInfo *pRegFileInfo = new RegFileInfo(fName, toNormalizedOutputPathName(usrClassSubdir), hiveType, 
                                fs_file->fs_info->offset, fs_file->meta->addr, pRegParser);

                            // determine the user for this file, from the homedir name
                            std::string userName("");
                            std::string aUserDirName("");

                            size_t lastSlashPos = aUserDirPathName.find_last_of("/");
                            if ((std::string::npos != lastSlashPos)) {
                                aUserDirName = aUserDirPathName.substr(lastSlashPos + 1);
                            }
                            size_t dotPos = aUserDirName.find_first_of(".");
                            if (std::string::npos != dotPos) {
                                userName = aUserDirName.substr(0, dotPos);
                            }
                            else {
                                userName = aUserDirName;
                            }

                            pRegFileInfo->setUserAccountName(userName);

                            // add reg file to list
                            m_regUsrClassFiles.push_back(pRegFileInfo);
                        }
                    }
                }
            }
            tsk_fs_file_close(fs_file);
        } // for
        tsk_fs_dir_close(fs_dir);
    }
    return 0;
}
