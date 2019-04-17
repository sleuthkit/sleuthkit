#include <iostream>
#include <sstream>
#include "RegistryLoader.h"
#include "TskHelper.h"
#include "ConfigMgr.h"

//#include "WindowsPhase1Processor.h" // needed only for the user folder paths

/** Responsible for loading and caching registry hives for the various modules that will need it. */

RegistryLoader::RegistryLoader() {
}

RegistryLoader::~RegistryLoader() {
    freeHives();
}

// free the registry hives loaded into memory. 
void RegistryLoader::freeHives()
{
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
string getFQDN(const string& aHostName)
{
    string sFQDN = aHostName;
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
*
* @returns  fixed output pth
*
*/
string toNormalizedOutputPathName(const string &aPath) {
    string pathNameNoDrive("");

    char drive[_MAX_DRIVE];
    char dir[_MAX_DIR];
    char fname[_MAX_FNAME];
    char ext[_MAX_EXT];


    // if its a UNC path and not drive letter                                                                        
    if ((TskHelper::startsWith(aPath, "\\\\") || TskHelper::startsWith(aPath, "//")) &&
        aPath.find(":") == string::npos) {

        pathNameNoDrive = aPath;
        TskHelper::replaceAll(pathNameNoDrive, "\\", "/");         // change to unix style slash                            
        TskHelper::replaceAll(pathNameNoDrive, "//", "/", 2);      // fix any redundant slashes                             

                                                        // resolve UNC hostname to FQDN                                                                          
        size_t secondSlashPos = pathNameNoDrive.find_first_of("/", 2); // look for / after the hostname          
        if (string::npos != secondSlashPos) {

            string hostname = pathNameNoDrive.substr(2, secondSlashPos - 2);
            string targetPath = pathNameNoDrive.substr(secondSlashPos);
            string hostFQDN = getFQDN(hostname);

            pathNameNoDrive = "//" + hostFQDN + targetPath;
        }
        else {  // Theres a UNC hostname but no sharename/targetPath                                             
            string hostname = pathNameNoDrive.substr(2, string::npos);
            string hostFQDN = getFQDN(hostname);

            pathNameNoDrive = "//" + hostFQDN;
        }

        return pathNameNoDrive;
    }

    _splitpath_s(aPath.c_str(), drive, dir, fname, ext);

    pathNameNoDrive = string(dir) + string(fname) + string(ext);
    TskHelper::replaceAll(pathNameNoDrive, "\\", "/");    // change to fwd slashes so they can be looked up by TskAuto          

                                               // @TODO - remove this when fixing CT-2372                                                                       
    if (TskHelper::startsWith(pathNameNoDrive, "/")) {    // strip the leading slash                                            
        pathNameNoDrive.erase(0, 1);
    }

    TskHelper::replaceAll(pathNameNoDrive, "//", "/");         // fix any redundant slashes                                     

    return pathNameNoDrive;
}

RegFileInfo *RegistryLoader::getSAMHive()
{
    loadSystemHives();
    for (auto itr = m_regSystemFiles.begin(); itr != m_regSystemFiles.end(); itr++) {
        RegFileInfo *regFile = (*itr);
        if (regFile->getHiveType() == RegHiveType::SAM) {
            return regFile;
        }
    }
    return NULL;
}

RegFileInfo *RegistryLoader::getSystemHive()
{
    loadSystemHives();
    for (auto itr = m_regSystemFiles.begin(); itr != m_regSystemFiles.end(); itr++) {
        RegFileInfo *regFile = (*itr);
        if (regFile->getHiveType() == RegHiveType::SYSTEM) {
            return regFile;
        }
    }
    return NULL;
}

RegFileInfo *RegistryLoader::getSoftwareHive()
{
    loadSystemHives();
    for (auto itr = m_regSystemFiles.begin(); itr != m_regSystemFiles.end(); itr++) {
        RegFileInfo *regFile = (*itr);
        if (regFile->getHiveType() == RegHiveType::SOFTWARE) {
            return regFile;
        }
    }
    return NULL;
}

RegFileInfo *RegistryLoader::getSecurityHive()
{
    loadSystemHives();
    for (auto itr = m_regSystemFiles.begin(); itr != m_regSystemFiles.end(); itr++) {
        RegFileInfo *regFile = (*itr);
        if (regFile->getHiveType() == RegHiveType::SECURITY) {
            return regFile;
        }
    }
    return NULL;
}

std::list<RegFileInfo *>RegistryLoader::getUsrClassHives()
{
    loadUserHives();
    return m_regUsrClassFiles;
}

std::list<RegFileInfo *>RegistryLoader::getNtUserHives()
{
    loadUserHives();
    return m_regNtUserFiles;
}

// lazy loading method for hives in system32
void RegistryLoader::loadSystemHives()
{
    if (m_sysHivesLoaded)
        return;

    m_sysHivesLoaded = true;
    //CyberTriageUtils::DEBUG_PRINT("Searching for system registry files");
    const std::list<TSK_FS_INFO *> fsList = TskHelper::getInstance().getFSInfoList();
    for (auto itr = fsList.begin(); itr != fsList.end(); itr++) {
        TSK_FS_INFO *fs_info = (*itr);
        findSystemRegFiles(fs_info);
    }

    // Could put a log entry here if nothing was found...
}

// lazy loading method for hives in user folders
void RegistryLoader::loadUserHives()
{
    if (m_userHivesLoaded)
        return;

    m_userHivesLoaded = true;
    //CyberTriageUtils::DEBUG_PRINT("Searching for user registry files");
    const std::list<TSK_FS_INFO *> fsList = TskHelper::getInstance().getFSInfoList();
    for (auto itr = fsList.begin(); itr != fsList.end(); itr++) {
        TSK_FS_INFO *fs_info = (*itr);
        findUserRegFiles(fs_info);
    }
}

/* Enumerate the System registry files and save the results to
 * class member variables.
 * @returns -1 on error, 0 on success
 */
int RegistryLoader::findSystemRegFiles(TSK_FS_INFO * a_fs_info) {
    const string SYS_REG_FILES_DIR = "/Windows/System32/config";

    //JSONWriter::getInstance().writeProgressRecord("Searching for system registry files");

    TSKFileNameInfo filenameInfo;
    TSK_FS_FILE *fsFile;
    int8_t retval = TskHelper::getInstance().path2Inum(a_fs_info, SYS_REG_FILES_DIR.c_str(), filenameInfo, NULL, &fsFile);
    if (retval == -1) {
        string errMsg = "Error in finding system Registry files. System Registry files will not be analyzed.";
        stringstream detailsSS;
        detailsSS << "findSystemRegFiles(): tsk_fs_path2inum() failed for dir = " << SYS_REG_FILES_DIR << ", errno = " << tsk_error_get();
        //CyberTriageUtils::getInstance().logError(ERRORTYPE::ET_MAJOR, errMsg, detailsSS.str());
        return -1;
    }
    else if (retval > 0) { // not found   // @@@ ACTUALLY CHECK IF IT IS #2
        //CyberTriageUtils::DEBUG_PRINT("File System at Offset " + to_string(a_fs_info->offset) + " did not have windows/system32/config folder");
        return 0;
    }

    // open the directory
    TSK_FS_DIR *fs_dir;
    if ((fs_dir = tsk_fs_dir_open_meta(a_fs_info, filenameInfo.getINUM())) == NULL) {
        string errMsg = "Error opening windows/system32/config folder. Some System Registry files may not be analyzed.";
        stringstream detailsSS;
        detailsSS << "findSystemRegFiles(): tsk_fs_dir_open_meta() failed for windows/system32/config folder.  dir inum = " << filenameInfo.getINUM() << ", errno = " << tsk_error_get();
        //JSONWriter::getInstance().writeErrorRecord(ERRORTYPE::ET_WARNING, errMsg, detailsSS.str());
        return -1;
    }

    // cycle through each directory entry
    for (size_t i = 0; i < tsk_fs_dir_getsize(fs_dir); i++) {

        TSK_OFF_T off = 0;
        size_t len = 0;

        // get the entry
        const TSK_FS_NAME *fs_name;
        if ((fs_name = tsk_fs_dir_get_name(fs_dir, i)) == NULL) {
            string errMsg = "Error in finding System Registry files. Some System Registry files may not be analyzed.";
            stringstream detailsSS;
            detailsSS << "findSystemRegFiles(): Error getting directory entry = " << i << " in dir inum = " << filenameInfo.getINUM() << ", errno = " << tsk_error_get() << ", some System Registry files may not be analyzed.";

            //CyberTriageUtils::getInstance().logError(ERRORTYPE::ET_MINOR, errMsg, detailsSS.str());
            continue;
        }

        if (((fs_name->flags & TSK_FS_META_FLAG_ALLOC) == 0) || (fs_name->type != TSK_FS_NAME_TYPE_REG)) {
            continue;
        }

        string fName = fs_name->name;
        if ((0 == _stricmp("SYSTEM", fName.c_str())) || (0 == _stricmp("SOFTWARE", fName.c_str())) ||
            (0 == _stricmp("SECURITY", fName.c_str())) || (0 == _stricmp("SAM", fName.c_str()))) {

            RegHiveType::Enum hiveType = RegFileInfo::hiveNameToType(fName);

            // @@ FIX THE ERROR MSGS HERE
            TSK_FS_FILE *fs_file;
            if ((fs_file = tsk_fs_dir_get(fs_dir, i)) == NULL) {
                string errMsg = "Error in loading Registry file. The Registry file will not be analyzed.";
                stringstream detailsSS;
                detailsSS << "findSystemRegFiles(): tsk_fs_dir_get failed for file = " << fs_file->name->name;
                //JSONWriter::getInstance().writeErrorRecord(ERRORTYPE::ET_MAJOR, errMsg, detailsSS.str());
                continue;
            }

            //CyberTriageUtils::DEBUG_PRINT("findSystemRegFiles: Loading hive");
            RegParser *pRegParser = new RegParser(hiveType);
            if (0 != pRegParser->loadHive(fs_file, hiveType)) {
                string errMsg = "Error in loading Registry file. The Registry file will not be analyzed.";
                stringstream detailsSS;
                detailsSS << "findSystemRegFiles(): loadHive() failed for file = " << fs_file->name->name;
                //JSONWriter::getInstance().writeErrorRecord(ERRORTYPE::ET_MAJOR, errMsg, detailsSS.str());
                continue;
            }

            RegFileInfo *pRegFileInfo = new RegFileInfo(fName, toNormalizedOutputPathName(SYS_REG_FILES_DIR.c_str()), hiveType, fs_file->fs_info->offset, fs_file->meta->addr, pRegParser);

            m_regSystemFiles.push_back(pRegFileInfo);
            tsk_fs_file_close(fs_file);
        }

    } // for

    tsk_fs_dir_close(fs_dir);

    return 0;
}

/** Enumerate the user registry hives in a given file system.
 * results are saved to class member variables.
 * @returns -1 on error and 0 on success
 */
int RegistryLoader::findUserRegFiles(TSK_FS_INFO * a_fs_info) {
    //JSONWriter::getInstance().writeProgressRecord("Searching for user registry files");

    const string XP_USER_ROOT_DIR = "/Documents and Settings";
    const string WIN7_USER_ROOT_DIR = "/Users";

    // expect one will fail and the other will hopefully succeed
    int rc1 = findUserRegFiles(a_fs_info, XP_USER_ROOT_DIR.c_str());
    int rc2 = findUserRegFiles(a_fs_info, WIN7_USER_ROOT_DIR.c_str());

    return (rc1 == 0 || rc2 == 0) ? 0 : -1;
}

/** Enumerate the user registry hives in a given user folder.  Goes recursively into them.
 * Results are saved to class member variables.
 * @returns -1 on error, 0 on success (NOTE THERE IS A BUG IN THE CODE)
 */

int RegistryLoader::findUserRegFiles(TSK_FS_INFO * a_fs_info, const string a_starting_dir) {

    TSK_FS_DIR *fs_dir;
    TSKFileNameInfo filenameInfo;
    TSK_FS_FILE *fsFile;
    int8_t retval = TskHelper::getInstance().path2Inum(a_fs_info, a_starting_dir.c_str(), filenameInfo, NULL, &fsFile);

    if (retval == -1) {
        string errMsg = "Error in finding User Registry files. Some User Registry files may not be analyzed.";
        stringstream detailsSS;
        detailsSS << "findUserRegFiles(): tsk_fs_path2inum() failed for dir = " << a_starting_dir << ", errno = " << tsk_error_get();
        //JSONWriter::getInstance().writeErrorRecord(ERRORTYPE::ET_WARNING, errMsg, detailsSS.str());
        return -1;
    }
    else if (retval > 0) { // not found
        return 0;
    }

    // open the directory
    if ((fs_dir = tsk_fs_dir_open_meta(a_fs_info, filenameInfo.getINUM())) == NULL) {
        string errMsg = "Error in finding User Registry files. Some User Registry files may not be analyzed.";
        stringstream detailsSS;
        detailsSS << "findUserRegFiles(): tsk_fs_dir_open_meta() failed for dir = " << a_starting_dir << ", errno = " << tsk_error_get();
        //JSONWriter::getInstance().writeErrorRecord(ERRORTYPE::ET_MAJOR, errMsg, detailsSS.str());
        return -1;
    }

    // cycle through each (user folder) directory entry
    for (size_t i = 0; i < tsk_fs_dir_getsize(fs_dir); i++) {
        TSK_FS_FILE *fs_file;
        TSK_OFF_T off = 0;
        size_t len = 0;

        // get the entry
        if ((fs_file = tsk_fs_dir_get(fs_dir, i)) == NULL) {
            string errMsg = "Error in finding User Registry files. Some User Registry files may not be analyzed.";
            stringstream detailsSS;
            detailsSS << "findUserRegFiles(): Error getting directory entry = " << i << " in dir inum = " << filenameInfo.getINUM() << ", errno = " << tsk_error_get();;
            //CyberTriageUtils::getInstance().logError(ERRORTYPE::ET_MINOR, errMsg, detailsSS.str());
            continue;
        }

        if (fs_file->meta) {
            if (fs_file->meta->type == TSK_FS_META_TYPE_DIR) {
                if (TSK_FS_ISDOT(fs_file->name->name) == 0) {

                    // @@@ We are ignoring the return value here...  Only the last value will be returned
                    retval = findNTUserRegFilesInDir(a_fs_info, fs_file->name->meta_addr, a_starting_dir, fs_file->name->name);

                    string userHomeDirPath = a_starting_dir + "/" + fs_file->name->name;
                    retval = findUsrclassRegFile(a_fs_info, userHomeDirPath);
                }
            }
        }

        tsk_fs_file_close(fs_file);
    } // for

    return retval;
}

/** Enumerates NTUSER.dat files in a given folder.  Does not go recursive.
 * Results are stored in member class variables.
 * @param a_fs_info File system being analyzed
 * @param a_dir_inum Metadata address for user directory.
 * @param a_userFolderPath Path to user folder
 * @param aUserDirName Name of user for folder
 * @returns -1 on error and 0 on success
 */
int RegistryLoader::findNTUserRegFilesInDir(TSK_FS_INFO * a_fs_info, TSK_INUM_T a_dir_inum, const string& a_userFolderPath, const string aUserDirName) {
    TSK_FS_DIR *fs_dir;

    // 1. open the directory
    if ((fs_dir = tsk_fs_dir_open_meta(a_fs_info, a_dir_inum)) == NULL) {
        string errMsg = "Error in finding NTUSER Registry files. Some User Registry files may not be analyzed.";

        stringstream detailsSS;
        detailsSS << "findNTUserRegFilesInDir(): tsk_fs_dir_open_meta() failed for dir = " << aUserDirName << ", errno = " << tsk_error_get();

        //JSONWriter::getInstance().writeErrorRecord(ERRORTYPE::ET_WARNING, errMsg, detailsSS.str());
        return -1;
    }

    // 2. cycle through each directory entry
    for (size_t i = 0; i < tsk_fs_dir_getsize(fs_dir); i++) {

        TSK_OFF_T off = 0;
        size_t len = 0;

        // get the entry
        const TSK_FS_NAME *fs_name;
        if ((fs_name = tsk_fs_dir_get_name(fs_dir, i)) == NULL) {
            string errMsg = "Error in finding NTUSER Registry files. Some User Registry files may not be analyzed.";
            stringstream detailsSS;
            detailsSS << "findNTUserRegFilesInDir(): Error getting directory entry = " << i << " in dir inum = " << a_dir_inum << ", errno = " << tsk_error_get();
            //CyberTriageUtils::getInstance().logError(ERRORTYPE::ET_MAJOR, errMsg, detailsSS.str());
            continue;
        }

        if (((fs_name->flags & TSK_FS_META_FLAG_ALLOC) == 0) || (fs_name->type != TSK_FS_NAME_TYPE_REG)) {
            continue;
        }

        if ((0 == _stricmp("NTUSER.DAT", fs_name->name))) {
            string fName = fs_name->name;
            RegHiveType::Enum hiveType = RegFileInfo::hiveNameToType(fName);

            TSK_FS_FILE *fs_file;
            if ((fs_file = tsk_fs_dir_get(fs_dir, i)) == NULL) {
                string errMsg = "Error in loading Registry file. The Registry file will not be analyzed.";
                stringstream detailsSS;
                detailsSS << "findNTUserRegFilesInDir(): tsk_fs_dir_get() failed for file = " << fs_file->name->name;
                //JSONWriter::getInstance().writeErrorRecord(ERRORTYPE::ET_MAJOR, errMsg, detailsSS.str());
                continue;
            }

           // CyberTriageUtils::DEBUG_PRINT("analyzeRegFilesSystemInfo: Loading hive");
            RegParser *pRegParser = new RegParser(hiveType);
            if (0 != pRegParser->loadHive(fs_file, hiveType)) {
                string errMsg = "Error in loading Registry file. The Registry file will not be analyzed.";
                stringstream detailsSS;
                detailsSS << "findNTUserRegFilesInDir(): loadHive() failed for file = " << fs_file->name->name;
               // JSONWriter::getInstance().writeErrorRecord(ERRORTYPE::ET_MAJOR, errMsg, detailsSS.str());
                continue;
            }
            RegFileInfo *pRegFileInfo = new RegFileInfo(fName, toNormalizedOutputPathName(a_userFolderPath + "/" + aUserDirName), hiveType, fs_file->fs_info->offset, fs_file->meta->addr, pRegParser);

            // assume the folder name where the REG file is found is the username 
            if (aUserDirName.length() > 0) {
                if (_stricmp(aUserDirName.c_str(), "All Users") != 0) { // thats not a real username

                    string userName("");
                    size_t dotPos = aUserDirName.find_first_of(".");
                    if (string::npos != dotPos) {
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
 * @param a_fs_info File system being analyzed
 * @param aUserDirPathName Path to user folder
 * @returns -1 on error and 0 on success
 */
int RegistryLoader::findUsrclassRegFile(TSK_FS_INFO * a_fs_info, const string aUserDirPathName) {

    // Look for usrclass.dat
    const string WIN7_USRCLASS_SUBDIR = "/AppData/Local/Microsoft/Windows";
    const string XP_USRCLASS_SUBDIR = "/Local Settings/Application Data/Microsoft/Windows";

    string usrClassSubdir("");
    if (TskHelper::startsWith(aUserDirPathName, "/Users")) {
        usrClassSubdir = aUserDirPathName + WIN7_USRCLASS_SUBDIR;
    }
    else {
        usrClassSubdir = aUserDirPathName + XP_USRCLASS_SUBDIR;
    }

    TSKFileNameInfo filenameInfo;
    TSK_FS_FILE *fsFile;
    int8_t retval = TskHelper::getInstance().path2Inum(a_fs_info, usrClassSubdir.c_str(), filenameInfo, NULL, &fsFile);

    if (retval == -1) {
        string errMsg = "Error in finding USRCLASS Registry files. Some User Registry files may not be analyzed.";
        stringstream detailsSS;
        detailsSS << "findUsrclassRegFile(): tsk_fs_path2inum() failed for dir = " << usrClassSubdir << ", errno = " << tsk_error_get();
        //CyberTriageUtils::getInstance().logError(ERRORTYPE::ET_MINOR, errMsg, detailsSS.str());
        return -1;
    }
    else if (retval == 0) {     //  found

        TSK_FS_DIR *fs_dir;

        // open the directory
        if ((fs_dir = tsk_fs_dir_open_meta(a_fs_info, filenameInfo.getINUM())) == NULL) {
            string errMsg = "Error in finding USRCLASS Registry files. Some User Registry files may not be analyzed.";
            stringstream detailsSS;
            detailsSS << "findUsrclassRegFile(): tsk_fs_dir_open_meta() failed for dir inum = " << filenameInfo.getINUM() << ", errno = " << tsk_error_get();
            //JSONWriter::getInstance().writeErrorRecord(ERRORTYPE::ET_MINOR, errMsg, detailsSS.str());
            return -1;
        }

        // cycle through each directory entry
        for (size_t i = 0; i < tsk_fs_dir_getsize(fs_dir); i++) {
            TSK_FS_FILE *fs_file;
            TSK_OFF_T off = 0;
            size_t len = 0;

            // get the entry
            if ((fs_file = tsk_fs_dir_get(fs_dir, i)) == NULL) {
                string errMsg = "Error in finding USRCLASS Registry files. Some User Registry files may not be analyzed.";
                stringstream detailsSS;
                detailsSS << "findUsrclassRegFile(): Error getting directory entry = " << i << " in dir inum = " << filenameInfo.getINUM() << ", errno = " << tsk_error_get();
                //CyberTriageUtils::getInstance().logError(ERRORTYPE::ET_MINOR, errMsg, detailsSS.str());
                continue;
            }

            // make sure it's got metadata and not only a name
            if (fs_file->meta) {
                if ((fs_file->meta->type == TSK_FS_META_TYPE_REG) && (fs_file->meta->flags & TSK_FS_META_FLAG_ALLOC)) {
                    if (fs_file->name) {
                        string fName = fs_file->name->name;

                        if ((0 == _stricmp("USRCLASS.DAT", fName.c_str()))) {

                            RegHiveType::Enum hiveType = RegFileInfo::hiveNameToType(fName);

                            //CyberTriageUtils::DEBUG_PRINT("findUsrclassRegFile: Loading hive");
                            RegParser *pRegParser = new RegParser(hiveType);
                            if (0 != pRegParser->loadHive(fs_file, hiveType)) {
                                string errMsg = "Error in loading Registry file. The Registry file will not be analyzed.";
                                stringstream detailsSS;
                                detailsSS << "findUsrclassRegFile(): loadHive() failed for file = " << fs_file->name->name;
                               // JSONWriter::getInstance().writeErrorRecord(ERRORTYPE::ET_MAJOR, errMsg, detailsSS.str());
                                return -1;
                            }
                            RegFileInfo *pRegFileInfo = new RegFileInfo(fName, toNormalizedOutputPathName(usrClassSubdir), hiveType, fs_file->fs_info->offset, fs_file->meta->addr, pRegParser);

                            // determine the user for this file, from the homedir name
                            string userName("");
                            string aUserDirName("");

                            size_t lastSlashPos = aUserDirPathName.find_last_of("/");
                            if ((string::npos != lastSlashPos)) {
                                aUserDirName = aUserDirPathName.substr(lastSlashPos + 1);
                            }
                            size_t dotPos = aUserDirName.find_first_of(".");
                            if (string::npos != dotPos) {
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
