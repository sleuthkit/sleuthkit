/*
 ** tsk_logical_imager
 ** The Sleuth Kit
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2019 Basis Technology.  All Rights reserved
 **
 ** This software is distributed under the Common Public License 1.0
 **
 */

#include <iostream>
#include <conio.h>
#include <string>
#include <list>
#include <algorithm>
#include <locale>
#include <codecvt>
#include <direct.h>
#include <winsock2.h>
#include <locale.h>
#include <Wbemidl.h>
#include <shlwapi.h>
#include <fstream>
#include <winbase.h>

#pragma comment(lib, "wbemuuid.lib")

#include <comutil.h>

#include "tsk/tsk_tools_i.h"
#include "tsk/auto/tsk_case_db.h"
#include "tsk/img/img_writer.h"
#include "LogicalImagerConfiguration.h"
#include "LogicalImagerRuleSet.h"
#include "TskFindFiles.h"
#include "TskHelper.h"
#include "RegistryAnalyzer.h"

#include "DriveUtil.h"
#include "ReportUtil.h"
#include "FileExtractor.h"

static TSK_TCHAR *progname;
bool createVHD = false;

static std::wstring cwd;

static std::string outputLocation;
static FileExtractor *fileExtractor = NULL;

/**
* isWinXPOrOlder: Determine if we are on Windows XP or older OS
*
* @returns  TRUE if running on Windows XP or older
*           FALSE otherwise
*
*/
static BOOL isWinXPOrOlder() {
    OSVERSIONINFO vi;
    memset(&vi, 0, sizeof vi);
    vi.dwOSVersionInfoSize = sizeof vi;
    GetVersionEx(&vi);
    unsigned int m_winntVerMajor = vi.dwMajorVersion;
    unsigned int m_winntVerMinor = vi.dwMinorVersion;

    return((m_winntVerMajor <= 5));
}

/**
* isProcessElevated: Determine if this process as admin privs.
*
* https://stackoverflow.com/questions/8046097/how-to-check-if-a-process-has-the-administrative-rights
*
* @returns  TRUE if process is elevated
*           FALSE otherwise
*
*/
static BOOL isProcessElevated() {
    static BOOL fRet = FALSE;
    HANDLE hToken = NULL;

    // the below logic doesn't work on XP, so lie and say
    // yes.  It will eventually fail with an uglier message
    // is Windows XP or older?
    if (isWinXPOrOlder()) {
        return TRUE;
    }

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION Elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
            fRet = Elevation.TokenIsElevated;
        }
    }
    if (hToken) {
        CloseHandle(hToken);
    }
    return fRet;
}

/**
* getLocalHost: Get the localhost name
*
* @param a_hostName - the localhost name
* @returns  0 on success
*           -1 if error
*
*/
static int getLocalHost(string &a_hostName) {

    // Initialize Winsock
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        ReportUtil::consoleOutput(stderr, "WSAStartup failed with error = %d\n", iResult);
        return -1;
    }

    char buf[MAX_PATH];
    if (gethostname(buf, sizeof(buf)) == SOCKET_ERROR) {
        ReportUtil::consoleOutput(stderr, "Error getting host name. Error =  %d\n", WSAGetLastError());
        return -1;
    }
    a_hostName = string(buf);

    WSACleanup();
    return 0;
}

/**
* createDirectory: Create a directory relative to current working directory for host. 
*
* @param [out] directoryPathname - the directory pathname created
* @returns  0 on success
*           -1 if error
*
*/
static int createSessionDirectory(string &directoryPathname) {
    time_t now;
    struct tm localTime;

    time(&now);
    gmtime_s(&localTime, &now);

    char timeStr[32];
    strftime(timeStr, sizeof timeStr, "%Y%m%d_%H_%M_%S", &localTime);

    string outDirName;
    string hostName;
    if (0 == getLocalHost(hostName)) {
        outDirName = "Logical_Imager_" + hostName + "_" + timeStr;
    }

    struct stat st;
    if (stat(outDirName.c_str(), &st) != 0) {
        int rc = _mkdir(outDirName.c_str());
        if (rc != 0) {
            ReportUtil::consoleOutput(stderr, "Failed to create output folder = %s Error: %d\n", outDirName.c_str(), rc);
            return -1;
        }
    }
    directoryPathname = outDirName;
    return 0;
}

/**
* getDrivesToProcess() - returns the drives to process
*          By default we process all available PhysicalDrives, unless
*          a drive is paritioned with LDM or has Bitlocker enabled, in which case we
*          enumerate all drive letters.
*
* @param output a set of drivesToProcess
*
* @returns  TRUE on success or FALSE in case of failure.
*
*/
static BOOL getDrivesToProcess(std::vector<std::wstring> &drivesToProcess) {

    // check if they are admin before we give them some ugly error messages
    if (isProcessElevated() == FALSE) {
        return FALSE;
    }

    string systemDriveLetter;
    bool status = false;

    // Detect if we have a BitLocker or LDM drive amount all drives
    for (int iDrive = 0; iDrive < 26; iDrive++) {
        char szDrive[_MAX_DRIVE + 1];
        sprintf(szDrive, "%c:\\", iDrive + 'A');
        UINT uDriveType = GetDriveTypeA(szDrive);
        if (uDriveType == DRIVE_FIXED || uDriveType == DRIVE_REMOVABLE) {
            sprintf(szDrive, "%c:", iDrive + 'A');
            systemDriveLetter = szDrive;
            status |= DriveUtil::hasBitLockerOrLDM(systemDriveLetter);
            if (status) {
                break;
            }
        }
    }
    if (status) {
        // Some of the drives has BitLocker or LDM, enumerate all driver letters
        for (int iDrive = 0; iDrive < 26; iDrive++) {
            char szDrive[_MAX_DRIVE + 1];
            sprintf(szDrive, "%c:\\", iDrive + 'A');
            UINT uDriveType = GetDriveTypeA(szDrive);
            if (uDriveType == DRIVE_FIXED || uDriveType == DRIVE_REMOVABLE) {
                sprintf(szDrive, "%c:", iDrive + 'A');
                systemDriveLetter = szDrive;
                drivesToProcess.push_back(TskHelper::toWide(systemDriveLetter));
            }
        }
        return TRUE;
    } else {
        // None of the drives has BitLocker or LDM, try all physical drives
        drivesToProcess.clear();
        if (DriveUtil::getPhysicalDrives(drivesToProcess)) {
            return TRUE;
        }
    }
    return FALSE;
}

/**
* hasTskLogicalImage - test if /tsk_logical_image.exe is in the image/drive
*
* @return true if found, false otherwise
*/
static bool hasTskLogicalImager() {
    bool result = false;

    const std::list<TSK_FS_INFO *> fsList = TskHelper::getInstance().getFSInfoList();
    TSKFileNameInfo filenameInfo;
    std::list<std::string> pathForTskLogicalImagerExe;
    pathForTskLogicalImagerExe.push_back("/tsk_logical_imager.exe");
    const std::list<std::string> filePaths(pathForTskLogicalImagerExe);
    TSK_FS_FILE *fs_file;
    for (std::list<TSK_FS_INFO *>::const_iterator fsListIter = fsList.begin(); fsListIter != fsList.end(); ++fsListIter) {
        for (std::list<std::string>::const_iterator iter = filePaths.begin(); iter != filePaths.end(); ++iter) {
            int retval = TskHelper::getInstance().path2Inum(*fsListIter, iter->c_str(), false, filenameInfo, NULL, &fs_file);
            if (retval == 0 && fs_file != NULL && fs_file->meta != NULL) {
                // found it
                result = true;
                tsk_fs_file_close(fs_file);
                break;
            }
            tsk_fs_file_close(fs_file);
        }
        if (result) {
            break;
        }
    }
    TskHelper::getInstance().reset();
    return result;
}

/*
* matchCallback - The function is passed into the LogicalImagerConfiguration.
*                 It is called when a file matches a rule. Depending on the matchedRuleInfo setting,
*                 this function may extract the matched file and alert the user.
*
* @param matchedRuleInfo The MatchedRuleInfo
* @param fs_file TSK_FS_FILE that matches the rule
* @param path Path of the file
*
* @returns TSK_IMG_TYPE_ENUM TSK_OK if callback has no error
*/
static TSK_RETVAL_ENUM matchCallback(const MatchedRuleInfo *matchedRuleInfo, TSK_FS_FILE *fs_file, const char *path) {
    TSK_RETVAL_ENUM extractStatus = TSK_ERR;
    std::string extractedFilePath;

    if (matchedRuleInfo->isShouldSave()) {
        extractStatus = fileExtractor->extractFile(fs_file, path, extractedFilePath);
    }
    ReportUtil::reportResult(outputLocation, extractStatus, matchedRuleInfo, fs_file, path, extractedFilePath);
    return TSK_OK;
}

/*
* getFilename - return the filename portion of the fullPath
*               The path separator is '/'
*
* @param fullPath The full path to a file
*
* @return filename portion of the fullPath
*/
string getFilename(const string &fullPath) {
    char sep = '/';
    size_t i = fullPath.rfind(sep, fullPath.length());
    if (i != string::npos) {
        return fullPath.substr(i + 1, string::npos);
    }
    return fullPath;
}

/*
* getPathName - return the path name portion of the fullPath
*               The path separator is '/'
*
* @param fullPath The full path to a file
*
* @return path name portion of the fullPath, or empty string there is no path name
*/
string getPathName(const string &fullPath) {
    char sep = '/';
    size_t i = fullPath.rfind(sep, fullPath.length());
    if (i != string::npos) {
        return fullPath.substr(0, i);
    }
    return "";
}

/**
* Search for files that were specified by full path.
* @param config Configuration that contains rules and other settings
* @param driveName Name of drive being processed (for display only)
*/

static void searchFilesByFullPath(LogicalImagerConfiguration *config, const std::string &driveName) {
    ReportUtil::consoleOutput(stdout, "%s - Searching for full path files\n", driveName.c_str());
    SetConsoleTitleA(std::string("Analyzing drive " + driveName + " - Searching for full path files").c_str());

    const std::list<TSK_FS_INFO *> fsList = TskHelper::getInstance().getFSInfoList();

    // cycle over each FS in the image
    for (std::list<TSK_FS_INFO *>::const_iterator fsListIter = fsList.begin(); fsListIter != fsList.end(); ++fsListIter) {
        
        // cycle over the rule sets
        const std::vector<std::pair<const MatchedRuleInfo *, std::list<std::string>>> fullFilePathsRules = config->getFullFilePaths();
        for (std::vector<std::pair<const MatchedRuleInfo *, std::list<std::string>>>::const_iterator ruleSetIter = fullFilePathsRules.begin(); ruleSetIter != fullFilePathsRules.end(); ++ruleSetIter) {
            const MatchedRuleInfo *matchedRuleInfo = ruleSetIter->first;
            const std::list<std::string> filePathsInSet = ruleSetIter->second;

            // cycle over each path in the set
            for (std::list<std::string>::const_iterator filePathIter = filePathsInSet.begin(); filePathIter != filePathsInSet.end(); ++filePathIter) {
                TSK_FS_FILE *fs_file;
                TSK_FS_NAME *fs_name = tsk_fs_name_alloc(1024, 16);
                TSKFileNameInfo filenameInfo;
                int retval = TskHelper::getInstance().path2Inum(*fsListIter, filePathIter->c_str(), false, filenameInfo, fs_name, &fs_file);
                if (retval == 0 && fs_file != NULL) {
                    std::string parent = getPathName(*filePathIter);
                    fs_file->name = fs_name;
                    matchCallback(matchedRuleInfo, fs_file, parent.c_str());
                }
                tsk_fs_name_free(fs_name);
                tsk_fs_file_close(fs_file);
            }
        }
    }
}

/**
* Search for the files that were specified by attributes (extensions, etc.)
* @param config COnfiguration with rules
* @param driveName Display name of drive being processed
* @param img_info Handle to open TSK image
*/
static void searchFilesByAttribute(LogicalImagerConfiguration *config, const std::string &driveName, TSK_IMG_INFO *img_info) {
    TskFindFiles findFiles(config, driveName);
    if (findFiles.openImageHandle(img_info)) {
        tsk_error_print(stderr);
        ReportUtil::consoleOutput(stderr, "Failed to open imagePath\n");
        ReportUtil::handleExit(1);
    }

    ReportUtil::consoleOutput(stdout, "%s - Searching for files by attribute\n", driveName.c_str());
    SetConsoleTitleA(std::string("Analyzing drive " + driveName + " - Searching for files by attribute").c_str());

    if (findFiles.findFilesInImg()) {
        // we already logged the errors in findFiles.handleError()
        // Don't exit, just let it continue
    }
}

/**
* Searches for hives and reports on users
* @param sessionDir Directory to create user file in
* @param driveName Display name of drive being processed.
*/
static void reportUsers(const std::string &sessionDir, const std::string &driveName) {
    ReportUtil::consoleOutput(stdout, "%s - Searching for registry\n", driveName.c_str());
    SetConsoleTitleA(std::string("Analyzing drive " + driveName + " - Searching for registry").c_str());

    // Enumerate Users with RegistryAnalyzer
    std::string driveLetter = driveName;
    if (TskHelper::endsWith(driveName, ":")) {
        driveLetter = driveName.substr(0, driveName.length() - 1);
    }
    std::string userFilename = sessionDir + "/" + driveLetter + "_users.txt";
    RegistryAnalyzer registryAnalyzer(userFilename);
    registryAnalyzer.analyzeSAMUsers();
}




static void usage() {
    TFPRINTF(stderr,
        _TSK_T
        ("usage: %s [-c configPath]\n"),
        progname);
    tsk_fprintf(stderr, "\t-c configPath: The configuration file. Default is logical-imager-config.json\n");
    tsk_fprintf(stderr, "\t-v: verbose output to stderr\n");
    tsk_fprintf(stderr, "\t-V: Print version\n");
    ReportUtil::handleExit(1);
}

int
main(int argc, char **argv1)
{
    TSK_IMG_TYPE_ENUM imgtype = TSK_IMG_TYPE_DETECT;

    int ch;
    TSK_TCHAR **argv;
    const TSK_TCHAR *imgPathArg = NULL; // set to image path if user specified on command line
    TSK_TCHAR *configFilename = (TSK_TCHAR *) NULL;
    LogicalImagerConfiguration *config = NULL;

    // NOTE: The following 2 calls are required to print non-ASCII UTF-8 strings to the Console.
    // fprintf works, std::cout does not. Also change the font in the Console to SimSun-ExtB to
    // display most non-ASCII characters (tested with European, Japanese, Chinese, Korean, Greek,
    // Arabic, Hebrew and Cyrillic strings).
    SetConsoleOutputCP(65001); // Set the CMD Console to Unicode codepage
    setlocale(LC_ALL, "en_US.UTF-8"); // Set locale to English and UTF-8 encoding.

#ifdef TSK_WIN32
    // On Windows, get the wide arguments (mingw doesn't support wmain)
    argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv == NULL) {
        ReportUtil::consoleOutput(stderr, "Error getting wide arguments\n");
        ReportUtil::handleExit(1);
    }
#else
    argv = (TSK_TCHAR **)argv1;
#endif
    progname = argv[0];

    while ((ch = GETOPT(argc, argv, _TSK_T("c:i:vV"))) > 0) {
        switch (ch) {
        case _TSK_T('?'):
        default:
            TFPRINTF(stderr, _TSK_T("Invalid argument: %s\n"),
                argv[OPTIND-1]);
            usage();

        case _TSK_T('c'):
            configFilename = OPTARG;
            break;

        case _TSK_T('v'):
            tsk_verbose++;
            break;

        case _TSK_T('V'):
            tsk_version_print(stdout);
            exit(0);

        // undocumented.  Used for testing only.
        case _TSK_T('i'):
            imgPathArg = OPTARG;
            break;
        }
    }

    // If there is extra argument, bail out.
    if (OPTIND != argc) {
        usage();
    }


    ////////////////////////////////////////////////////////
    // Load the configuration file
    if (configFilename == NULL) {
        configFilename = _TSK_T("logical-imager-config.json");
        ReportUtil::consoleOutput(stdout, "Using default configuration file logical-imager-config.json\n");
    }
    ReportUtil::printDebug("Using config file %s", TskHelper::toNarrow(configFilename).c_str());

    try {
        config = new LogicalImagerConfiguration(TskHelper::toNarrow(configFilename), (LogicalImagerRuleSet::matchCallback)matchCallback);
        ReportUtil::SetPromptBeforeExit(config->getPromptBeforeExit());
        createVHD = config->getCreateVHD();
    }
    catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
        ReportUtil::handleExit(1);
    }

    // If CWD is FAT, exit with error because it cannot create files greater 4 GB
    if (DriveUtil::cwdIsFAT(cwd)) {
        ReportUtil::consoleOutput(stderr, "Error: Writing to FAT device is not supported.\n");
        ReportUtil::handleExit(1);
    }


    //////////////////////////////////////////////////////
    // Enumerate what we are going to analyze

    // these two vectors should be kept in sync and each entry should correspond to an entry in the other at the same offset
    std::vector<std::wstring> imgShortNames; // short name of data
    std::vector<std::wstring> imgPaths; // full path for data to analyze

    if (imgPathArg != NULL) {
        // @@@ Ideally, we'd just store the name of the image here and strip out parent folder
        imgShortNames.push_back(imgPathArg);
        imgPaths.push_back(imgPathArg);
    } else {
        if (getDrivesToProcess(imgShortNames)) {
            ReportUtil::printDebug("Process is running in elevated mode");
            for (auto it = std::begin(imgShortNames); it != std::end(imgShortNames); ++it) {
                imgPaths.push_back(std::wstring(L"\\\\.\\") + *it);
            }
        }
        else {
            ReportUtil::consoleOutput(stderr, "Process is not running in elevated mode\n");
            ReportUtil::handleExit(1);
        }
    }


    /////////////////////////////////////////////////////////////////////
    // Now that we've verified everything, let's make an output folder
    // create a directory with hostname_timestamp
    std::string sessionDir;
    if (createSessionDirectory(sessionDir) == -1) {
        ReportUtil::consoleOutput(stderr, "Failed to create directory %s\n", sessionDir.c_str());
        ReportUtil::handleExit(1);
    }

    ReportUtil::initialize(sessionDir);

    ReportUtil::consoleOutput(stdout, "Created directory %s\n", sessionDir.c_str());
    ReportUtil::copyConfigFile(configFilename);

    std::list<std::pair<TSK_IMG_INFO *, std::string>> imgFinalizePending;
    fileExtractor = new FileExtractor(createVHD, cwd, sessionDir);

    // Loop through all images
    for (size_t i = 0; i < imgPaths.size(); ++i) {
        const TSK_TCHAR *imagePath = (TSK_TCHAR *)imgPaths[i].c_str();
        std::string imageShortName = TskHelper::toNarrow(imgShortNames[i]);

        ReportUtil::printDebug("Processing drive %s", imageShortName.c_str());
        ReportUtil::consoleOutput(stdout, "Analyzing drive %zi of %zu (%s)\n", (size_t) i+1, imgPaths.size(), imageShortName.c_str());
        SetConsoleTitleA(std::string("Analyzing drive " + TskHelper::intToStr((long)i+1) + " of " + TskHelper::intToStr(imgPaths.size()) + " (" + imageShortName + ")").c_str());

        if (DriveUtil::isDriveLocked(imageShortName) == 1) {
            ReportUtil::consoleOutput(stdout, "Skipping drive %s because it is bitlocked.\n", imageShortName.c_str());
            continue;
        }

        TSK_IMG_INFO *img;
        img = TskHelper::addFSFromImage(imagePath);

        if (hasTskLogicalImager()) {
            ReportUtil::consoleOutput(stdout, "Skipping drive %s because tsk_logical_imager.exe exists at the root directory.\n", imageShortName.c_str());
            img->close(img);
            TskHelper::getInstance().reset();
            continue; // Don't process a drive with /tsk_logicial_image.exe at the root
        }

        std::string subDirForFiles;
        if (imgPathArg != NULL) {
            subDirForFiles = "sparse_image";
        } else {
            subDirForFiles = imageShortName;
            // strip final ":"
            if (subDirForFiles.back() == ':') {
                subDirForFiles = subDirForFiles.substr(0, subDirForFiles.size() - 1);
            }
        }
        fileExtractor->initializePerImage(subDirForFiles);
        
        // @@@ SHould probably rename outputLocation for non-VHD files
        outputLocation = subDirForFiles + (createVHD ? ".vhd" : "");

        bool closeImgNow = true;

        // Setup the VHD for this drive (if we are making one)
        if (createVHD) {
            if (img->itype == TSK_IMG_TYPE_RAW) {
                std::string outputFileName = sessionDir + "/" + outputLocation;

                if (tsk_img_writer_create(img, (TSK_TCHAR *)TskHelper::toWide(outputFileName).c_str()) == TSK_ERR) {
                    tsk_error_print(stderr);
                    ReportUtil::consoleOutput(stderr, "Failed to initialize VHD writer\n");
                    ReportUtil::handleExit(1);
                }
                imgFinalizePending.push_back(std::make_pair(img, imageShortName));
                closeImgNow = false;
            }
            else {
                ReportUtil::consoleOutput(stderr, "Input is not a live device or raw imagePath, VHD will not be created\n");
            }
        }

        ////////////////////////////////////////////////
        // Enumerate the file and volume systems that we'll need for the various searches
        TskHelper::getInstance().enumerateFileAndVolumeSystems(img);

        ////////////////////////////////////////////////////////
        // do the work 

        // search for files based on full path
        searchFilesByFullPath(config, imageShortName);

        // Get users
        std::string prefix;
        if (imgPathArg != NULL) {
            prefix = "sparse_image";
        } else {
            prefix = imageShortName;
        }
        reportUsers(sessionDir, prefix);

        // We no longer need the cached files
        TskHelper::getInstance().reset();

        // Full scan of drive for files based on extension, etc.
        searchFilesByAttribute(config, imageShortName, img);
        
        if (closeImgNow) {
            // close the image, if not creating VHD. 
            img->close(img);
        }
    }

    // close report file before tsk_img_writer_finish, which may take a long time.
    ReportUtil::closeReport();

    // Delayed finialize image write
    for (auto it = std::begin(imgFinalizePending); it != std::end(imgFinalizePending); ++it) {
        TSK_IMG_INFO *img = it->first;
        if (img->itype == TSK_IMG_TYPE_RAW) {
            if (createVHD && config->getFinalizeImagerWriter()) {
                ReportUtil::printDebug("finalize imagePath writer for %s", it->second.c_str());
                ReportUtil::consoleOutput(stdout, "Copying remainder of %s\n", it->second.c_str());
                SetConsoleTitleA(std::string("Copying remainder of " + it->second).c_str());
                if (tsk_img_writer_finish(img) == TSK_ERR) {
                    tsk_error_print(stderr);
                    ReportUtil::consoleOutput(stderr, "Error finishing VHD for %s\n", it->second.c_str());
                }
            }
        }
        img->close(img);
    }

    if (config) {
        delete config;
    }
    if (fileExtractor) {
        delete fileExtractor;
    }
    tsk_error_win32_thread_cleanup();
    ReportUtil::printDebug("Exiting");
    ReportUtil::handleExit(0);
}
