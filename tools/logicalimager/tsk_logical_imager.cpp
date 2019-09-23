/*
 ** tsk_logical_imager
 ** The Sleuth Kit
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2010-2011 Brian Carrier.  All Rights reserved
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
std::string directoryPath;
std::wstring cwd;
std::string driveToProcess;
std::string outputLocation;
FileExtractor *fileExtractor = NULL;

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
* createDirectory: Create a directory to store sparse_image.vhd
*
* @param directoryPathname - the directory pathname created
* @returns  0 on success
*           -1 if error
*
*/
static int createDirectory(string &directoryPathname) {
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
* getDrivesToProcess() - returns the drive to process
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
* hasTskLogicalImage - test if /tsk_logical_image.exe is in the image
*
* @param image - path to image
* @return true if found, false otherwise
*/
static bool hasTskLogicalImager(const TSK_TCHAR *image) {
    bool result = false;

    TSK_IMG_INFO *img = DriveUtil::addFSFromImage(image);

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
        }
        if (result) {
            break;
        }
    }
    img->close(img);
    TskHelper::getInstance().reset();
    return result;
}

/*
* matchCallback - The function is passed into the LogicalImagerConfiguration.
*                 It is called when a file matches a rule. Depending on the matchResult setting,
*                 this function may extract the matched file and alert the user.
*
* @param matchResult The RuleMatchResult
* @param fs_file TSK_FS_FILE that matches the rule
* @param path Path of the file
*
* @returns TSK_IMG_TYPE_ENUM TSK_OK if callback has no error
*/
static TSK_RETVAL_ENUM matchCallback(const RuleMatchResult *matchResult, TSK_FS_FILE *fs_file, const char *path) {
    TSK_RETVAL_ENUM extractStatus = TSK_ERR;
    std::string extractedFilePath;

    if (matchResult->isShouldSave()) {
        extractStatus = fileExtractor->extractFile(fs_file, path, extractedFilePath);
    }
    ReportUtil::reportResult(outputLocation, extractStatus, matchResult, fs_file, path, extractedFilePath);
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
    unsigned int ssize = 0;
    std::vector<std::wstring> imgPaths;
    const TSK_TCHAR *imgPath;
    BOOL iFlagUsed = FALSE;
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

        case _TSK_T('i'):
            imgPath = OPTARG;
            iFlagUsed = TRUE;
            break;

        }
    }

    // If there is extra argument, bail out.
    if (OPTIND != argc) {
        usage();
    }

    // If CWD is FAT, exit with error because it cannot create files greater 4 GB
    if (DriveUtil::cwdIsFAT(cwd)) {
        ReportUtil::consoleOutput(stderr, "Error: Writing to FAT device is not supported.\n");
        ReportUtil::handleExit(1);
    }

    if (configFilename == NULL) {
        configFilename = _TSK_T("logical-imager-config.json");
        ReportUtil::consoleOutput(stdout, "Using default configuration file logical-imager-config.json\n");
    }
    ReportUtil::printDebug("Using config file %s", TskHelper::toNarrow(configFilename).c_str());

    std::wstring wImgPathName;
    std::vector<std::wstring> drivesToProcess;

    if (iFlagUsed) {
        imgPaths.push_back(imgPath);
    } else {
        if (getDrivesToProcess(drivesToProcess)) {
            ReportUtil::printDebug("Process is running in elevated mode");
            for (auto it = std::begin(drivesToProcess); it != std::end(drivesToProcess); ++it) {
                imgPaths.push_back(std::wstring(_TSK_T("\\\\.\\")) + *it);
            }
        }
        else {
            ReportUtil::consoleOutput(stderr, "Process is not running in elevated mode\n");
            ReportUtil::handleExit(1);
        }
    }

    try {
        config = new LogicalImagerConfiguration(TskHelper::toNarrow(configFilename), (LogicalImagerRuleSet::matchCallback)matchCallback);
        ReportUtil::SetPromptBeforeExit(config->getPromptBeforeExit());
        createVHD = config->getCreateVHD();
    }
    catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
        ReportUtil::handleExit(1);
    }

    // create a directory with hostname_timestamp
    if (createDirectory(directoryPath) == -1) {
        ReportUtil::consoleOutput(stderr, "Failed to create directory %s\n", directoryPath.c_str());
        ReportUtil::handleExit(1);
    }

    std::string consoleFileName = directoryPath + "/console.txt";
    ReportUtil::openConsoleOutput(consoleFileName);

    ReportUtil::consoleOutput(stdout, "Created directory %s\n", directoryPath.c_str());

    // copy the config file into the output directoryPath
    std::ifstream src(TskHelper::toNarrow(configFilename), std::ios::binary);
    std::ofstream dst(directoryPath + "/config.json", std::ios::binary);
    dst << src.rdbuf();
    dst.close();
    src.close();

    std::string reportFilename = directoryPath + "/SearchResults.txt";
    ReportUtil::openReport(reportFilename);

    std::list<std::pair<TSK_IMG_INFO *, std::string>> imgFinalizePending;
    fileExtractor = new FileExtractor(createVHD, cwd, directoryPath);

    // Loop through all images
    for (size_t i = 0; i < imgPaths.size(); ++i) {
        const TSK_TCHAR *image = (TSK_TCHAR *)imgPaths[i].c_str();
        driveToProcess = iFlagUsed ? TskHelper::toNarrow(imgPaths[i]) : TskHelper::toNarrow(drivesToProcess[i]);
        ReportUtil::printDebug("Processing drive %s", driveToProcess.c_str());
        ReportUtil::consoleOutput(stdout, "Analyzing drive %zi of %zu (%s)\n", (size_t) i+1, imgPaths.size(), driveToProcess.c_str());
        SetConsoleTitleA(std::string("Analyzing drive " + TskHelper::intToStr((long)i+1) + " of " + TskHelper::intToStr(imgPaths.size()) + " (" + driveToProcess + ")").c_str());

        if (DriveUtil::isDriveLocked(driveToProcess) == 1) {
            ReportUtil::consoleOutput(stdout, "Skipping drive %s because it is bitlocked.\n", driveToProcess.c_str());
            continue;
        }

        if (driveToProcess.back() == ':') {
            driveToProcess = driveToProcess.substr(0, driveToProcess.size() - 1);
        }

        if (hasTskLogicalImager(image)) {
            ReportUtil::consoleOutput(stdout, "Skipping drive %s because tsk_logical_imager.exe exists at the root directory.\n", driveToProcess.c_str());
            continue; // Don't process a drive with /tsk_logicial_image.exe at the root
        }

        TSK_IMG_INFO *img;
        if ((img = tsk_img_open(1, &image, imgtype, ssize)) == NULL) {
            tsk_error_print(stderr);
            ReportUtil::handleExit(1);
        }

        std::string subDirForFiles = iFlagUsed ? "sparse_image" : driveToProcess;
        outputLocation = (iFlagUsed ? "sparse_image" : driveToProcess) + (createVHD ? ".vhd" : "");
        if (!createVHD) {
            fileExtractor->initializePerImage(subDirForFiles);
        }

        if (createVHD) {
            if (img->itype == TSK_IMG_TYPE_RAW) {
                std::string outputFileName = directoryPath + "/" + outputLocation;

                if (tsk_img_writer_create(img, (TSK_TCHAR *)TskHelper::toWide(outputFileName).c_str()) == TSK_ERR) {
                    tsk_error_print(stderr);
                    ReportUtil::consoleOutput(stderr, "Failed to initialize VHD writer\n");
                    ReportUtil::handleExit(1);
                }
            }
            else {
                ReportUtil::consoleOutput(stderr, "Image is not a RAW image, VHD will not be created\n");
            }
        }

        imgFinalizePending.push_back(std::make_pair(img, driveToProcess));

        TskFindFiles findFiles(config, driveToProcess);

        TskHelper::getInstance().reset();
        TskHelper::getInstance().setImgInfo(img);
        TSK_VS_INFO *vs_info;
        if ((vs_info = tsk_vs_open(img, 0, TSK_VS_TYPE_DETECT)) == NULL) {
            ReportUtil::printDebug("No volume system found. Looking for file system");
            DriveUtil::openFs(img, 0);
        }
        else {
            // process the volume system
            //fprintf(stdout, "Partition:\n");
            for (TSK_PNUM_T i = 0; i < vs_info->part_count; i++) {
                const TSK_VS_PART_INFO *vs_part = tsk_vs_part_get(vs_info, i);
                //fprintf(stdout, "#%i: %s Start: %s Length: %s\n",
                //    i, vs_part->desc, std::to_string(vs_part->start).c_str(), std::to_string(vs_part->len).c_str());
                if ((vs_part->flags & TSK_VS_PART_FLAG_UNALLOC) || (vs_part->flags & TSK_VS_PART_FLAG_META)) {
                    continue;
                }
                DriveUtil::openFs(img, vs_part->start * vs_part->vs->block_size);
            }
            tsk_vs_close(vs_info);
        }

        ReportUtil::consoleOutput(stdout, "%s - Searching for full path files\n", driveToProcess.c_str());
        SetConsoleTitleA(std::string("Analyzing drive " + driveToProcess + " - Searching for full path files").c_str());

        const std::list<TSK_FS_INFO *> fsList = TskHelper::getInstance().getFSInfoList();
        TSKFileNameInfo filenameInfo;
        const std::vector<std::pair<const RuleMatchResult *, std::list<std::string>>> fullFilePathsRules = config->getFullFilePaths();
        for (std::vector<std::pair<const RuleMatchResult *, std::list<std::string>>>::const_iterator iter = fullFilePathsRules.begin(); iter != fullFilePathsRules.end(); ++iter) {
            const RuleMatchResult *matchResult = iter->first;
            const std::list<std::string> filePaths = iter->second;
            TSK_FS_FILE *fs_file;
            for (std::list<TSK_FS_INFO *>::const_iterator fsListIter = fsList.begin(); fsListIter != fsList.end(); ++fsListIter) {
                for (std::list<std::string>::const_iterator iter = filePaths.begin(); iter != filePaths.end(); ++iter) {
                    int retval = TskHelper::getInstance().path2Inum(*fsListIter, iter->c_str(), false, filenameInfo, NULL, &fs_file);
                    if (retval == 0 && fs_file != NULL) {
                        std::string filename = getFilename(*iter);
                        std::string parent = getPathName(*iter);
                        // create a TSK_FS_NAME for report purpose
                        fs_file->name = new TSK_FS_NAME();
                        fs_file->name->name = (char *)tsk_malloc(strlen(filename.c_str()) + 1);
                        strcpy(fs_file->name->name, filename.c_str());
                        matchCallback(matchResult, fs_file, parent.c_str());

                        tsk_fs_file_close(fs_file);
                    }
                }
            }
        }

        ReportUtil::consoleOutput(stdout, "%s - Searching for registry\n", driveToProcess.c_str());
        SetConsoleTitleA(std::string("Analyzing drive " + driveToProcess + " - Searching for registry").c_str());

        std::string prefix;
        std::string userFilename = "users.txt";
        if (iFlagUsed) {
            prefix = "sparse_image";
        }
        else {
            if (TskHelper::endsWith(driveToProcess, ":")) {
                prefix = driveToProcess.c_str()
            }
            prefix = 
        }
        string usersFileName = directoryPath + "/" + prefix + "users.txt";

        // Enumerate Users with RegistryAnalyzer
        RegistryAnalyzer registryAnalyzer(usersFileName);
        registryAnalyzer.analyzeSAMUsers();

        TskHelper::getInstance().reset();

        if (findFiles.openImageHandle(img)) {
            tsk_error_print(stderr);
            ReportUtil::consoleOutput(stderr, "Failed to open image\n");
            ReportUtil::handleExit(1);
        }

        ReportUtil::consoleOutput(stdout, "%s - Searching for files by attribute\n", driveToProcess.c_str());
        SetConsoleTitleA(std::string("Analyzing drive " + driveToProcess + " - Searching for files by attribute").c_str());

        if (findFiles.findFilesInImg()) {
            // we already logged the errors in findFiles.handleError()
            // Don't exit, just let it continue
        }
    }

    // close report file before tsk_img_writer_finish, which may take a long time.
    ReportUtil::closeReport();

    // Delayed finialize image write
    for (auto it = std::begin(imgFinalizePending); it != std::end(imgFinalizePending); ++it) {
        TSK_IMG_INFO *img = it->first;
        if (img->itype == TSK_IMG_TYPE_RAW) {
            if (createVHD && config->getFinalizeImagerWriter()) {
                ReportUtil::printDebug("finalize image writer for %s", it->second.c_str());
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
    ReportUtil::printDebug("Exiting");
    ReportUtil::handleExit(0);
}
