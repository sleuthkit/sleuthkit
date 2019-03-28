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

#pragma comment(lib, "wbemuuid.lib")

#include <comutil.h>

#include "tsk/tsk_tools_i.h"
#include "tsk/auto/tsk_case_db.h"
#include "tsk/img/img_writer.h"
#include "LogicalImagerRuleSet.h"
#include "TskFindFiles.h"
#include "TskHelper.h"
#include "tsk_logical_imager.h"

std::wstring GetLastErrorStdStrW();
std::string GetErrorStdStr(DWORD err);
std::wstring GetErrorStdStrW(DWORD err);

static TSK_TCHAR *progname;

static std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;

/**
* toUpper: convert string to uppercase
* @param srcStr to convert
* @return uppercase string
*/
string toUpper(const string &srcStr) {
    string outStr(srcStr);
    std::transform(srcStr.begin(), srcStr.end(), outStr.begin(), ::toupper);

    return outStr;
}

/**
* toLower: convert string to lowercase
* @param srcStr to convert
* @return lowercase string
*/
string toLower(const string &srcStr) {
    string outStr(srcStr);
    std::transform(srcStr.begin(), srcStr.end(), outStr.begin(), ::tolower);

    return outStr;
}

/**
* Convert from UTF-16 to UTF-8.
* Returns empty string on error
*/
string toNarrow(const std::wstring& a_utf16Str) {
    try {
        std::string narrow = converter.to_bytes(a_utf16Str);
        return narrow;
    }
    catch (...) {
        std::exception_ptr eptr = std::current_exception();
        return "";
    }
}

/**
* Convert from UTF-8 to UTF-16.
* Returns empty string on error
*/
std::wstring toWide(const string& a_utf8Str) {
    try {
        std::wstring wide = converter.from_bytes(a_utf8Str);
        return wide;
    }
    catch (...) {
        std::exception_ptr eptr = std::current_exception();
        return L"";
    }
}

/**
* GetErrorStdStr - returns readable error message for the given error code
*
* @param err error code
* @returns error message string
*/
string GetErrorStdStr(DWORD err) {
    return toNarrow(GetErrorStdStrW(err));
}

/**
* GetLastErrorStdStrW - returns readable widestring error message for the last error code as reported by GetLastError()
*
* @returns error message wide string
*/
std::wstring GetLastErrorStdStrW() {
    DWORD error = GetLastError();
    return GetErrorStdStrW(error);
}

/**
* GetErrorStdStrW - returns readable widestring error message for the given error code
*
* @param err error code
* @returns error message wide string
*/
std::wstring GetErrorStdStrW(DWORD a_err) {
    if (ERROR_SUCCESS != a_err) {
        LPVOID lpMsgBuf;
        DWORD bufLen = FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            a_err,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPWSTR)&lpMsgBuf,
            0, NULL);
        if (bufLen) {
            LPCWSTR lpMsgStr = (LPCWSTR)lpMsgBuf;

            /***
            LPWSTR p = const_cast<LPWSTR>(_tcschr(lpMsgStr, _T('\r')));
            if(p != NULL) { // lose CRLF
            *p = _T('\0');
            }
            ****/

            std::wstring result(lpMsgStr, lpMsgStr + bufLen);

            size_t pos = result.find_last_not_of(L"\r\n");
            if (pos != std::wstring::npos) {
                result.resize(pos);
            }


            LocalFree(lpMsgBuf);

            return result;
        }
    }
    return std::wstring(L"no error");
}

/**
* isWinXPOrOlder: Determine if we are on Windows XP or older OS
*
* @returns  TRUE if running on Windows XP or older
*           FALSE otherwise
*
*/
BOOL isWinXPOrOlder() {
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
int getLocalHost(string &a_hostName) {

    // Initialize Winsock
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        fprintf(stderr, "WSAStartup failed with error = %d\n", iResult);
        return -1;
    }

    char buf[MAX_PATH];
    if (gethostname(buf, sizeof(buf)) == SOCKET_ERROR) {
        fprintf(stderr, "Error getting host name. Error =  %d\n", WSAGetLastError());
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
int createDirectory(string &directoryPathname) {
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
            fprintf(stderr, "Failed to create output folder = %s Error: %d\n", outDirName.c_str(), rc);
            return -1;
        }
    }
    directoryPathname = outDirName;
    return 0;
}

/**
* wmi_init: Initialize WMN
*
* @param input wmiNamespace - wmi namespace to open
* @returns  0 on success
*                        WBEM_E_INVALID_NAMESPACE, if namespace is not found
*           -1 if error
*
* Ref: https://msdn.microsoft.com/en-us/library/aa390423(VS.85).aspx
*
*/

long wmi_init(const std::wstring& wmiNamespace, IWbemLocator **ppWbemLocator, IWbemServices **ppWbemServices) {
    HRESULT hres;

    // Step 1: Initialize COM.

    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        fprintf(stderr, "wmi_init: Failed to initialize COM library. Error code = %#X\n", hres);
        return -1;                  // Program has failed.
    }

    // Step 2: Set general COM security levels
    hres = CoInitializeSecurity(
        NULL,
        -1,                          // COM authentication
        NULL,                        // Authentication services
        NULL,                        // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
        RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
        NULL,                        // Authentication info
        EOAC_NONE,                   // Additional capabilities 
        NULL                         // Reserved
    );

    if (FAILED(hres)) {
        fprintf(stderr, "wmi_init: Failed to initialize security. Error code = %#X\n", hres);
        CoUninitialize();
        return -1;                    // Program has failed.
    }

    // Step 3: Obtain the initial locator to WMI
    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID *)ppWbemLocator);

    if (FAILED(hres))
    {
        fprintf(stderr, "wmi_init: Failed to create IWbemLocator object. Err code = %#X\n", hres);
        CoUninitialize();
        return -1;                 // Program has failed.
    }

    // Step 4: Connect to WMI through the IWbemLocator::ConnectServer method
    // Connect to the given namespace with
    // the current user and obtain pointer pSvc
    // to make IWbemServices calls.
    hres = (*ppWbemLocator)->ConnectServer(
        _bstr_t(wmiNamespace.c_str()), // Object path of WMI namespace
        NULL,                    // User name. NULL = current user
        NULL,                    // User password. NULL = current
        0,                       // Locale. NULL indicates current
        NULL,                    // Security flags.
        0,                       // Authority (e.g. Kerberos)
        0,                       // Context object 
        ppWbemServices                    // pointer to IWbemServices proxy
    );

    if (FAILED(hres)) {
        if (WBEM_E_INVALID_NAMESPACE != hres) {
            fprintf(stderr, "wmi_init: Could not connect to namespace %s, Error = %s\n",
                toNarrow(wmiNamespace).c_str(), GetErrorStdStr(hres).c_str());
        }

        (*ppWbemLocator)->Release();
        CoUninitialize();

        return (WBEM_E_INVALID_NAMESPACE == hres) ? hres : -1;
    }

    // Step 5: Set security levels on the proxy
    hres = CoSetProxyBlanket(
        *ppWbemServices,                        // Indicates the proxy to set
        RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
        RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
        NULL,                        // Server principal name 
        RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
        RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
        NULL,                        // client identity
        EOAC_NONE                    // proxy capabilities 
    );

    if (FAILED(hres)) {
        fprintf(stderr, "wmi_init: Could not set proxy blanket. Error code = %#X\n", hres);
        (*ppWbemServices)->Release();
        (*ppWbemLocator)->Release();
        CoUninitialize();
        return -1;               // Program has failed.
    }
    return 0;
}

/**
* wmi_close: closes WMI
*
* @returns  0 on success
*           -1 if error
*
*/
int wmi_close(IWbemLocator **ppWbemLocator, IWbemServices **ppWbemServices) {
    // Cleanup
    // ========

    (*ppWbemServices)->Release();
    (*ppWbemLocator)->Release();
    CoUninitialize();

    (*ppWbemServices) = NULL;
    (*ppWbemLocator) = NULL;

    return 0;
}

/**
* checkDriveForLDM: checks if the given drive is an LDM disk
*
* @param input driveLetter drive to check
*
* @returns  0 if the drive is NOT an LDM disk
*           1 if the drive IS an LDM disk
*           -1 if error, or if drive not found
*
*/
int checkDriveForLDM(const string& driveLetter) {

    IWbemLocator *pWbemLocator = NULL;
    IWbemServices *pWbemServices = NULL;

    if (0 != wmi_init(L"ROOT\\CIMV2", &pWbemLocator, &pWbemServices)) {
        return -1;
    }


    // Use the IWbemServices pointer to make requests of WMI. 
    // Make requests here:
    HRESULT hres;
    IEnumWbemClassObject* pEnumerator = NULL;
    bool bDriveFound = false;
    int isLDM = 0;

    std::wstring wstrQuery = L"ASSOCIATORS OF {Win32_LogicalDisk.DeviceID='";
    wstrQuery += toWide(driveLetter);
    wstrQuery += L"'} where AssocClass=Win32_LogicalDiskToPartition";

    // Run WMI query
    hres = pWbemServices->ExecQuery(
        bstr_t("WQL"),
        bstr_t(wstrQuery.c_str()),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres)) {
        std::cerr << "WMI Query for partition type failed. "
            << "Error code = 0x"
            << std::hex << hres << std::endl;
        wmi_close(&pWbemLocator, &pWbemServices);
        return -1;

    } else {

        IWbemClassObject *pclsObj;
        ULONG uReturn = 0;
        while (pEnumerator) {
            hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
            if (0 == uReturn) break;

            VARIANT vtProp, vtProp2;

            hres = pclsObj->Get(_bstr_t(L"Type"), 0, &vtProp, 0, 0);
            std::wstring partitionType = vtProp.bstrVal;

            hres = pclsObj->Get(_bstr_t(L"DeviceID"), 0, &vtProp2, 0, 0);
            std::wstring deviceID = vtProp2.bstrVal;

            VariantClear(&vtProp);
            VariantClear(&vtProp2);

            bDriveFound = true;

            //wcout << L"Drive: " << toWide(driveLetter) << ", DeviceID:  " << deviceID << ", Type: " << partitionType << endl;
            if (string::npos != toLower(toNarrow(partitionType)).find("logical disk manager")) {
                std::cerr << "Found Logical Disk Manager disk for drive =   " << driveLetter << std::endl;

                isLDM = 1;
            }
        }
    }
    pEnumerator->Release();

    wmi_close(&pWbemLocator, &pWbemServices);

    if (!bDriveFound) {
        std::cerr << "Drive =  " << driveLetter << " not found in Win32_LogicalDiskToPartition" << std::endl;
    }

    return bDriveFound ? isLDM : -1;
}

/**
* checkDriveForBitlocker: checks if the given drive has BitLocker encrypted
*
* @param input driveLetter drive to check
*
* @returns  0  if the drive is not encrypted
*           1  if the drive is Bitlocker encrypted
*           -1 if error
*
*/
int checkDriveForBitlocker(const string& driveLetter) {

    IWbemLocator *pWbemLocator = NULL;
    IWbemServices *pWbemServices = NULL;

    long rc = 0;

    std::wstring wsBitLockerNamespace = L"ROOT\\CIMV2\\security\\MicrosoftVolumeEncryption";


    // Init WMI with the requisite namespace. This may fail on some versions of Windows, if Bitlocker in not installed.
    rc = wmi_init(wsBitLockerNamespace, &pWbemLocator, &pWbemServices);
    if (0 != rc) {

        if ((WBEM_E_INVALID_NAMESPACE == rc)) {
            std::cerr << " Bitlocker is not installed." << std::endl;
            return 0;
        } else {
            std::cerr << "Failed to connect to WMI namespace = " << toNarrow(wsBitLockerNamespace) << std::endl;
            return -1;
        }
    }

    // Use the IWbemServices pointer to make requests of WMI. 
    // Make requests here:
    HRESULT hres;
    IEnumWbemClassObject* pEnumerator = NULL;

    unsigned int bitLockerStatus = 0; // assume no Bitlocker

                                                                      // WMI query
    std::wstring wstrQuery = L"SELECT * FROM Win32_EncryptableVolume where driveletter = '";
    wstrQuery += toWide(driveLetter);
    wstrQuery += L"'";

    // Run WMI query
    hres = pWbemServices->ExecQuery(
        bstr_t("WQL"),
        bstr_t(wstrQuery.c_str()),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres)) {
        std::cerr << "WMI Query for Win32_EncryptableVolume failed. "
            << "Error code = 0x"
            << std::hex << hres << std::endl;
        wmi_close(&pWbemLocator, &pWbemServices);
        return -1;
    } else {
        IWbemClassObject *pclsObj;
        ULONG uReturn = 0;
        while (pEnumerator) {
            hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
            if (0 == uReturn) break;

            VARIANT vtProp;
            hres = pclsObj->Get(_bstr_t(L"EncryptionMethod"), 0, &vtProp, 0, 0);

            if (WBEM_E_NOT_FOUND == hres) { // Means Bitlocker is not installed
                bitLockerStatus = 0;
            } else {
                unsigned int encryptionMethod = vtProp.uintVal;
                std::cerr << "Drive: " << driveLetter << ",  found in Win32_EncryptableVolume.  EncryptionMethod:  " 
                    << encryptionMethod << std::endl;
                bitLockerStatus = (0 == encryptionMethod) ? 0 : 1;
            }
            VariantClear(&vtProp);
        }
    }
    pEnumerator->Release();

    wmi_close(&pWbemLocator, &pWbemServices);

    return bitLockerStatus;
}

/**
* getDriveToProcess() - returns the drive to process
*          By default we process PhysicalDrive0, unless
*          C: is paritioned with LDM or has Bitlocker enabled, in which case we process 'C:'
*
* @param output driveToProcess
*
* @returns  TRUE on success or FALSE in case of failure.
*
*/
BOOL getDriveToProcess(string& driveToProcess) {

    // check if they are admin before we give them some ugly error messages
    if (isProcessElevated() == FALSE) {
        return FALSE;
    }

    int checkLDMStatus = 0;
    int checkBitlockerStatus = 0;

    // By default, cast a wide net
    driveToProcess = "PhysicalDrive0";

    const string systemDriveLetter = "C:";

    // if C: is part of LDM, then we'll just analyze C:
    checkLDMStatus = checkDriveForLDM(systemDriveLetter);
    if (1 == checkLDMStatus) {
        fprintf(stderr, "System drive %s is an LDM disk\n", systemDriveLetter.c_str());
        driveToProcess = systemDriveLetter;
        return TRUE;
    }

    // If bitlocker protection is enabled, then analyze C: and not full drive
    checkBitlockerStatus = checkDriveForBitlocker(systemDriveLetter);
    if (1 == checkBitlockerStatus) {
        fprintf(stderr, "System drive %s is BitLocker encrypted\n", systemDriveLetter.c_str());
        driveToProcess = systemDriveLetter;
        return TRUE;
    }

    if (0 == checkLDMStatus && 0 == checkBitlockerStatus) {
        return TRUE;        // neither LDM nor BitLocker detected on C:
    } else { // an error happened  in determining LDM or ProtectionStatus
        if (-1 == checkLDMStatus) {
            fprintf(stderr, "Error in checking LDM disk\n");
        }
        if (-1 == checkBitlockerStatus) {
            fprintf(stderr, "Error in checking BitLocker protection status\n");
        }

        // Take a chance and go after PhysicalDrive0,  few systems have LDM or Bitlocker 
        return TRUE;
    }
}

void openFs(TSK_IMG_INFO *img, TSK_OFF_T byteOffset) {
    TSK_FS_INFO *fs_info;
    if ((fs_info = tsk_fs_open_img(img, byteOffset, TSK_FS_TYPE_DETECT)) != NULL) {
        // Tell TSKHelper about this FS
        TskHelper::getInstance().addFSInfo(fs_info);
    }
    else {
        // check if it is bitlocker - POC effort 
        char buffer[32];
        tsk_img_read(img, byteOffset, buffer, 32);
        if ((buffer[3] == '-') && (buffer[4] == 'F') &&
            (buffer[5] == 'V') && (buffer[6] == 'E') &&
            (buffer[7] == '-') && (buffer[8] == 'F') &&
            (buffer[9] == 'S') && (buffer[10] == '-'))
        {
            std::cerr << "Volume is encrypted with BitLocker." << std::endl
                << "Volume did not have a file system and has a BitLocker signature" << std::endl;
        }

        std::cerr << "Volume does not contain a file system" << std::endl;
        tsk_error_reset();
    }
}

static void usage() {
    TFPRINTF(stderr,
        _TSK_T
        ("usage: %s [-i imgPath] -c configPath\n"),
        progname);
    tsk_fprintf(stderr, "\t-i imgPath: The image file\n");
    tsk_fprintf(stderr, "\t-c configPath: The configuration file\n");
    tsk_fprintf(stderr, "\t-v: verbose output to stderr\n");
    tsk_fprintf(stderr, "\t-V: Print version\n");
    exit(1);
}

int
main(int argc, char **argv1)
{
    TSK_IMG_INFO *img;
    TSK_IMG_TYPE_ENUM imgtype = TSK_IMG_TYPE_DETECT;

    int ch;
    TSK_TCHAR **argv;
    unsigned int ssize = 0;
    const TSK_TCHAR *imgPath[1];
    BOOL iFlagUsed = FALSE;
    TSK_TCHAR *configFilename = (TSK_TCHAR *) NULL;
    LogicalImagerRuleSet *ruleSet = NULL;

#ifdef TSK_WIN32
    // On Windows, get the wide arguments (mingw doesn't support wmain)
    argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv == NULL) {
        fprintf(stderr, "Error getting wide arguments\n");
        exit(1);
    }
#else
    argv = (TSK_TCHAR **)argv1;
#endif
    progname = argv[0];
    setlocale(LC_ALL, "");

    while ((ch = GETOPT(argc, argv, _TSK_T("c:i:vV"))) > 0) {
        switch (ch) {
        case _TSK_T('?'):
        default:
            TFPRINTF(stderr, _TSK_T("Invalid argument: %s\n"),
                argv[OPTIND]);
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
            imgPath[0] = OPTARG;
            iFlagUsed = TRUE;
            break;
        }
    }

    if (configFilename == NULL) {
        TFPRINTF(stderr, _TSK_T("-c configPath is required\n"));
        exit(1);
    }

    std::wstring wImgPathName;

    if (!iFlagUsed) {
        string driveToProcess;
        if (getDriveToProcess(driveToProcess)) {
            wImgPathName = _TSK_T("\\\\.\\") + toWide(driveToProcess);
            imgPath[0] = (TSK_TCHAR *)wImgPathName.c_str();
        }
        else {
            fprintf(stderr, "Process is not running in elevated mode\n");
            exit(1);
        }
    }
    TFPRINTF(stdout, _TSK_T("logical image path = %s\n"), imgPath[0]);

    if ((img = tsk_img_open(1, imgPath, imgtype, ssize)) == NULL) {
        tsk_error_print(stderr);
        exit(1);
    }

    // create a directory with hostname_timestamp
    string directory_path;
    if (createDirectory(directory_path) == -1) {
        exit(1);
    }
    fprintf(stdout, "Created directory %s\n", directory_path.c_str());

    string outputFileName = directory_path + "/sparse_image.vhd";
    std::wstring outputFileNameW = toWide(outputFileName);

    if (tsk_img_writer_create(img, (TSK_TCHAR *)outputFileNameW.c_str()) == TSK_ERR) {
        fprintf(stderr, "tsk_img_writer_create returns TSK_ERR\n");
        exit(1);
    }

    ruleSet = new LogicalImagerRuleSet(toNarrow(configFilename));

    TskHelper::getInstance().setImgInfo(img);
    TSK_VS_INFO *vs_info;
    if ((vs_info = tsk_vs_open(img, 0, TSK_VS_TYPE_DETECT)) == NULL) {
        std::cout << "No volume system found. Looking for file system" << std::endl;
        openFs(img, 0);
    } else {
        // process the volume system
        for (TSK_PNUM_T i = 0; i < vs_info->part_count; i++) {
            const TSK_VS_PART_INFO *vs_part = tsk_vs_part_get(vs_info, i);
            std::cout << "Partition: " + string(vs_part->desc) + "    Start: " + std::to_string(vs_part->start) << std::endl;
            if ((vs_part->flags & TSK_VS_PART_FLAG_UNALLOC) || (vs_part->flags & TSK_VS_PART_FLAG_META)) {
                continue;
            }
            openFs(img, vs_part->start * vs_part->vs->block_size);
        }
        tsk_vs_close(vs_info);
    }

    const std::list<TSK_FS_INFO *> fsList = TskHelper::getInstance().getFSInfoList();
    TSKFileNameInfo filenameInfo;
    const std::vector<std::string> filePaths = ruleSet->getFilePaths();
    TSK_FS_FILE *fs_file;
    for (std::list<TSK_FS_INFO *>::const_iterator fsListIter = fsList.begin(); fsListIter != fsList.end(); ++fsListIter) {
        for (std::vector<std::string>::const_iterator iter = filePaths.begin(); iter != filePaths.end(); ++iter) {
            int retval = TskHelper::getInstance().TSKHlprPath2Inum(*fsListIter, iter->c_str(), filenameInfo, NULL, &fs_file);
            std::cout << "TSKHlprPath2Inum returns " << retval << " " << (retval == 0 && fs_file == NULL ? "duplicate" : "") << " for " << iter->c_str() << std::endl;
            if (retval == 0 && fs_file != NULL) {
                (void) TskFindFiles::extractFile(fs_file);
            }
        }
    }
    TskHelper::getInstance().reset();

    TskFindFiles findFiles(ruleSet);

    if (findFiles.openImageHandle(img)) {
        tsk_error_print(stderr);
        if (ruleSet) {
            delete ruleSet;
        }
        exit(1);
    }

    if (findFiles.findFilesInImg()) {
        // we already logged the errors
        if (ruleSet) {
            delete ruleSet;
        }
        // should we call findFiles.closeImage() upon error?
        exit(1);
    }

    //if (tsk_img_writer_finish(img) == TSK_ERR) {
    //	fprintf(stderr, "tsk_img_writer_finish returns TSK_ERR\n");
    //	// not exiting, should call tsk_img_close.
    //}

    if (ruleSet) {
        delete ruleSet;
    }
    findFiles.closeImage();
    TFPRINTF(stdout, _TSK_T("Created VHD file %s\n"), (TSK_TCHAR *)outputFileNameW.c_str());
    exit(0);
}