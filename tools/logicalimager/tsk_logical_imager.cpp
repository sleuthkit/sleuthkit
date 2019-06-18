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
#include "LogicalImagerConfiguration.h"
#include "LogicalImagerRuleSet.h"
#include "TskFindFiles.h"
#include "TskHelper.h"
#include "RegistryAnalyzer.h"

std::wstring GetLastErrorStdStrW();
std::string GetErrorStdStr(DWORD err);
std::wstring GetErrorStdStrW(DWORD err);

static TSK_TCHAR *progname;

static std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;

static BOOL debug = FALSE;

void printDebug(char *msg, const char *fmt...) {
    if (debug) {
        fprintf(stderr, msg, fmt);
    }
}

/**
* GetErrorStdStr - returns readable error message for the given error code
*
* @param err error code
* @returns error message string
*/
string GetErrorStdStr(DWORD err) {
    return TskHelper::toNarrow(GetErrorStdStrW(err));
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
                TskHelper::toNarrow(wmiNamespace).c_str(), GetErrorStdStr(hres).c_str());
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
    wstrQuery += TskHelper::toWide(driveLetter);
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
            if (string::npos != TskHelper::toLower(TskHelper::toNarrow(partitionType)).find("logical disk manager")) {
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
            std::cerr << "Failed to connect to WMI namespace = " << TskHelper::toNarrow(wsBitLockerNamespace) << std::endl;
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
    wstrQuery += TskHelper::toWide(driveLetter);
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
* getPhysicalDrives: return a list of physical drives
*
* @param output a vector of physicalDrives
* @returns true on success, or false on error
*/
BOOL getPhysicalDrives(std::vector<std::wstring> &phyiscalDrives) {
    char physical[60000];

    if (QueryDosDeviceA(NULL, (LPSTR)physical, sizeof(physical))) {
        phyiscalDrives.clear();
        for (char *pos = physical; *pos; pos += strlen(pos) + 1) {
            std::wstring str(TskHelper::toWide(pos));
            if (str.rfind(_TSK_T("PhysicalDrive")) == 0) {
                phyiscalDrives.push_back(str);
                printDebug("Found %s\n", pos);
            }
        }
    } else {
        fprintf(stderr, "QueryDosDevice() return error: %d\n", GetLastError());
        return false;
    }
    return true;
}

/**
* getDrivesToProcess() - returns the drive to process
*          By default we process all available PhysicalDrives, unless
*          C: is paritioned with LDM or has Bitlocker enabled, in which case we process 'C:'
*
* @param output a set of drivesToProcess
*
* @returns  TRUE on success or FALSE in case of failure.
*
*/
BOOL getDrivesToProcess(std::vector<std::wstring> &drivesToProcess) {

    // check if they are admin before we give them some ugly error messages
    if (isProcessElevated() == FALSE) {
        return FALSE;
    }

    int checkLDMStatus = 0;
    int checkBitlockerStatus = 0;

    // By default, cast a wide net
    if (!getPhysicalDrives(drivesToProcess)) {
        return FALSE;
    }

    const string systemDriveLetter = "C:";

    // if C: is part of LDM, then we'll just analyze C:
    checkLDMStatus = checkDriveForLDM(systemDriveLetter);
    if (1 == checkLDMStatus) {
        fprintf(stderr, "System drive %s is an LDM disk\n", systemDriveLetter.c_str());
        drivesToProcess.clear();
        drivesToProcess.push_back((TSK_TCHAR *) systemDriveLetter.c_str());
        return TRUE;
    }

    // If bitlocker protection is enabled, then analyze C: and not full drive
    checkBitlockerStatus = checkDriveForBitlocker(systemDriveLetter);
    if (1 == checkBitlockerStatus) {
        fprintf(stderr, "System drive %s is BitLocker encrypted\n", systemDriveLetter.c_str());
        drivesToProcess.clear();
        drivesToProcess.push_back((TSK_TCHAR *)systemDriveLetter.c_str());
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

        // Take a chance and go after PhysicalDrives, few systems have LDM or Bitlocker 
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

/**
* hasTskLogicalImage - test if /tsk_logical_image.exe is in the image
*
* @param image - path to image
* @return true if found, false otherwise
*/
bool hasTskLogicalImager(const TSK_TCHAR *image) {
    TSK_IMG_INFO *img;
    TSK_IMG_TYPE_ENUM imgtype = TSK_IMG_TYPE_DETECT;
    unsigned int ssize = 0;
    bool result = false;

    if ((img = tsk_img_open(1, &image, imgtype, ssize)) == NULL) {
        tsk_error_print(stderr);
        return result;
    }

    TskHelper::getInstance().reset();
    TskHelper::getInstance().setImgInfo(img);

    TSK_VS_INFO *vs_info;
    if ((vs_info = tsk_vs_open(img, 0, TSK_VS_TYPE_DETECT)) == NULL) {
        openFs(img, 0);
    }
    else {
        // process the volume system
        for (TSK_PNUM_T i = 0; i < vs_info->part_count; i++) {
            const TSK_VS_PART_INFO *vs_part = tsk_vs_part_get(vs_info, i);
            if ((vs_part->flags & TSK_VS_PART_FLAG_UNALLOC) || (vs_part->flags & TSK_VS_PART_FLAG_META)) {
                continue;
            }
            openFs(img, vs_part->start * vs_part->vs->block_size);
        }
        tsk_vs_close(vs_info);
    }

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


FILE *m_alertFile = NULL;
std::string driveToProcess;

/*
* Create the alert file and print the header.
*
* @param alertFilename Name of the alert file
*/
void openAlert(const std::string &alertFilename) {
    m_alertFile = fopen(alertFilename.c_str(), "w");
    if (!m_alertFile) {
        fprintf(stderr, "ERROR: Failed to open alert file %s\n", alertFilename.c_str());
        exit(1);
    }
    fprintf(m_alertFile, "Drive\tExtraction Status\tRule Set Name\tRule Name\tDescription\tFilename\tPath\n");
}

/*
* Write an file match alert record to the alert file. Also send same record to stdout.
* An alert file record contains tab-separated fields:
*   - drive
*   - extractStatus
*   - ruleSetName
*   - ruleName
*   - description
*   - name
*   - path
*
* @param driveName Drive name
* @param extractStatus Extract status: 0 if file was extracted, 1 otherwise
* @param ruleMatchResult The rule match result
* @param fs_file TSK_FS_FILE that matches
* @param path Parent path of fs_file
*/
void alert(const std::string driveName, TSK_RETVAL_ENUM extractStatus, const RuleMatchResult *ruleMatchResult, TSK_FS_FILE *fs_file, const char *path) {
    if (fs_file->name && (strcmp(fs_file->name->name, ".") == 0 || strcmp(fs_file->name->name, "..") == 0)) {
        // Don't alert . and ..
        return;
    }
    // alert file format is "drive<tab>extractStatus<tab>ruleSetName<tab>ruleName<tab>description<tab>name<tab>path"
    fprintf(m_alertFile, "%s\t%d\t%s\t%s\t%s\t%s\t%s\n",
        driveName.c_str(),
        extractStatus,
        ruleMatchResult->getRuleSetName().c_str(),
        ruleMatchResult->getName().c_str(),
        ruleMatchResult->getDescription().c_str(),
        (fs_file->name ? fs_file->name->name : "name is null"),
        path);
    fflush(m_alertFile);

    fprintf(stdout, "%s\t%d\t%s\t%s\t%s\t%s\t%s\n",
        driveName.c_str(),
        extractStatus,
        ruleMatchResult->getRuleSetName().c_str(),
        ruleMatchResult->getName().c_str(),
        ruleMatchResult->getDescription().c_str(),
        (fs_file->name ? fs_file->name->name : "name is null"),
        path);
}

/*
* Close the alert file.
*/
void closeAlert() {
    if (m_alertFile) {
        fclose(m_alertFile);
    }
}

/**
* Extract a file. tsk_img_writer_create must have been called prior to this method.
*
* @param fs_file File details
* @returns TSK_RETVAL_ENUM TSK_OK if file is extracted, TSK_ERR otherwise.
*/
TSK_RETVAL_ENUM extractFile(TSK_FS_FILE *fs_file) {
    TSK_OFF_T offset = 0;
    size_t bufferLen = 16 * 1024;
    char buffer[16 * 1024];

    while (true) {
        ssize_t bytesRead = tsk_fs_file_read(fs_file, offset, buffer, bufferLen, TSK_FS_FILE_READ_FLAG_NONE);
        if (bytesRead == -1) {
            if (fs_file->meta && fs_file->meta->size == 0) {
                // ts_fs_file_read returns -1 with empty files, don't report it.
                return TSK_OK;
            }
            else {
                // fprintf(stderr, "processFile: tsk_fs_file_read returns -1 filename=%s\toffset=%" PRId64 "\n", fs_file->name->name, offset);
                return TSK_ERR;
            }
        }
        offset += bytesRead;
        if (offset >= fs_file->meta->size) {
            break;
        }
    }
    return TSK_OK;
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
TSK_RETVAL_ENUM matchCallback(const RuleMatchResult *matchResult, TSK_FS_FILE *fs_file, const char *path) {
    TSK_RETVAL_ENUM extractStatus = TSK_ERR;
    if (matchResult->isShouldSave()) {
        extractStatus = extractFile(fs_file);
    }
    if (matchResult->isShouldAlert()) {
        alert(driveToProcess, extractStatus, matchResult, fs_file, path);
    }
    return TSK_OK;
}

static void usage() {
    TFPRINTF(stderr,
        _TSK_T
        ("usage: %s [-i imgPath] [-c configPath]\n"),
        progname);
    tsk_fprintf(stderr, "\t-i imgPath: The image file\n");
    tsk_fprintf(stderr, "\t-c configPath: The configuration file. Default is config.json\n");
    tsk_fprintf(stderr, "\t-v: verbose output to stderr\n");
    tsk_fprintf(stderr, "\t-d: debug output to stderr\n");
    tsk_fprintf(stderr, "\t-V: Print version\n");
    exit(1);
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
        fprintf(stderr, "Error getting wide arguments\n");
        exit(1);
    }
#else
    argv = (TSK_TCHAR **)argv1;
#endif
    progname = argv[0];

    while ((ch = GETOPT(argc, argv, _TSK_T("c:i:vV:d"))) > 0) {
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
            imgPath = OPTARG;
            iFlagUsed = TRUE;
            break;

        case _TSK_T('d'):
            debug = TRUE;
            break;
        }
    }

    if (configFilename == NULL) {
        configFilename = _TSK_T("config.json");
        fprintf(stdout, "Using default configuration file config.json\n");
    }

    // create a directory with hostname_timestamp
    std::string directoryPath;
    if (createDirectory(directoryPath) == -1) {
        exit(1);
    }
    fprintf(stdout, "Created directory %s\n", directoryPath.c_str());

    std::wstring wImgPathName;
    std::vector<std::wstring> drivesToProcess;

    if (iFlagUsed) {
        imgPaths.push_back(imgPath);
    } else {
        if (getDrivesToProcess(drivesToProcess)) {
            for (auto it = std::begin(drivesToProcess); it != std::end(drivesToProcess); ++it) {
                imgPaths.push_back(std::wstring(_TSK_T("\\\\.\\")) + *it);
            }
        }
        else {
            fprintf(stderr, "Process is not running in elevated mode\n");
            exit(1);
        }
    }

    try {
        config = new LogicalImagerConfiguration(TskHelper::toNarrow(configFilename), (LogicalImagerRuleSet::matchCallback)matchCallback);
    }
    catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
        exit(1);
    }

    std::string alertFileName = directoryPath + "/alert.txt";
    openAlert(alertFileName);

    std::list<TSK_IMG_INFO *>imgFinalizePending;

    // Loop through all images
    for (int i = 0; i < imgPaths.size(); ++i) {
        const TSK_TCHAR *image = (TSK_TCHAR *)imgPaths[i].c_str();
        driveToProcess = iFlagUsed ? TskHelper::toNarrow(imgPaths[i]) : TskHelper::toNarrow(drivesToProcess[i]);

        std::string outputFileName = directoryPath + "/" + (iFlagUsed ? "sparse_image" : driveToProcess) + ".vhd";
        std::wstring outputFileNameW = TskHelper::toWide(outputFileName);

        if (hasTskLogicalImager(image)) {
            printDebug("Skipping drive %s\n", driveToProcess.c_str());
            continue; // Don't process a drive with /tsk_logicial_image.exe at the root
        }

        TFPRINTF(stdout, _TSK_T("logical image path = %s\n"), image);

        TSK_IMG_INFO *img;
        if ((img = tsk_img_open(1, &image, imgtype, ssize)) == NULL) {
            tsk_error_print(stderr);
            exit(1);
        }

        if (img->itype == TSK_IMG_TYPE_RAW) {
            if (tsk_img_writer_create(img, (TSK_TCHAR *)outputFileNameW.c_str()) == TSK_ERR) {
                tsk_error_print(stderr);
                fprintf(stderr, "tsk_img_writer_create returns TSK_ERR\n");
                exit(1);
            }
        }
        else {
            fprintf(stderr, "Image is not a RAW image, sparse_image.vhd will not be created\n");
        }


        imgFinalizePending.push_back(img);

        TskFindFiles findFiles(config);

        TskHelper::getInstance().reset();
        TskHelper::getInstance().setImgInfo(img);
        TSK_VS_INFO *vs_info;
        if ((vs_info = tsk_vs_open(img, 0, TSK_VS_TYPE_DETECT)) == NULL) {
            std::cout << "No volume system found. Looking for file system" << std::endl;
            openFs(img, 0);
        }
        else {
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
        const std::vector<std::pair<const RuleMatchResult *, std::list<std::string>>> fullFilePathsRules = config->getFullFilePaths();
        for (std::vector<std::pair<const RuleMatchResult *, std::list<std::string>>>::const_iterator iter = fullFilePathsRules.begin(); iter != fullFilePathsRules.end(); ++iter) {
            const RuleMatchResult *matchResult = iter->first;
            const std::list<std::string> filePaths = iter->second;
            TSK_FS_FILE *fs_file;
            for (std::list<TSK_FS_INFO *>::const_iterator fsListIter = fsList.begin(); fsListIter != fsList.end(); ++fsListIter) {
                for (std::list<std::string>::const_iterator iter = filePaths.begin(); iter != filePaths.end(); ++iter) {
                    int retval = TskHelper::getInstance().path2Inum(*fsListIter, iter->c_str(), false, filenameInfo, NULL, &fs_file);
                    if (retval == 0 && fs_file != NULL) {
                        // create a TSK_FS_NAME for alert purpose
                        fs_file->name = new TSK_FS_NAME();
                        fs_file->name->name = (char *)tsk_malloc(strlen(iter->c_str()) + 1);
                        strcpy(fs_file->name->name, iter->c_str());
                        matchCallback(matchResult, fs_file, "");

                        tsk_fs_file_close(fs_file);
                    }
                }
            }
        }

        string usersFileName = directoryPath + "/users.txt";

        // Enumerate Users with RegistryAnalyzer
        RegistryAnalyzer registryAnalyzer(usersFileName);
        registryAnalyzer.analyzeSAMUsers();

        TskHelper::getInstance().reset();

        if (findFiles.openImageHandle(img)) {
            tsk_error_print(stderr);
            fprintf(stderr, "openImageHandle failed\n");
            exit(1);
        }

        if (findFiles.findFilesInImg()) {
            // we already logged the errors in findFiles.handleError()
            // Don't exit, just let it continue
            fprintf(stderr, "findFilesInImg returns TSK_ERR\n");
        }

        TFPRINTF(stdout, _TSK_T("Created VHD file %s\n"), (TSK_TCHAR *)outputFileNameW.c_str());
    }

    // close alert file before tsk_img_writer_finish, which may take a long time. 
    closeAlert();

    // Delayed finialize image write
    for (auto it = std::begin(imgFinalizePending); it != std::end(imgFinalizePending); ++it) {
        TSK_IMG_INFO *img = *it;
        if (img->itype == TSK_IMG_TYPE_RAW) {
            if (config->getFinalizeImagerWriter()) {
                if (tsk_img_writer_finish(img) == TSK_ERR) {
                    fprintf(stderr, "tsk_img_writer_finish returns TSK_ERR\n");
                }
            }
        }
        img->close(img);
    }

    if (config) {
        delete config;
    }
    exit(0);
}