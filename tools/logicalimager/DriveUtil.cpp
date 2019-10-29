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
* \file DriveUtil.cpp
* Contains C++ code that implement the Drive Util class.
*/

#include <iostream>
#include <string>
#include <list>
#include <Wbemidl.h>
#include <comutil.h>

#include "DriveUtil.h"
#include "ReportUtil.h"
#include "TskHelper.h"
#include "tsk/auto/tsk_auto.h"

/*
* Test if Current Working Directory file system is FAT.
*
* @param [out] cwd Current working directory
* @returns true if current working directory file system is FAT, false otherwise.
*/
bool DriveUtil::cwdIsFAT(std::wstring &cwd) {
    wchar_t *buffer;

    if ((buffer = _wgetcwd(NULL, 0)) == NULL) {
        ReportUtil::ReportUtil::consoleOutput(stderr, "Error: _wgetcwd failed\n");
        ReportUtil::handleExit(1);
    }

    cwd = buffer;

    wchar_t drive[3];
    wcsncpy_s(drive, 3, buffer, 2);
    drive[2] = 0;
    free(buffer);
    return driveIsFAT(drive);
}

/*
* Test if drive is a FAT file system
*
* @param drive Drive to get, must be of the format "C:"
* @return true if drive is FAT, false otherwise.
*/
bool DriveUtil::driveIsFAT(wchar_t *drive) {
    std::wstring imageStr = std::wstring(L"\\\\.\\") + drive;
    const TSK_TCHAR *image = (TSK_TCHAR *)imageStr.c_str();
    bool result = false;

    TSK_IMG_INFO *img = TskHelper::addFSFromImage(image);
    if (img == NULL) {
        return result;
    }

    const std::list<TSK_FS_INFO *> fsList = TskHelper::getInstance().getFSInfoList();
    for (std::list<TSK_FS_INFO *>::const_iterator fsListIter = fsList.begin(); fsListIter != fsList.end(); ++fsListIter) {
        TSK_FS_INFO *fsInfo = *fsListIter;
        TSK_FS_TYPE_ENUM fileSystemType = fsInfo->ftype;
        if (fileSystemType == TSK_FS_TYPE_FAT12 ||
            fileSystemType == TSK_FS_TYPE_FAT16 ||
            fileSystemType == TSK_FS_TYPE_FAT32 ||
            fileSystemType == TSK_FS_TYPE_FAT_DETECT) {
            result = true;
            break;
        }
    }
    img->close(img);
    TskHelper::getInstance().reset();
    return result;
}


/**
* checkDriveForBitlocker: checks if the given drive has BitLocker encrypted
*
* @param input driveLetter drive to check, for example C:
*
* @returns  0  if the drive is not encrypted
*           1  if the drive is Bitlocker encrypted
*           -1 if error
*
*/
int DriveUtil::checkDriveForBitlocker(const std::string &driveLetter) {

    IWbemLocator *pWbemLocator = NULL;
    IWbemServices *pWbemServices = NULL;

    long rc = 0;

    std::wstring wsBitLockerNamespace = L"ROOT\\CIMV2\\Security\\MicrosoftVolumeEncryption";

    // Init WMI with the requisite namespace. This may fail on some versions of Windows, if Bitlocker in not installed.
    rc = wmi_init(wsBitLockerNamespace, &pWbemLocator, &pWbemServices);
    if (0 != rc) {
        if ((WBEM_E_INVALID_NAMESPACE == rc)) {
            std::cerr << " Bitlocker is not installed." << std::endl;
            return 0;
        }
        else {
            std::cerr << "Failed to connect to WMI namespace = " << TskHelper::toNarrow(wsBitLockerNamespace) << std::endl;
            return -1;
        }
    }

    // Use the IWbemServices pointer to make requests of WMI.
    // Make requests here:
    HRESULT hres;
    IEnumWbemClassObject* pEnumerator = NULL;

    unsigned int bitLockerStatus = 0; // assume no Bitlocker
    int returnStatus = 0;
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
    }
    else {
        IWbemClassObject *pclsObj;
        ULONG uReturn = 0;
        while (pEnumerator) {
            hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
            if (0 == uReturn) break;

            VARIANT vtProp;
            hres = pclsObj->Get(_bstr_t(L"EncryptionMethod"), 0, &vtProp, 0, 0);

            if (WBEM_E_NOT_FOUND == hres) { // Means Bitlocker is not installed
                bitLockerStatus = 0;
            }
            else {
                unsigned int encryptionMethod = vtProp.uintVal;
                bitLockerStatus = (0 == encryptionMethod) ? 0 : 1;
                if (bitLockerStatus == 1) {
                    returnStatus = 1;
                }
            }
            VariantClear(&vtProp);
        }
    }
    pEnumerator->Release();

    wmi_close(&pWbemLocator, &pWbemServices);

    return returnStatus;
}

/**
* isDriveLocked: checks if the given drive is BitLocker locked
*
* @param input driveLetter drive to check, for example C:
*
* @returns  0  if the drive is not locked
*           1  if the drive is Bitlocker locked
*           -1 if error
*
*/
int DriveUtil::isDriveLocked(const std::string &driveLetter) {

    IWbemLocator *pWbemLocator = NULL;
    IWbemServices *pWbemServices = NULL;

    long rc = 0;

    std::wstring wsBitLockerNamespace = L"ROOT\\CIMV2\\Security\\MicrosoftVolumeEncryption";

    // Init WMI with the requisite namespace. This may fail on some versions of Windows, if Bitlocker in not installed.
    rc = wmi_init(wsBitLockerNamespace, &pWbemLocator, &pWbemServices);
    if (0 != rc) {
        if ((WBEM_E_INVALID_NAMESPACE == rc)) {
            std::cerr << " Bitlocker is not installed." << std::endl;
            return 0;
        }
        else {
            std::cerr << "Failed to connect to WMI namespace = " << TskHelper::toNarrow(wsBitLockerNamespace) << std::endl;
            return -1;
        }
    }

    // Use the IWbemServices pointer to make requests of WMI.
    // Make requests here:
    HRESULT hres;
    IEnumWbemClassObject* pEnumerator = NULL;

    int returnStatus = 0;
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
    }
    else {
        IWbemClassObject *pclsObj;
        ULONG uReturn = 0;
        while (pEnumerator) {
            hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
            if (0 == uReturn) break;

            VARIANT vtProp;
            hres = pclsObj->Get(_bstr_t(L"ProtectionStatus"), 0, &vtProp, 0, 0);

            if (WBEM_E_NOT_FOUND != hres) {
                unsigned int protectionStatus = vtProp.uintVal;
                if (2 == protectionStatus) {
                    returnStatus = 1;
                }
            }
            VariantClear(&vtProp);
        }
    }
    pEnumerator->Release();

    wmi_close(&pWbemLocator, &pWbemServices);

    return returnStatus;
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
long DriveUtil::wmi_init(const std::wstring& wmiNamespace, IWbemLocator **ppWbemLocator, IWbemServices **ppWbemServices) {
    HRESULT hres;

    // Step 1: Initialize COM.

    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        ReportUtil::consoleOutput(stderr, "wmi_init: Failed to initialize COM library. Error code = %#X\n", hres);
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
        ReportUtil::consoleOutput(stderr, "wmi_init: Failed to initialize security. Error code = %#X\n", hres);
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
        ReportUtil::consoleOutput(stderr, "wmi_init: Failed to create IWbemLocator object. Err code = %#X\n", hres);
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
            ReportUtil::consoleOutput(stderr, "wmi_init: Could not connect to namespace %s, Error = %s\n",
                TskHelper::toNarrow(wmiNamespace).c_str(), ReportUtil::GetErrorStdStr(hres).c_str());
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
        ReportUtil::consoleOutput(stderr, "wmi_init: Could not set proxy blanket. Error code = %#X\n", hres);
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
int DriveUtil::wmi_close(IWbemLocator **ppWbemLocator, IWbemServices **ppWbemServices) {
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
* @param input driveLetter drive to check, for example C:
*
* @returns  0 if the drive is NOT an LDM disk
*           1 if the drive IS an LDM disk
*           -1 if error, or if drive not found
*
*/
int DriveUtil::checkDriveForLDM(const std::string &driveLetter) {

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
    }
    else {
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

            //std::wcout << L"Drive: " << TskHelper::toWide(driveLetter) << ", DeviceID:  " << deviceID << ", Type: " << partitionType << std::endl;
            if (std::string::npos != TskHelper::toLower(TskHelper::toNarrow(partitionType)).find("logical disk manager")) {
                //std::cerr << "Found Logical Disk Manager disk for drive = " << driveLetter << std::endl;
                isLDM = 1;
            }
        }
    }
    pEnumerator->Release();

    wmi_close(&pWbemLocator, &pWbemServices);

    return bDriveFound ? isLDM : -1;
}

/*
* Test if a drive is a BitLocker or LDM drive
*
* @param systemDriveLetter Drive letter, in the form of "C:"
* @returns true if this is a BitLocker or LDM drive, false otherwise.
*
*/
bool DriveUtil::hasBitLockerOrLDM(const std::string &systemDriveLetter) {
    int checkLDMStatus = 0;
    int checkBitlockerStatus = 0;

    checkLDMStatus = DriveUtil::checkDriveForLDM(systemDriveLetter);
    if (1 == checkLDMStatus) {
        ReportUtil::printDebug("System drive %s is an LDM disk\n", systemDriveLetter.c_str());
        return TRUE;
    }

    // If bitlocker protection is enabled, then analyze it
    checkBitlockerStatus = DriveUtil::checkDriveForBitlocker(systemDriveLetter);
    if (1 == checkBitlockerStatus) {
        ReportUtil::printDebug("System drive %s is BitLocker encrypted\n", systemDriveLetter.c_str());
        return TRUE;
    }

    if (0 == checkLDMStatus && 0 == checkBitlockerStatus) {
        return false;        // neither LDM nor BitLocker detected
    }
    else { // an error happened in determining LDM or ProtectionStatus
        if (-1 == checkLDMStatus) {
            ReportUtil::printDebug("Error in checking LDM disk\n");
        }
        if (-1 == checkBitlockerStatus) {
            ReportUtil::printDebug("Error in checking BitLocker protection status\n");
        }

        // Take a chance and go after PhysicalDrives, few systems have LDM or Bitlocker
        return false;
    }
}

/**
* getPhysicalDrives: return a list of physical drives
*
* @param output a vector of physicalDrives
* @returns true on success, or false on error
*/
BOOL DriveUtil::getPhysicalDrives(std::vector<std::wstring> &phyiscalDrives) {
    char physical[60000];

    /* Get list of Windows devices.  Result is a list of NULL
    * terminated device names. */
    if (QueryDosDeviceA(NULL, (LPSTR)physical, sizeof(physical))) {
        phyiscalDrives.clear();
        for (char *pos = physical; *pos; pos += strlen(pos) + 1) {
            std::wstring str(TskHelper::toWide(pos));
            if (str.rfind(_TSK_T("PhysicalDrive")) == 0) {
                phyiscalDrives.push_back(str);
                ReportUtil::printDebug("Found %s from QueryDosDeviceA", pos);
            }
        }
    }
    else {
        ReportUtil::consoleOutput(stderr, "QueryDosDevice() return error: %d\n", GetLastError());
        return false;
    }
    return true;
}
