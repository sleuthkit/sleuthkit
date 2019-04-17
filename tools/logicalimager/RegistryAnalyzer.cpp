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
* \file RegistryAnalyzer.cpp
* Contains C++ code that creates the Registry Analyzer class.
*/

#include <string>
#include <sstream>
#include <iostream>
#include <codecvt>
#include <iomanip> 

#include "RegistryAnalyzer.h"
#include "tsk/tsk_tools_i.h"
#include "TskHelper.h"
#include "RegHiveType.h"
#include "RegParser.h"
#include "RegistryLoader.h"
#include "ConfigMgr.h"
#include "CyberTriageDefs.h"

const string LOCAL_DOMAIN = "local";

RegistryAnalyzer::RegistryAnalyzer(const TSK_FS_INFO *fsInfo)
{
    m_fsInfo = fsInfo;
}

RegistryAnalyzer::~RegistryAnalyzer() {
}

/* Enumerate the System registry files and save the results to
* class member variables.
* @returns -1 on error, 0 on success
*/
int RegistryAnalyzer::findSystemRegFiles(TSK_FS_INFO * a_fs_info) const {
    const std::string SYS_REG_FILES_DIR = "/Windows/System32/config";

    std::cout << "Searching for system registry files" << std::endl;

    TSKFileNameInfo filenameInfo;
    TSK_FS_FILE *fsFile;
    int8_t retval = TskHelper::getInstance().path2Inum(a_fs_info, SYS_REG_FILES_DIR.c_str(), filenameInfo, NULL, &fsFile);
    if (retval == -1) {
        std::cerr << "Error in finding system Registry files. System Registry files will not be analyzed. errno = " << tsk_error_get() << std::endl;
        return -1;
    }
    else if (retval > 0) { // not found   // @@@ ACTUALLY CHECK IF IT IS #2
        std::cout << "File System at Offset " << a_fs_info->offset << " did not have windows/system32/config folder" << std::endl;
        return 0;
    }

    // open the directory
    TSK_FS_DIR *fs_dir;
    if ((fs_dir = tsk_fs_dir_open_meta(a_fs_info, filenameInfo.getINUM())) == NULL) {
        std::cerr << "Error opening windows/system32/config folder. Some System Registry files may not be analyzed." << std::endl;
        std::cerr << "findSystemRegFiles(): tsk_fs_dir_open_meta() failed for windows/system32/config folder.  dir inum = " << filenameInfo.getINUM() << ", errno = " << tsk_error_get() << std::endl;
        return -1;
    }

    // cycle through each directory entry
    for (size_t i = 0; i < tsk_fs_dir_getsize(fs_dir); i++) {

        TSK_OFF_T off = 0;
        size_t len = 0;

        // get the entry
        const TSK_FS_NAME *fs_name;
        if ((fs_name = tsk_fs_dir_get_name(fs_dir, i)) == NULL) {
            std::cerr << "Error in finding System Registry files. Some System Registry files may not be analyzed." << std::endl;
            std::cerr << "findSystemRegFiles(): Error getting directory entry = " << i << " in dir inum = " << filenameInfo.getINUM() << ", errno = " << tsk_error_get() << ", some System Registry files may not be analyzed." << std::endl;
            continue;
        }

        if (((fs_name->flags & TSK_FS_META_FLAG_ALLOC) == 0) || (fs_name->type != TSK_FS_NAME_TYPE_REG)) {
            continue;
        }

        std::string fName = fs_name->name;
        if ((0 == _stricmp("SYSTEM", fName.c_str())) || (0 == _stricmp("SOFTWARE", fName.c_str())) ||
            (0 == _stricmp("SECURITY", fName.c_str())) || (0 == _stricmp("SAM", fName.c_str()))) {

            RegHiveType::Enum hiveType = hiveNameToType(fName);

            // @@ FIX THE ERROR MSGS HERE
            TSK_FS_FILE *fs_file;
            if ((fs_file = tsk_fs_dir_get(fs_dir, i)) == NULL) {
                std::cerr << "Error in loading Registry file. The Registry file will not be analyzed." << std::endl;
                std::cerr << "findSystemRegFiles(): tsk_fs_dir_get failed for file = " << fs_file->name->name << std::endl;
                continue;
            }

            std::cout << "findSystemRegFiles: Loading hive" << std::endl;
            RegParser *pRegParser = new RegParser(hiveType);
            if (0 != pRegParser->loadHive(fs_file, hiveType)) {
                std::cerr << "Error in loading Registry file. The Registry file will not be analyzed." << std::endl;
                std::cerr << "findSystemRegFiles(): loadHive() failed for file = " << fs_file->name->name << std::endl;
                continue;
            }

//            RegFileInfo *pRegFileInfo = new RegFileInfo(fName, CyberTriageUtils::toNormalizedOutputPathName(SYS_REG_FILES_DIR.c_str()), hiveType, fs_file->fs_info->offset, fs_file->meta->addr, pRegParser);

//            m_regSystemFiles.push_back(pRegFileInfo);
            tsk_fs_file_close(fs_file);
        }

    } // for

    tsk_fs_dir_close(fs_dir);

    return 0;
}

RegHiveType::Enum RegistryAnalyzer::hiveNameToType(const string aName) const
{
    if (0 == _stricmp("SYSTEM", aName.c_str()))
        return RegHiveType::SYSTEM;
    else if (0 == _stricmp("SOFTWARE", aName.c_str()))
        return RegHiveType::SOFTWARE;
    else if (0 == _stricmp("SECURITY", aName.c_str()))
        return RegHiveType::SECURITY;
    else if (0 == _stricmp("SAM", aName.c_str()))
        return RegHiveType::SAM;
    else if (0 == _stricmp("NTUSER.DAT", aName.c_str()))
        return RegHiveType::NTUSER;
    else if (0 == _stricmp("USRCLASS.DAT", aName.c_str()))
        return RegHiveType::USRCLASS;
    else
        return RegHiveType::UNKNOWN;
}

// Returns a 8601 time string for the given time_t.  Assumes that the time_t value is in UTC and returns readable timestamp in UTC                                                                                                               
string getTimeStr(time_t aTime, unsigned long a_fractionSecs = 0) {

    string retStr;
    retStr.clear();

    if (0 == aTime)
        return retStr;

    // convert time_t (UTC) to struct tm (UTC)                                                                       
    struct tm localTime;
    gmtime_s(&localTime, &aTime);

    char timeStr[32];
    strftime(timeStr, sizeof timeStr, "%Y-%m-%dT%H:%M:%S", &localTime);

    retStr = timeStr;

    // append the fraction of seconds                                                                                
    std::stringstream ss;
    ss << std::setfill('0') << std::setw(9) << a_fractionSecs;
    string fractionStr = ss.str();
    retStr += "." + fractionStr;
    retStr += "Z";
    return retStr;
}

time_t filetimeToTimet(const FILETIME& ft)
{
    ULARGE_INTEGER ull;

    ull.LowPart = ft.dwLowDateTime;
    ull.HighPart = ft.dwHighDateTime;
    time_t tt = ((0 == ft.dwLowDateTime) && (0 == ft.dwLowDateTime)) ? 0 : (ull.QuadPart / 10000000ULL - 11644473600ULL);
    return tt;
}

/**
* FiletimeToStr - converts the given FILETIME stamp into a ISO 8601 timmestamp string
*  Returns:  ISO 8601 formatted time string, "Unknown" is FILETIME is 0
*/
string FiletimeToStr(FILETIME filetime) {
    if (filetime.dwLowDateTime == 0 && filetime.dwHighDateTime == 0)
        return "Unknown";
    return getTimeStr(filetimeToTimet(filetime));
}

/**
* samUserTypeToAccountType - maps SAM user account type to CyberTriage user acccount type.
*/
USER_ACCOUNT_TYPE::Enum samUserTypeToAccountType(uint32_t& acctType) {
    switch (acctType & 0x000000FF) {
    case 0xBC:
    case 0xD4:
    case 0xF4:
    case 0x0C:
        return USER_ACCOUNT_TYPE::REGULAR;
    case 0xB0:
    case 0xE8:
        return USER_ACCOUNT_TYPE::LIMITED;  //Guest account                                                      
    default:
        return USER_ACCOUNT_TYPE::UNKNOWN;
    }
}
/**
* samUserTypeToAdminPriv - retunrs whether a given SAM account type has admin privileges
*/
USER_ADMIN_PRIV::Enum samUserTypeToAdminPriv(uint32_t& acctType) {
    switch (acctType & 0x000000FF) {
    case 0xBC:                          // Prior to Windows 10                                                       
    case 0xF4:                          // Windows 10                                                                
        return USER_ADMIN_PRIV::YES;    // Member of Default Admin group                                         
    case 0xD4:                          // Prior to Windows 10                                                       
    case 0x0C:                          // Windows 10                                                                
    case 0xB0:                          // Prior to Windows 10                                                       
    case 0xE8:                          // Windows 10                                                                
        return USER_ADMIN_PRIV::NO;
    default:
        return USER_ADMIN_PRIV::UNKNOWN;
    }
}

/**
* analyzeSAMUsers - parses SAM to gather information for local user accounts
*
* Hive: SAM
* Key: "SAM\\Domains\\Account\\Users"
*
* Resources:
* https://ad-pdf.s3.amazonaws.com/Forensic_Determination_Users_Logon_Status.pdf
*
* acb Flags:
*  0x0001 => "Account Disabled",
*  0x0002 => "Home directory required",
*  0x0004 => "Password not required",
*  0x0008 => "Temporary duplicate account",
*  0x0010 => "Normal user account",
*  0x0020 => "MNS logon user account",
*  0x0040 => "Interdomain trust account",
*  0x0080 => "Workstation trust account",
*  0x0100 => "Server trust account",
*  0x0200 => "Password does not expire",
*  0x0400 => "Account auto locked"
*
* @param aRegFile - Registry file to parse
* @param aRegParser - registry parser to use to read the registry
*
* @returns 0 on success, -1 if error
*/

int RegistryAnalyzer::analyzeSAMUsers() const {
    map<wstring, FILETIME> acctCreationDateMap;
    RegFileInfo *aRegFile = RegistryLoader::getInstance().getSAMHive();
    if (aRegFile == NULL) {
        std::cerr << "ERROR: SAM HIVE not found" << std::endl;
        return -1;
    }
    RegParser &aRegParser = aRegFile->getRegParser();

    std::cout << "Registry: Analyzing SAM Users" << std::endl;

    // First collect the known user names and their account creation time.  
    // Account creation time corresponds with creation of a user name key
    wstring wsSAMUserNamesKeyName = L"SAM\\Domains\\Account\\Users\\Names";
    vector<wstring> wsUserNameSubkeys;
    int rc;
    try {
        rc = aRegParser.getSubKeys(wsSAMUserNamesKeyName, wsUserNameSubkeys);
        if (0 == rc) {
            for (vector<wstring>::iterator it = wsUserNameSubkeys.begin(); it != wsUserNameSubkeys.end(); ++it) {
                wstring wsName = (*it);
                wstring wsKeyName = wsSAMUserNamesKeyName + L"\\" + wsName;
                RegKey* pUserNameSubkey = new RegKey(wsKeyName);
                if (0 == aRegParser.getKey(wsKeyName, *pUserNameSubkey)) {
                    FILETIME ft = { 0, 0 };
                    pUserNameSubkey->getModifyTime(ft);
                    acctCreationDateMap[wsName] = ft;
                }
            }
        }
        else if (-2 == rc) {
            string errMsg = "analyzeSAMUsers: Error getting key  = " + TskHelper::toNarrow(wsSAMUserNamesKeyName) + " Local user accounts may not be reported.";
            string details = "analyzeSAMUsers() failed.";
            std::cerr << errMsg << std::endl;
            rc = -1;
        }

        wstring wsSAMUsersKeyName = L"SAM\\Domains\\Account\\Users";
        vector<wstring> wsSubkeyNames;

        rc = aRegParser.getSubKeys(wsSAMUsersKeyName, wsSubkeyNames);
        if (0 == rc) {

            for (vector<wstring>::iterator it = wsSubkeyNames.begin(); it != wsSubkeyNames.end(); ++it) {
                if (TskHelper::startsWith(TskHelper::toNarrow((*it)), "0000")) {
                    wstring wsRID = (*it);
                    wstring wsSAMRIDKeyName = wsSAMUsersKeyName + L"\\" + wsRID;

                    //Make users SID from RID and computer SID
                    long lRID = strtol(TskHelper::toNarrow(wsRID).c_str(), NULL, 16);
                    string compSID = ConfigMgr::getInstance().getTargetComputerSID();
                    string userSID = compSID + "-" + to_string(lRID);


                    bool bError = false;
                    wstring wsUserName(L"");
                    wstring wsFullName(L"");
                    wstring wsComment(L"");
                    string sUserName("");

                    uint32_t samAcctType = 0;
                    USER_ACCOUNT_TYPE::Enum acctType;
                    USER_ADMIN_PRIV::Enum acctAdminPriv;

                    // Get V Record
                    RegVal vRecord;
                    wstring wsVRecordValname = L"V";
                    vRecord.setValName(wsVRecordValname);
                    if (0 == aRegParser.getValue(wsSAMRIDKeyName, wsVRecordValname, vRecord)) {
                        if (parseSAMVRecord(vRecord.getBinary(), vRecord.getValLen(), wsUserName, wsFullName, wsComment, samAcctType)) {
                            bError = true;
                        }
                        else {
                            sUserName = TskHelper::toNarrow(wsUserName);
                            acctType = samUserTypeToAccountType(samAcctType);
                            acctAdminPriv = samUserTypeToAdminPriv(samAcctType);
                        }
                    }
                    else {
                        bError = true;
                    }

                    FILETIME lastLoginDate = { 0,0 };
                    FILETIME lastPWResetDate = { 0,0 };
                    FILETIME accountExpiryDate = { 0,0 };
                    FILETIME lastFailedLoginDate = { 0,0 };

                    string sDateCreated = "Unknown";
                    string sLastLoginDate;
                    string sAcctExpiryDate;

                    uint16_t loginCount = 0;
                    uint16_t  acbFlags = 0;
                    bool accountDisabled = false;

                    // GET F Record
                    RegVal fRecord;
                    wstring wsFRecordValname = L"F";
                    fRecord.setValName(wsFRecordValname);

                    if (0 == aRegParser.getValue(wsSAMRIDKeyName, wsFRecordValname, fRecord)) {
                        // Parse F Record
                        parseSAMFRecord(fRecord.getBinary(), fRecord.getValLen(), lastLoginDate, lastPWResetDate, accountExpiryDate, lastFailedLoginDate, loginCount, acbFlags);

                        sLastLoginDate = FiletimeToStr(lastLoginDate);
                        if (accountExpiryDate.dwHighDateTime != 0x7FFFFFFF) {
                            sAcctExpiryDate = FiletimeToStr(accountExpiryDate);
                        }
                        else {
                            sAcctExpiryDate = "Never";
                        }

                        map<wstring, FILETIME>::iterator it = acctCreationDateMap.find(wsUserName);
                        if (it != acctCreationDateMap.end()) {
                            sDateCreated = FiletimeToStr(it->second);
                        }
                        else {
                            wcerr << "User name = " << wsUserName << " not found in acctCreationDateMap" << endl;
                        }

                        if ((acbFlags & 0x0001) == 0x0001)
                            accountDisabled = true;
                    }

                    if (!bError) {

                        // SAM is parsed first and has only local accounts. We assume none of these users already exist.
                        UserAccount *pUserAccount = new UserAccount(sUserName);

                        pUserAccount->setUserDomain(LOCAL_DOMAIN);   // this is a local account
                        pUserAccount->setAccountType(acctType);
                        pUserAccount->setAdminPriv(acctAdminPriv);
                        pUserAccount->setSID(userSID);

                        pUserAccount->setDateCreated(sDateCreated);
                        pUserAccount->setLastLoginDate(sLastLoginDate); //  Fri Jan 20 17:10:41 2012 Z
                        pUserAccount->setLoginCount(TskHelper::intToStr(loginCount));
                        pUserAccount->setAccountLocation(USER_ACCOUNT_LOCATION::LOCAL_ACCOUNT);  // all accounts found in SAM registry are local (as opposed to Domain)
                        pUserAccount->setDisabled(accountDisabled); // from flags;

                        //pUserAccount->setExtractor(CTExtractor::COLLECTION_TOOL);
                        //pUserAccount->getSource().setSourceType(ItemSourceType::REGISTRY_KEY);
                        //pUserAccount->getSource().setPath(aRegFile->getPathName());
                        //pUserAccount->getSource().setKeyName(TskHelper::toNarrow(wsSAMRIDKeyName));
                        //pUserAccount->getSource().setValueName(TskHelper::toNarrow(wsVRecordValname));

                        // Since we gather user accounts from multiple places and must be deduped, all the user accounts are reported alltogether.
                        // TODO DataCollector::getInstance().addUserAccount(pUserAccount);
                    }
                }
            }
        }
        else {
            string errMsg = "analyzeSAMUsers: Error getting key  = " + TskHelper::toNarrow(wsSAMUsersKeyName) + " Local user accounts may not be reported.";
            string details = "analyzeSAMUsers() failed.";
            std::cerr << errMsg << std::endl;
            rc = -1;
        }
    }
    catch (...) {
        std::exception_ptr eptr = std::current_exception();
        try {
            std::rethrow_exception(eptr);
        }
        catch (const std::exception& e) {
            string errMsg = "RegisteryAnalyzer: Uncaught exception in analyzeSAMUsers.";
            std::cerr << errMsg << std::endl;
            std::cerr << e.what() << std::endl;
        }
        rc = -1;
    }
    return rc;
}

DWORD makeDWORD(const unsigned char *buf) {
    return (buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24));
}

WORD makeWORD(const unsigned char *buf) {
    return (buf[0] | (buf[1] << 8));
}

/**
* utf16LEToWString - convert the given UTF16 LE byte stream into a wstring
*
*/
std::wstring utf16LEToWString(const unsigned char *buf, size_t len) {
    if (NULL == buf || len == 0)
        return wstring();

    wstring_convert<codecvt_utf16<wchar_t, 0x10ffff, little_endian>,
        wchar_t> conv;
    wstring ws = conv.from_bytes(
        reinterpret_cast<const char*> (buf),
        reinterpret_cast<const char*> (buf + len));

    return ws;
}

/***
* parseSAMVRecord - parses the given byte stream as SAM V Record.
*                   Extacts and returns account attributes:
*                   userName, userFullName, comment, acctType
* http://www.beginningtoseethelight.org/ntsecurity/index.htm#8603CF0AFBB170DD
*
* @param input pVRec - Byte stream for the V Record
* @param input aVRecLen - length of the V Record
* @param output userName - returned username as parsed from the record
* @param output userFullName - returned user full name extracted from the record
* @param output userFullName - returned user full name extracted from the record
* @param output comment - user account comment extracted from the record
* @param output acctType - account type extractd from the record
*
* @returns 0 on success, -1 if error
*/
int RegistryAnalyzer::parseSAMVRecord(const unsigned char *pVRec, size_t aVRecLen, wstring& userName, wstring& userFullName, wstring& comment, uint32_t& acctType) const {

    int rc = 0;
    size_t off;
    int len;

    std::cout << "Registry: Parsing SAMV Record" << std::endl;
    userName = L"";
    userFullName = L"";
    comment = L"";

    if (aVRecLen < 44) {
        std::cerr << "ERROR: SAMV record too short" << std::endl;
        return -1;
    }

    // acctType - DWORD at off 0x04
    acctType = makeDWORD(&pVRec[4]);

    // get user name
    off = makeDWORD(&pVRec[12]) + 0xCC;
    len = makeDWORD(&pVRec[16]);

    if ((off >= aVRecLen) || (off + len > aVRecLen)) {
        std::cerr << "ERROR: SAMV record too short" << std::endl;
        return -1;
    }
    userName = utf16LEToWString(&pVRec[off], len);

    // get full name
    off = makeDWORD(&pVRec[24]) + 0xCC;
    len = makeDWORD(&pVRec[28]);
    if (len > 0) {
        if (off + len > aVRecLen) {
            std::cerr << "ERROR: SAMV record too short" << std::endl;
            return -1;
        }
        userFullName = utf16LEToWString(&pVRec[off], len);
    }

    // get comment
    off = makeDWORD(&pVRec[36]) + 0xCC;
    len = makeDWORD(&pVRec[40]);
    if (len > 0) {
        if (off + len > aVRecLen) {
            std::cerr << "ERROR: SAMV record too short" << std::endl;
            return -1;
        }
        comment = utf16LEToWString(&pVRec[off], len);
    }

    return rc;
}

/**
* parseSAMFRecord - parses the given bytes stream as F record from SAM.
*                  Extacts and returns various account attributes:
*                    lastLoginDate, lastPWResetDate, accountExpiryDate, lastFailedLoginDate,
*                    loginCount, acbFlags
*
*http://www.beginningtoseethelight.org/ntsecurity/index.htm#8603CF0AFBB170DD
*
* @param input pVRec - Byte stream for the F Record
* @param input aVRecLen - length of the F Record
* @param output lastLoginDate - last login datetime
* @param output lastPWResetDate - last password reset datetime
* @param output accountExpiryDate - account expirt datetime
* @param output lastFailedLoginDate - last failed login datetime
* @param output loginCount - login count
* @param output acbFlags - acbFlags
*
* @returns 0 on success, -1 if error
*/
int RegistryAnalyzer::parseSAMFRecord(const unsigned char *pFRec, long aFRecLen, FILETIME& lastLoginDate,
    FILETIME& lastPWResetDate, FILETIME& accountExpiryDate, FILETIME& lastFailedLoginDate,
    unsigned short& loginCount, unsigned short& acbFlags) const {
    int rc = 0;

    FILETIME tv;

    std::cout << "Registry: Parsing SAMF Record" << std::endl;

    if (aFRecLen < 68) {
        std::cerr << "ERROR: SAMF record too short" << std::endl;
        return -1;
    }

    // get last login date                                                                                           
    tv = *(FILETIME *)&pFRec[8];
    if ((tv.dwLowDateTime != 0)) {
        lastLoginDate = tv;
    }

    // get passwd last reset date                                                                                    
    tv = *(FILETIME *)&pFRec[24];
    if ((tv.dwLowDateTime != 0)) {
        lastPWResetDate = tv;
    }

    // get acct expiry date                                                                                          
    tv = *(FILETIME *)&pFRec[32];
    if ((tv.dwLowDateTime != 0)) {
        accountExpiryDate = tv;
    }

    // get acct expiry date                                                                                          
    tv = *(FILETIME *)&pFRec[40];
    if ((tv.dwLowDateTime != 0)) {
        lastFailedLoginDate = tv;
    }


    acbFlags = makeWORD(&pFRec[56]);
    loginCount = makeWORD(&pFRec[66]);

    return rc;
}
