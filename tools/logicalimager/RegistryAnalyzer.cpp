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
#include <vector>
#include <map>

#include "RegistryAnalyzer.h"
#include "tsk/tsk_tools_i.h"
#include "TskHelper.h"
#include "RegHiveType.h"
#include "RegParser.h"
#include "RegistryLoader.h"
#include "UserAccount.h"

const std::string LOCAL_DOMAIN = "local";

RegistryAnalyzer::RegistryAnalyzer(const std::string &outputFilePath) :
    m_outputFilePath(outputFilePath)
{
    m_outputFile = fopen(m_outputFilePath.c_str(), "w");
    if (!m_outputFile) {
        fprintf(stderr, "ERROR: Failed to open alert file %s\n", m_outputFilePath.c_str());
        exit(1);
    }
    fprintf(m_outputFile, "UserName\tFullName\tUserDomain\tHomeDir\tAccountType\tAdminPriv\tDateCreated\tLastLoginDate\tLastFailedLoginDate\tLastPasswordResetDate\tLoginCount\tAccountLocation\tisDisabled\taccountStatus\n");
}

RegistryAnalyzer::~RegistryAnalyzer() {
    if (m_outputFile) {
        fclose(m_outputFile);
    }
}

RegHiveType::Enum RegistryAnalyzer::hiveNameToType(const std::string &aName) const
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
std::string getTimeStr(time_t aTime, unsigned long a_fractionSecs = 0) {

    std::string retStr;
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
    std::string fractionStr = ss.str();
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
std::string FiletimeToStr(FILETIME filetime) {
    if (filetime.dwLowDateTime == 0 && filetime.dwHighDateTime == 0)
        return "Unknown";
    return getTimeStr(filetimeToTimet(filetime));
}

/**
* samUserTypeToAccountType - maps SAM user account type to user acccount type.
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
    std::map<std::wstring, FILETIME> acctCreationDateMap;
    RegFileInfo *aRegFile = RegistryLoader::getInstance().getSAMHive();
    if (aRegFile == NULL) {
        fprintf(m_outputFile, "SAM HIVE not found\n");
        fclose(m_outputFile);
        std::cerr << "ERROR: SAM HIVE not found" << std::endl;
        return -1;
    }
    RegParser &aRegParser = aRegFile->getRegParser();

    // std::cout << "Registry: Analyzing SAM Users" << std::endl;

    // First collect the known user names and their account creation time.  
    // Account creation time corresponds with creation of a user name key
    std::wstring wsSAMUserNamesKeyName = L"SAM\\Domains\\Account\\Users\\Names";
    std::vector<std::wstring> wsUserNameSubkeys;
    int rc;
    try {
        rc = aRegParser.getSubKeys(wsSAMUserNamesKeyName, wsUserNameSubkeys);
        if (0 == rc) {
            for (std::vector<std::wstring>::iterator it = wsUserNameSubkeys.begin(); it != wsUserNameSubkeys.end(); ++it) {
                std::wstring wsName = (*it);
                std::wstring wsKeyName = wsSAMUserNamesKeyName + L"\\" + wsName;
                RegKey *pUserNameSubkey = new RegKey(wsKeyName);
                if (0 == aRegParser.getKey(wsKeyName, *pUserNameSubkey)) {
                    FILETIME ft = { 0, 0 };
                    pUserNameSubkey->getModifyTime(ft);
                    acctCreationDateMap[wsName] = ft;
                }
                delete pUserNameSubkey;
            }
        }
        else if (-2 == rc) {
            std::string errMsg = "analyzeSAMUsers: Error getting key  = " + TskHelper::toNarrow(wsSAMUserNamesKeyName) + " Local user accounts may not be reported.";
            std::string details = "analyzeSAMUsers() failed.";
            std::cerr << errMsg << std::endl;
            rc = -1;
        }

        std::wstring wsSAMUsersKeyName = L"SAM\\Domains\\Account\\Users";
        std::vector<std::wstring> wsSubkeyNames;

        rc = aRegParser.getSubKeys(wsSAMUsersKeyName, wsSubkeyNames);
        if (0 == rc) {
            for (std::vector<std::wstring>::iterator it = wsSubkeyNames.begin(); it != wsSubkeyNames.end(); ++it) {
                if (TskHelper::startsWith(TskHelper::toNarrow((*it)), "0000")) {
                    std::wstring wsRID = (*it);
                    std::wstring wsSAMRIDKeyName = wsSAMUsersKeyName + L"\\" + wsRID;

                    bool bError = false;
                    std::wstring wsUserName(L"");
                    std::wstring wsFullName(L"");
                    std::wstring wsComment(L"");
                    std::string sUserName("");

                    uint32_t samAcctType = 0;
                    USER_ACCOUNT_TYPE::Enum acctType;
                    USER_ADMIN_PRIV::Enum acctAdminPriv;

                    // Get V Record
                    RegVal vRecord;
                    std::wstring wsVRecordValname = L"V";
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

                    std::string sDateCreated = "Unknown";
                    std::string sLastLoginDate;
                    std::string slastFailedLoginDate;
                    std::string slastPWResetDate;

                    uint16_t loginCount = 0;
                    uint16_t acbFlags = 0;
                    bool accountDisabled = false;

                    // GET F Record
                    RegVal fRecord;
                    std::wstring wsFRecordValname = L"F";
                    fRecord.setValName(wsFRecordValname);

                    if (0 == aRegParser.getValue(wsSAMRIDKeyName, wsFRecordValname, fRecord)) {
                        // Parse F Record
                        parseSAMFRecord(fRecord.getBinary(), fRecord.getValLen(), lastLoginDate, lastPWResetDate, accountExpiryDate, lastFailedLoginDate, loginCount, acbFlags);

                        sLastLoginDate = FiletimeToStr(lastLoginDate);
                        slastFailedLoginDate = FiletimeToStr(lastFailedLoginDate);
                        slastPWResetDate = FiletimeToStr(lastPWResetDate);

                        std::map<std::wstring, FILETIME>::iterator it = acctCreationDateMap.find(wsUserName);
                        if (it != acctCreationDateMap.end()) {
                            sDateCreated = FiletimeToStr(it->second);
                        }
                        else {
                            std::wcerr << "User name = " << wsUserName << " not found in acctCreationDateMap" << std::endl;
                        }

                        if ((acbFlags & 0x0001) == 0x0001)
                            accountDisabled = true;
                    }

                    if (!bError) {

                        // SAM is parsed first and has only local accounts. We assume none of these users already exist.
                        UserAccount userAccount(sUserName);

                        userAccount.setUserDomain(LOCAL_DOMAIN);   // this is a local account
                        userAccount.setAccountType(acctType);
                        userAccount.setAdminPriv(acctAdminPriv);

                        userAccount.setDateCreated(sDateCreated);
                        userAccount.setLastLoginDate(sLastLoginDate); //  Fri Jan 20 17:10:41 2012 Z
                        userAccount.setLoginCount(loginCount);
                        userAccount.setAccountLocation(USER_ACCOUNT_LOCATION::LOCAL_ACCOUNT);  // all accounts found in SAM registry are local (as opposed to Domain)
                        userAccount.setDisabled(accountDisabled); // from flags;

                        fprintf(m_outputFile, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%d\t%s\n",
                            userAccount.getUserName().c_str(),
                            TskHelper::toNarrow(wsFullName).c_str(),
                            userAccount.getUserDomain().c_str(),
                            userAccount.getHomeDir().c_str(),
                            userAccount.getAccountType().c_str(),
                            userAccount.getAdminPriv().c_str(),
                            userAccount.getDateCreated().c_str(),
                            userAccount.getLastLoginDate().c_str(),
                            slastFailedLoginDate.c_str(),
                            slastPWResetDate.c_str(),
                            userAccount.getLoginCount(),
                            userAccount.getAccountLocationStr().c_str(),
                            userAccount.isDisabled(),
                            userAccount.getAccountStatus().c_str()
                        );
                    }
                }
            }
        }
        else {
            std::string errMsg = "analyzeSAMUsers: Error getting key  = " + TskHelper::toNarrow(wsSAMUsersKeyName) + " Local user accounts may not be reported.";
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
            std::string errMsg = "RegisteryAnalyzer: Uncaught exception in analyzeSAMUsers.";
            std::cerr << errMsg << std::endl;
            std::cerr << e.what() << std::endl;
        }
        rc = -1;
    }
    fclose(m_outputFile);
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
        return std::wstring();

    std::wstring_convert<std::codecvt_utf16<wchar_t, 0x10ffff, std::little_endian>,
        wchar_t> conv;
    std::wstring ws = conv.from_bytes(
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
int RegistryAnalyzer::parseSAMVRecord(const unsigned char *pVRec, size_t aVRecLen, std::wstring& userName, std::wstring& userFullName, std::wstring& comment, uint32_t& acctType) const {

    int rc = 0;
    size_t off;
    int len;

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
