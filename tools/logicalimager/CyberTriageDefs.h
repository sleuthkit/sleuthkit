/***************************************************************************
** This data and information is proprietary to, and a valuable trade secret
** of, Basis Technology Corp.  It is given in confidence by Basis Technology
** and may only be used as permitted under the license agreement under which
** it has been distributed, and in no other way.
**
** Copyright (c) 2014 Basis Technology Corp. All rights reserved.
**
** The technical data and information provided herein are provided with
** `limited rights', and the computer software provided herein is provided
** with `restricted rights' as those terms are defined in DAR and ASPR
** 7-104.9(a).
***************************************************************************/

#pragma once

#include "ThreatDefs.h"
#include "TskHelper.h"

const unsigned int RECENT_RUN_THRESHOLD_SECS = 15 * 24 * 60 * 60;  // 15 days

namespace NAMEMATCH_TYPE {
    enum Enum {
        NMT_PREFIX,
        NMT_SUBSTR,
        NMT_EXACT,
        NMT_UNKNOWN
    };
};

namespace ACTIVITY_MODERATOR_TYPE {
    enum Enum {
        BAM,
        DAM
    };
};

namespace ERRORTYPE {
    enum Enum {
        ET_CRITICAL,
        ET_MAJOR,
        ET_MINOR,
        ET_WARNING,
        ET_UNKNOWN
    };
    static char String[][100] = {
        "CRITICAL",
        "MAJOR",
        "MINOR",
        "WARNING",
        "UNKNOWN"
    };
};

/*
 * KnownSuspiciousFile: defines a black-listed file name
 */
class KnownSuspiciousFileName {
public:
    KnownSuspiciousFileName(string aFileNamePrefix, const ThreatCriteria* aCriteria);
    ~KnownSuspiciousFileName(void);

public:
    string getName() const { return m_namePrefix; };
    const ThreatCriteria* getCriteria() const { return m_criteria; };
    bool isMatch(string aLowerCaseName) const { return TskHelper::startsWith(aLowerCaseName, m_namePrefix); };;

private:
    string m_namePrefix;
    const ThreatCriteria* m_criteria;
};

namespace USER_ACCOUNT_LOCATION {
    enum Enum {
        LOCAL_ACCOUNT,
        DOMAIN_ACCOUNT,
        UNKNOWN
    };
    static char String[][100] = {
        "local",
        "domain controller",
        "UNKNOWN"
    };
};

/**
 * This enum is also defined on JAVA side.
 * Keep in sync when making changes.
 */
namespace USER_ACCOUNT_TYPE {
    enum Enum {
        REGULAR,		// normal user account
        LIMITED,		// Limited/Guest account
        SERVICE,		// 
        UNKNOWN,
    };
    static char String[][100] = {
        "Regular",
        "Limited",
        "Service",
        "Unknown"
    };
};

namespace USER_ADMIN_PRIV {
    enum Enum {
        YES,
        NO,
        UNKNOWN,
    };
    static char String[][100] = {
        "Yes",
        "No",
        "Unknown"
    };
};

class UserAccount {
public:
    UserAccount(string aUserName);
    ~UserAccount();

    // Overrides
    string getItemJSONName() const { return "userAccount"; };

    void setAccountType(USER_ACCOUNT_TYPE::Enum aType) { m_accountType = aType; }
    void setAdminPriv(USER_ADMIN_PRIV::Enum aPriv) { m_adminPriv = aPriv; }
    void setUserDomain(const string aDomain) { m_userDomain = aDomain; };
    void setSID(const string aSID) { m_SID = aSID; };
    void setHomeDir(const string aDir) { m_userHomeDir = aDir; };
    void setDateCreated(const string aDateStr) { m_dateCreatedStr = aDateStr; };
    void setLastLoginDate(const string aDateStr) { m_lastLoginDateStr = aDateStr; };
    void setLoginCount(const string aCountStr) { m_loginCountStr = aCountStr; };
    void setAccountLocation(USER_ACCOUNT_LOCATION::Enum aLocn) { m_accountLocation = aLocn; };
    void setDisabled(bool a_bool) { m_isDisabled = a_bool; };

    string getUserName() const { return m_userName; };
    string getUserDomain() const { return m_userDomain; };
    string getSID() const { return m_SID; };
    string getHomeDir() const { return m_userHomeDir; };
    string getAccountType() const { return USER_ACCOUNT_TYPE::String[m_accountType]; };
    string getAdminPriv() const { return USER_ADMIN_PRIV::String[m_adminPriv]; };
    string getDateCreated() const { return m_dateCreatedStr; };
    string getLastLoginDate() const { return m_lastLoginDateStr; };
    string getLoginCount() const { return m_loginCountStr; };
    USER_ACCOUNT_LOCATION::Enum getAccountLocation() const { return m_accountLocation; };
    string getAccountLocationStr() const { return USER_ACCOUNT_LOCATION::String[m_accountLocation]; };
    bool isDisabled() const { return m_isDisabled; };

    string getAccountStatus() const;

private:
    string m_userName;
    string m_userDomain;
    string m_SID;
    string m_userHomeDir;
    USER_ACCOUNT_TYPE::Enum m_accountType;
    USER_ADMIN_PRIV::Enum m_adminPriv;
    string m_dateCreatedStr;
    string m_lastLoginDateStr;
    string m_loginCountStr;
    USER_ACCOUNT_LOCATION::Enum m_accountLocation;   // local or domain
    bool m_isDisabled;
};

// Stores info for a configured service
class SvcInfo {
public:
    SvcInfo(string& a_name, DWORD a_type, string& a_groupName, string& a_PathName);
    ~SvcInfo();

    string getName() const { return m_svcName; }
    string getGroupName() const { return m_svcGroupName; }
    string getPathName() const { return m_svcPathName; }

private:
    string m_svcName;			// name only
    DWORD  m_svcType;			// svc type
    string m_svcGroupName;		// group name, if svc type is SHARED_PROCESSS
    string m_svcPathName;		// executable's pathname
};

// Stores info about a running Service - pid/name etc.
class RunningService {
public:
    RunningService(long a_pid, string& a_serviceName);
    ~RunningService();

    void setDisplayName(string & a_dispName) { m_displayName = a_dispName; };
    void setSvcType(DWORD a_svcType) { m_serviceType = a_svcType; };

    long getPID() const { return m_procId; }
    DWORD getSvcType() const { return m_serviceType; }
    string getName() const { return m_serviceName; }
    string getDisplayName() const { return m_displayName; }

private:
    long   m_procId;
    DWORD  m_serviceType;
    string m_serviceName;
    string m_displayName;
};

// Stores info about a host
class HostInfo {
public:
    HostInfo(string& aHostName);
    ~HostInfo();

    void setHostFQDN(const string & aHostFQDN) { m_hostFQDN = aHostFQDN; };

    string getHostName() const { return m_hostName; };
    string getHostFQDN() const { return m_hostFQDN; };

private:
    string m_hostName;
    string m_hostFQDN;
    string m_hostIP;
};

/*
 * AppGUIDInfo: captures information applications with GUID
 *
 * An Application GUID (either CLSID or AppID) may be mapped to an executable
 * Alternatively, it may map to a string ProgID or a Service name which are then in turn mapped to an executable
 */
class AppGUIDInfo {
public:
    AppGUIDInfo();
    AppGUIDInfo(const string& aGUID);

    string getGUID() const { return m_appGUID; }
    wstring getExe() const { return m_exe; }
    wstring getWow6432Exe() const { return m_wow6432Exe; }
    string getProgID() const { return m_progID; }
    string getServiceName() const { return m_serviceName; }

    void setGUID(const string & a_GUID) { m_appGUID = a_GUID; }
    void setExe(const wstring& aPath) { m_exe = aPath; };
    void setWow6432Exe(const wstring& aPath) { m_wow6432Exe = aPath; };
    void setProgID(const string & a_progID) { m_progID = a_progID; };
    void setServiceName(const string & a_name) { m_serviceName = a_name; };

    void copy(const AppGUIDInfo& a_src);

private:
    string m_appGUID;
    wstring m_exe; // name, with or without path, of the executable
    wstring m_wow6432Exe;	// name, usualy with path, of the WOW6432 executable
    string m_progID;
    string m_serviceName;
};

/*
 * AppCompatCacheEntry: captures information found in AppCompat cache
 */
class AppCompatCacheEntry {
public:
    AppCompatCacheEntry(const wstring& exePathName);
    ~AppCompatCacheEntry();

    wstring getExePathname() const { return exePathName; }
    FILETIME getEntryUpdateTime() const { return entryUpdateTime; }
    FILETIME getExeModTime() const { return exeModifyTime; }
    bool isExecuted() const { return isExeExecuted; }

    void setExePathname(const wstring& aPath) { exePathName = aPath; };
    void setEntryUpdateTime(const FILETIME& a_ft) { entryUpdateTime = a_ft; }
    void setExeModTime(const FILETIME& a_ft) { exeModifyTime = a_ft; }
    void setIsExecuted(bool a_bool) { isExeExecuted = a_bool; }

private:
    wstring exePathName;

    FILETIME entryUpdateTime;	// Not available for all versions of Windows, when available, can be interpreted as the most recent execution time;
    FILETIME exeModifyTime;		// last modify time on the exe file

    bool isExeExecuted;			// was the exe actually executed ?
    DWORD insertFlags;
    DWORD shimFlags;
};