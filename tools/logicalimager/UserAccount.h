/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2010-2019 Brian Carrier.  All Rights reserved
**
** This software is distributed under the Common Public License 1.0
**
*/

#pragma once

#include "TskHelper.h"

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
    UserAccount(std::string &aUserName);
    ~UserAccount();

    std::string getItemJSONName() const { return "userAccount"; };

    void setAccountType(USER_ACCOUNT_TYPE::Enum aType) { m_accountType = aType; }
    void setAdminPriv(USER_ADMIN_PRIV::Enum aPriv) { m_adminPriv = aPriv; }
    void setUserDomain(const std::string &aDomain) { m_userDomain = aDomain; };
    void setSID(const std::string &aSID) { m_SID = aSID; };
    void setHomeDir(const std::string &aDir) { m_userHomeDir = aDir; };
    void setDateCreated(const std::string &aDateStr) { m_dateCreatedStr = aDateStr; };
    void setLastLoginDate(const std::string &aDateStr) { m_lastLoginDateStr = aDateStr; };
    void setLoginCount(uint16_t aCount) { m_loginCount = aCount; };
    void setAccountLocation(USER_ACCOUNT_LOCATION::Enum aLocn) { m_accountLocation = aLocn; };
    void setDisabled(bool a_bool) { m_isDisabled = a_bool; };

    std::string getUserName() const { return m_userName; };
    std::string getUserDomain() const { return m_userDomain; };
    std::string getSID() const { return m_SID; };
    std::string getHomeDir() const { return m_userHomeDir; };
    std::string getAccountType() const { return USER_ACCOUNT_TYPE::String[m_accountType]; };
    std::string getAdminPriv() const { return USER_ADMIN_PRIV::String[m_adminPriv]; };
    std::string getDateCreated() const { return m_dateCreatedStr; };
    std::string getLastLoginDate() const { return m_lastLoginDateStr; };
    uint16_t getLoginCount() const { return m_loginCount; };
    USER_ACCOUNT_LOCATION::Enum getAccountLocation() const { return m_accountLocation; };
    std::string getAccountLocationStr() const { return USER_ACCOUNT_LOCATION::String[m_accountLocation]; };
    bool isDisabled() const { return m_isDisabled; };
    std::string getAccountStatus() const;

private:
    std::string m_userName;
    std::string m_userDomain;
    std::string m_SID;
    std::string m_userHomeDir;
    USER_ACCOUNT_TYPE::Enum m_accountType;
    USER_ADMIN_PRIV::Enum m_adminPriv;
    std::string m_dateCreatedStr;
    std::string m_lastLoginDateStr;
    uint16_t m_loginCount;
    USER_ACCOUNT_LOCATION::Enum m_accountLocation;   // local or domain
    bool m_isDisabled;
};

