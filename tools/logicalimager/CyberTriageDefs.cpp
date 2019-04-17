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

#include <string>

#include "CyberTriageDefs.h"

using namespace std;

AppGUIDInfo::AppGUIDInfo() {
	m_appGUID.clear();
	m_exe.clear();
	m_wow6432Exe.clear();
	m_progID.clear();
	m_serviceName.clear();
}

AppGUIDInfo::AppGUIDInfo(const string& aGUID) :
	m_appGUID(aGUID)
{
	m_exe.clear();
	m_wow6432Exe.clear();
	m_progID.clear();
	m_serviceName.clear();
}

/**
 * copy - copies data from the given AppGUIDInfo, except for the GUID
 *
 * @param IN a_src - source AppGUIDInfo to copy from
 * @returns none
 */
void AppGUIDInfo::copy(const AppGUIDInfo& a_src) {

	m_exe = a_src.getExe();
	m_wow6432Exe = a_src.getWow6432Exe();
	m_progID = a_src.getProgID();
	m_serviceName = a_src.getServiceName();

}

KnownSuspiciousFileName::KnownSuspiciousFileName(string aProgNamePrefix, const ThreatCriteria* aCriteria) :
	m_namePrefix(aProgNamePrefix),
	m_criteria(aCriteria)
{

}

KnownSuspiciousFileName:: ~KnownSuspiciousFileName(void) {
	m_criteria = NULL;
}


UserAccount::UserAccount(string aUserName) :
	m_userName(aUserName),
	m_userDomain(""),
	m_userHomeDir(""),
	m_accountType(USER_ACCOUNT_TYPE::UNKNOWN),
	m_adminPriv(USER_ADMIN_PRIV::UNKNOWN),
	m_accountLocation(USER_ACCOUNT_LOCATION::UNKNOWN),
	m_SID(""),
	m_isDisabled(false)
{

}

UserAccount:: ~UserAccount(void) {
}

/**
 * getAccountStatus - returns an accounts enabled/disbaled status as a string
 *
 * @returns - account status
 */
string UserAccount::getAccountStatus() const {

	string accountStatus;

	// For local account we know definitively if an account is enabled or disabled
	if (USER_ACCOUNT_LOCATION::LOCAL_ACCOUNT == m_accountLocation) {
		if (isDisabled())
			accountStatus += "Disabled";
		else
			accountStatus += "Enabled";
	}
	else {
		accountStatus = "Unknown";
	}

	return accountStatus;
}

SvcInfo::SvcInfo(string& a_name, DWORD a_svcType, string& a_groupName, string& a_pathName) :
	m_svcName(a_name),
	m_svcType(a_svcType),
	m_svcGroupName(a_groupName),
	m_svcPathName(a_pathName)
{
}

SvcInfo::~SvcInfo() {
}


RunningService::RunningService(long a_pid, string& a_serviceName) :
	m_procId(a_pid),
	m_serviceName(a_serviceName)
{
}
RunningService::~RunningService() {
}


HostInfo::HostInfo(string& aHostName) :
	m_hostName(aHostName)
{
	m_hostFQDN.clear();
	m_hostIP.clear();
}
HostInfo::~HostInfo() {
}



AppCompatCacheEntry::AppCompatCacheEntry(const wstring& a_exePathName) :
	exePathName(a_exePathName)
{
	FILETIME ft_unkown = { 0, 0 };
	entryUpdateTime = ft_unkown;
	exeModifyTime = ft_unkown;

	isExeExecuted = false;
	insertFlags = 0;
	shimFlags = 0;
}

AppCompatCacheEntry::~AppCompatCacheEntry() {
}
