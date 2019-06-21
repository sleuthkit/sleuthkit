/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2010-2019 Brian Carrier.  All Rights reserved
**
** This software is distributed under the Common Public License 1.0
**
*/

#include <string>

#include "UserAccount.h"

UserAccount::UserAccount(std::string &aUserName) :
	m_userName(aUserName),
	m_userDomain(""),
	m_userHomeDir(""),
	m_accountType(USER_ACCOUNT_TYPE::UNKNOWN),
	m_adminPriv(USER_ADMIN_PRIV::UNKNOWN),
	m_accountLocation(USER_ACCOUNT_LOCATION::UNKNOWN),
	m_SID(""),
	m_isDisabled(false),
    m_loginCount(0)
{
}

UserAccount:: ~UserAccount(void) {
}

/**
 * getAccountStatus - returns an accounts enabled/disbaled status as a string
 *
 * @returns - account status
 */
std::string UserAccount::getAccountStatus() const {

	std::string accountStatus;

	// For local account we know definitively if an account is enabled or disabled
	if (USER_ACCOUNT_LOCATION::LOCAL_ACCOUNT == m_accountLocation) {
		if (isDisabled())
			accountStatus = "Disabled";
		else
			accountStatus = "Enabled";
	}
	else {
		accountStatus = "Unknown";
	}

	return accountStatus;
}
