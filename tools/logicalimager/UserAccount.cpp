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

#include "UserAccount.h"

UserAccount::UserAccount(std::string aUserName) :
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
std::string UserAccount::getAccountStatus() const {

	std::string accountStatus;

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
