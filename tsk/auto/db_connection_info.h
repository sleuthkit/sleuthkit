/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2010-2013 Brian Carrier.  All Rights reserved
**
** This software is distributed under the Common Public License 1.0
**
*/

/**
* \file db_connection_info.h
* Contains multi-user database connection information. 
*/

#ifndef _DB_CONNECTION_INFO_H
#define _DB_CONNECTION_INFO_H

#include <string>
using std::string;

class CaseDbConnectionInfo 
{	
public: 
    
	enum DbType
	{
		// Add any additional remote database types here, and keep it in sync 
		// with the JNI version of this enum located at:
		// sleuthkit/bindings/java/src/org/sleuthkit/datamodel/TskData.java
		// Be sure to add to settingsValid() if you add a type here.
		UNKNOWN = 0,
		POSTGRESQL = 1
	};

private:
	string hostNameOrIP;
	string portNumber;
	string userName;
	string password;
	DbType dbType;

public:

	CaseDbConnectionInfo(string lhostNameOrIP, string lportNumber, string luserName, string lpassword, DbType ldbType) {
		this->hostNameOrIP = lhostNameOrIP;
		this->portNumber = lportNumber;
		this->userName = luserName;
		this->password = lpassword;
		this->dbType = ldbType;
	}

	DbType getDbType() {
		return this->dbType;
	}

	string getHost() {
		return this->hostNameOrIP;
	}

	string getPort() {
		return this->portNumber;
	}

	string getUserName() {
		return this->userName;
	}

	string getPassword() {
		return this->password;
	}
};

#endif //_DB_CONNECTION_INFO_H