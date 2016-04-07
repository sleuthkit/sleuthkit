/*
 * Autopsy Forensic Browser
 *
 * Copyright 2011-2015 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.datamodel;

import org.sleuthkit.datamodel.TskData.DbType;

/**
 * The intent of this class is to hold any information needed to connect to a
 * remote database server, except for the actual database name. This does not
 * hold information to connect to a local database such as SQLite.
 *
 * It can be used generically to hold remote database connection information.
 */
public class CaseDbConnectionInfo {

	private String hostNameOrIP;
	private String portNumber;
	private String userName;
	private String password;
	private DbType dbType;

	/**
	 * The intent of this class is to hold any information needed to connect to
	 * a remote database server, except for the actual database name. This does
	 * not hold information to connect to a local database such as SQLite.
	 *
	 * It can be used generically to hold remote database connection
	 * information.
	 *
	 * @param hostNameOrIP the host name
	 * @param portNumber   the port number
	 * @param userName     the user name
	 * @param password     the password
	 * @param dbType       the database type
	 */
	public CaseDbConnectionInfo(String hostNameOrIP, String portNumber, String userName, String password, DbType dbType) {
		this.hostNameOrIP = hostNameOrIP;
		this.portNumber = portNumber;
		this.userName = userName;
		this.password = password;
		if (dbType == DbType.SQLITE) {
			throw new IllegalArgumentException("SQLite database type invalid for CaseDbConnectionInfo. CaseDbConnectionInfo should be used only for remote database types.");
		}
		this.dbType = dbType;
	}

	public DbType getDbType() {
		return this.dbType;
	}

	public String getHost() {
		return this.hostNameOrIP;
	}

	public String getPort() {
		return this.portNumber;
	}

	public String getUserName() {
		return this.userName;
	}

	public String getPassword() {
		return this.password;
	}

	public void setDbType(DbType db) {
		this.dbType = db;
	}

	public void setHost(String host) {
		this.hostNameOrIP = host;
	}

	public void setPort(String port) {
		this.portNumber = port;
	}

	public void setUserName(String user) {
		this.userName = user;
	}

	public void setPassword(String pass) {
		this.password = pass;
	}
}
