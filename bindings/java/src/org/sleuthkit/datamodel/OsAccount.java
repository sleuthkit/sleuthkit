/*
 * Sleuth Kit Data Model
 *
 * Copyright 2020 Basis Technology Corp.
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

import java.util.Optional;

/**
 * Abstracts an OS User account. 
 * 
 * A user may own  files and (some) artifacts.
 * 
 */
public class OsAccount {

	final static long NO_USER = -1;
	final static String NULL_UID_STR = null;
	
	private final long rowId;	// row id in the tsk_os_accounts table
	private final long dataSourceObjId;
	private final String userName;	// user login name - may be null
	private final String realm;		// realm where the username is unique - a domain or a host name, may be null
	private final String uniqueId;	// a unique sid/uid, may be null
	private final String signature; // some to uniquely identify this user - either the uid or the realm/userName.
	private final Long artifactObjId; // object id of the backing artifact, may be null if one hasnt been created yet.

	
	/** 
	 * Creates an OsAccount with a realm/username and unique id, and signature
	 */
	OsAccount(long rowId, long dataSourceObjId, String userName, String realm,  String uniqueId, String signature, long artifactObjId ) {
		
		this.rowId = rowId;
		this.dataSourceObjId = dataSourceObjId;
		this.uniqueId = uniqueId;
		this.userName = userName;
		this.realm = realm;
		this.signature = signature;
		this.artifactObjId = artifactObjId;
	}
	
	public long getRowId() {
		return rowId;
	}
	
	public long getDataSourceObjId() {
		return dataSourceObjId;
	}
	
	public Optional<String> getUniqueId() {
		return Optional.ofNullable(uniqueId);
	}

	public String getSignature() {
		return signature;
	}
	
	public Optional<String> getRealm() {
		return Optional.ofNullable(realm);
	}

	public Optional<String> getUserName() {
		return Optional.ofNullable(userName);
	}
	
	public Optional<Long> getArtifactObjId() {
		return Optional.ofNullable(artifactObjId);
	}
}