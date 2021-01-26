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
 * Encapsulates the scope of an OsAccount. An account is unique within a realm.
 *
 * The realm may be comprised of a single host, say for a local account, or a
 * domain.
 */
public final class OsAccountRealm {

	private final long id;	// row id 
	private final String name;
	private final String uniqueId;
	private final Host host;	// if the realm consists of a single host, may be null
	private final RealmNameType nameType;	// if the realm is inferred

	
	
	public OsAccountRealm(long id, String name, RealmNameType nameType, String uniqueId, Host host) {
		this.id = id;
		this.name = name;
		this.uniqueId = uniqueId;
		this.host = host;
		this.nameType = nameType;
	}

	/**
	 * Get the realm row id. 
	 * 
	 * @return Realm id.
	 */
	public long getId() {
		return id;
	}

	/**
	 * Get the realm name.
	 *
	 * @return Realm name.
	 */
	public String getName() {
		return name;
	}

	/**
	 * Get the realm uniqueId/SID.
	 *
	 * @return Optional realm unique id..
	 */
	public Optional<String> getUniqueId() {
		return Optional.ofNullable(uniqueId);
	}

	/**
	 * Get the realm host, if it's a single host realm.
	 * 
	 * @return Optional host.
	 */
	public Optional<Host> getHost() {
		return Optional.ofNullable(host);
	}

	/**
	 * Get realm name type.
	 * 
	 * @return Realm name type. 
	 */
	public RealmNameType getNameType() {
		return nameType;
	}
	
	
	/**
	 * Enum to encapsulate realm name type. 
	 * 
	 * Realm name may be explicitly expressed, say in an event log.
	 * Occasionally, a name may be inferred  (e.g. for stand alone machines)
	 */
	public enum RealmNameType {
		EXPRESSED(0, "Expressed"),	// realm name was explicitly expressed 
		INFERRED(1, "Inferred");	// name is inferred

		private final int id;
		private final String name; 

		RealmNameType(int id, String name) {
			this.id = id;
			this.name = name;
		}

		/**
		 * Get the id of the realm name type.
		 * 
		 * @return Realm name type id.
		 */
		public int getId() {
			return id;
		}
		
		/**
		 * Get the realm name type name.
		 * 
		 * @return Realm name type name.
		 */
		String getName() {
			return name;
		}
		
		/**
		 * Gets a realm name type enum by id. 
		 * 
		 * @param typeId Realm name type id.
		 * 
		 * @return RealmNameType enum.
		 */
		public static RealmNameType fromID(int typeId) {
			for (RealmNameType statusType : RealmNameType.values()) {
				if (statusType.ordinal() == typeId) {
					return statusType;
				}
			}
			return null;
		}
	}
	
}
