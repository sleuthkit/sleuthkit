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

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.ResourceBundle;
import org.apache.commons.lang3.StringUtils;

/**
 * Realm encapsulates the scope of an OsAccount. An account is unique within a realm.
 *
 * A realm may be host scoped, say for a local standalone computer, or 
 * domain scoped.
 *
 * Many times, we may learn about the existence of a realm without fully understanding
 * it. Such as when we find a Windows SID before we've parsed the registry to know if
 * it is for the local computer or domain. By default, a realm is created with a 
 * host-level scope and a confidence of "inferred". 
 */
public final class OsAccountRealm {
	
	private static final ResourceBundle bundle = ResourceBundle.getBundle("org.sleuthkit.datamodel.Bundle");

	private final long id;	// row id 
	
	// a realm may have multiple names - for exmple, for a user ABCCorp\\user1 or user1@ABCcorp.com - 'ABCCorp' and 'ABCcorp.com' both refer to the same realm.
	// currently we only support a single name, this could be expanded in future.
	private final String realmName; // realm name
	
	private final String realmAddr; // realm address
	private String signature; // either realm address or name (if address is not known)
	private final Host host;	// if the realm consists of a single host.  Will be null if the realm is domain scoped. 
	private final ScopeConfidence scopeConfidence; // confidence in realm scope.
	private final RealmDbStatus dbStatus; // Status of row in database.
	
	/**
	 * Creates OsAccountRealm.
	 * 
	 * @param id              Row Id.
	 * @param realmName       Realm name, may be null.
	 * @param realmAddr       Unique numeric address for realm, may be null only
	 *                        if realm name is not null.
	 * @param signature       Either the address or the name.
	 * @param host            Host if the realm is host scoped.
	 * @param scopeConfidence Scope confidence.
	 */
	OsAccountRealm(long id, String realmName, String realmAddr, String signature, Host host, ScopeConfidence scopeConfidence, RealmDbStatus dbStatus) {
		this.id = id;
		this.realmName = realmName;
		this.realmAddr = realmAddr;
		this.signature = signature;
		this.host = host;
		this.scopeConfidence = scopeConfidence;
		this.dbStatus = dbStatus;
	}

	/**
	 * Get the realm row id. 
	 * 
	 * @return Realm id.
	 */
	long getRealmId() {
		return id;
	}

	/**
	 * Get realm names list.
	 *
	 * Currently we only support a single name for realm, so this list may have
	 * at most a single name. And the list may be empty if there is no name.
	 *
	 * @return List of realm names, may be empty.
	 */
	public List<String> getRealmNames() {
		List<String> namesList = new ArrayList<>();
		if (!Objects.isNull(realmName)) {
			namesList.add(realmName);
		}

		return namesList;
	}

	/**
	 * Get the realm address, such as part of a Windows SID. 
	 *
	 * @return Optional realm unique address.
	 */
	public Optional<String> getRealmAddr() {
		return Optional.ofNullable(realmAddr);
	}

	/**
	 * Get the realm signature.
	 *
	 * @return Realm signature.
	 */
	String getSignature() {
		return signature;
	}
	
	/**
	 * Get the realm scope host, if it's a single host realm.
	 * 
	 * @return Optional host. Is empty if the scope of the realm is domain-scoped.
	 */
	public Optional<Host> getScopeHost() {
		return Optional.ofNullable(host);
	}

	/**
	 * Get realm scope confidence.
	 * 
	 * @return Realm scope confidence. 
	 */
	public ScopeConfidence getScopeConfidence() {
		return scopeConfidence;
	}
	
	/**
	 * Get the database status of this realm.
	 * 
	 * @return Realm database status. 
	 */
	public RealmDbStatus getDbStatus() {
		return dbStatus;
	}	

	/**
	 * Get the realm scope.
	 * 
	 * @return Realm scope.
	 */
	public RealmScope getScope() {
		return getScopeHost().isPresent() ? RealmScope.LOCAL : RealmScope.DOMAIN; 
	}
	
	/**
	 * Enum to encapsulate a realm scope.
	 *
	 * Scope of a realm may extend to a single host (local) 
	 * or to a domain.
	 */
	public enum RealmScope {
		UNKNOWN(0,	bundle.getString("OsAccountRealm.Unknown.text")),			// realm scope is unknown.
		LOCAL(1,	bundle.getString("OsAccountRealm.Local.text")),				// realm scope is a single host.
		DOMAIN(2,	bundle.getString("OsAccountRealm.Domain.text"));			// realm scope is a domain.
		
		private final int id;
		private final String name; 

		RealmScope(int id, String name) {
			this.id = id;
			this.name = name;
		}

		/**
		 * Get the id of the realm scope.
		 * 
		 * @return Realm scope id.
		 */
		public int getId() {
			return id;
		}
		
		/**
		 * Get the realm scope name.
		 * 
		 * @return Realm scope name.
		 */
		public String getName() {
			return name;
		}
		
		/**
		 * Gets a realm scope confidence enum by id. 
		 * 
		 * @param typeId Realm scope confidence id.
		 * 
		 * @return ScopeConfidence enum.
		 */
		public static RealmScope fromID(int typeId) {
			for (RealmScope scopeType : RealmScope.values()) {
				if (scopeType.ordinal() == typeId) {
					return scopeType;
				}
			}
			return null;
		}
	}
	
	/**
	 * Enum to encapsulate scope confidence.
	 *
	 * We may know for sure that a realm is domain scope or host scope, based
	 * on where it is found. Occasionally, we may have to infer or assume a scope to
	 * initially create a realm.
	 */
	public enum ScopeConfidence {
		KNOWN(0, bundle.getString("OsAccountRealm.Known.text")),			// realm scope is known for sure.
		INFERRED(1, bundle.getString("OsAccountRealm.Inferred.text"));	// realm scope is inferred

		private final int id;
		private final String name; 

		ScopeConfidence(int id, String name) {
			this.id = id;
			this.name = name;
		}

		/**
		 * Get the id of the realm scope confidence.
		 * 
		 * @return Realm scope confidence id.
		 */
		public int getId() {
			return id;
		}
		
		/**
		 * Get the realm scope confidence name.
		 * 
		 * @return Realm scope confidence name.
		 */
		public String getName() {
			return name;
		}
		
		/**
		 * Gets a realm scope confidence enum by id. 
		 * 
		 * @param typeId Realm scope confidence id.
		 * 
		 * @return ScopeConfidence enum.
		 */
		public static ScopeConfidence fromID(int typeId) {
			for (ScopeConfidence statusType : ScopeConfidence.values()) {
				if (statusType.ordinal() == typeId) {
					return statusType;
				}
			}
			return null;
		}
	}
		
	 /**
	  * Set the signature for the account realm.
	  * 
	  * @param signature Realm signature.
	  * 
	  * @return Returns true of the address is set, false if the address was not
	 *         changed.
	  */
	boolean setSignature(String signature) {
		if (StringUtils.isNotBlank(signature)) {
			this.signature = signature;
			return true;
		}
		
		return false;
	}
	
	
	/**
	 * Encapsulates status of realm row.
	 */
	public enum RealmDbStatus {
		ACTIVE(0, "Active"),
		MERGED(1, "Merged"),
		DELETED(2, "Deleted");	

		private final int id;
		private final String name;

		RealmDbStatus(int id, String name) {
			this.id = id;
			this.name = name;
		}

		public int getId() {
			return id;
		}

		String getName() {
			return name;
		}

		public static RealmDbStatus fromID(int typeId) {
			for (RealmDbStatus type : RealmDbStatus.values()) {
				if (type.ordinal() == typeId) {
					return type;
				}
			}
			return null;
		}
	}
	
}
