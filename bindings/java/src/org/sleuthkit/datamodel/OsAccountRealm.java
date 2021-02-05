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
 * Realm encapsulates the scope of an OsAccount. An account is unique within a realm.
 *
 * A realm may be host scoped, say for a local standalone computer, or 
 * domain scoped.
 */
public final class OsAccountRealm {

	private final long id;	// row id 
	private String realmName; // realm name - may be updated later.
	private String realmAddr; // realm address - may be updated later. 
	private String signature; // either realm name or address 
	private final Host host;	// if the realm consists of a single host, may be null
	private final ScopeConfidence scopeConfidence;

	
	
	/**
	 * Creates OsAccountRealm.
	 * 
	 * @param id Row Id.
	 * @param realmName Realm name, may be null.
	 * @param realmAddr Unique numeric address for realm, may be null only if realm name is not null.
	 * @param signature Either the address or the name.
	 * @param host Host if the realm is host scoped.
	 * @param scopeConfidence  Scope confidence.
	 */
	OsAccountRealm(long id, String realmName, String realmAddr, String signature, Host host, ScopeConfidence scopeConfidence) {
		this.id = id;
		this.realmName = realmName;
		this.realmAddr = realmAddr;
		this.signature = signature;
		this.host = host;
		this.scopeConfidence = scopeConfidence;
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
	 * @return Optional with realm name.
	 */
	public Optional<String> getRealmName() {
		return Optional.ofNullable(realmName);
	}

	/**
	 * Get the realm address.
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
	 * @return Optional host.
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
	 * Enum to encapsulate scope confidence.
	 *
	 * We may know for sure that a realm is domain scope or host scope, based
	 * on where it is found. Occasionally, we may have to infer or assume a scope to
	 * initially create a realm.
	 */
	public enum ScopeConfidence {
		KNOWN(0, "Known"),			// realm scope is known for sure.
		INFERRED(1, "Inferred");	// realm scope is inferred

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
		String getName() {
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
	
}
