/*
 * Sleuth Kit Data Model
 *
 * Copyright 2020-2021 Basis Technology Corp.
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
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Abstracts an OS user account.
 *
 * An OS user account may own files and (some) artifacts.
 *
 */
public final class OsAccount {

	final static long NO_USER = -1;
	final static String NULL_UID_STR = null;

	private final long id;	// row id in the tsk_os_accounts table
	private final OsAccountRealm realm;		// realm where the username is unique - a domain or a host name, may be null
	private final String loginName;	// user login name - may be null
	private final String uniqueId;	// a unique user sid/uid, may be null
	private final String signature; // something that uniquely identifies this user - either the uniqueId or the realmName/userName.

	private String fullName;	// full name
	private boolean isAdmin = false;	// is admin account.
	private OsAccountType osAccountType = OsAccountType.UNKNOWN;
	private OsAccountStatus osAccountStatus = OsAccountStatus.UNKNOWN;
	private long creationTime = 0;

	private final List<OsAccountAttribute> osAccountAttributes = new ArrayList<>();

	/**
	 * Encapsulates status of an account - whether is it active or disabled or
	 * deleted.
	 */
	public enum OsAccountStatus {
		UNKNOWN(0, "Unknown"),
		ACTIVE(1, "Active"),
		DISABLED(2, "Disabled"),
		DELETED(2, "Deleted");

		private final int id;
		private final String name;

		OsAccountStatus(int id, String name) {
			this.id = id;
			this.name = name;
		}

		/**
		 * Get account status id.
		 *
		 * @return Account status id.
		 */
		public int getId() {
			return id;
		}

		/**
		 * Get the account status enum name.
		 *
		 * @return
		 */
		String getName() {
			return name;
		}

		/**
		 * Gets account status enum from id.
		 *
		 * @param statusId Id to look for.
		 *
		 * @return Account status enum.
		 */
		public static OsAccountStatus fromID(int statusId) {
			for (OsAccountStatus statusType : OsAccountStatus.values()) {
				if (statusType.ordinal() == statusId) {
					return statusType;
				}
			}
			return null;
		}
	}

	/**
	 * Encapsulates an account type - whether its an interactive login account
	 * or a service account.
	 */
	public enum OsAccountType {
		UNKNOWN(0, "Unknown"),
		SERVICE(1, "Service"),
		INTERACTIVE(2, "Interactive");

		private final int id;
		private final String name;

		OsAccountType(int id, String name) {
			this.id = id;
			this.name = name;
		}

		/**
		 * Get account type id.
		 *
		 * @return Account type id.
		 */
		int getId() {
			return id;
		}

		/**
		 * Get account type name.
		 *
		 * @return Account type name.
		 */
		String getName() {
			return name;
		}

		/**
		 * Gets account type enum from id.
		 *
		 * @param typeId Id to look for.
		 *
		 * @return Account type enum.
		 */
		public static OsAccountType fromID(int typeId) {
			for (OsAccountType accountType : OsAccountType.values()) {
				if (accountType.ordinal() == typeId) {
					return accountType;
				}
			}
			return null;
		}
	}

	/**
	 * Describes the relationship between an os account instance and the host
	 * where the instance was found.
	 *
	 * Whether an os account actually performed any action on the host or if
	 * just a reference to it was found on the host.
	 */
	public enum OsAccountInstanceType {
		PERFORMED_ACTION_ON(0, "PerformedActionOn"), // the user performed actions on a host
		REFERENCED_ON(1, "ReferencedOn");	// user was simply referenced on a host

		private final int id;
		private final String name;

		OsAccountInstanceType(int id, String name) {
			this.id = id;
			this.name = name;
		}

		/**
		 * Get account instance type id.
		 *
		 * @return Account instance type id.
		 */
		public int getId() {
			return id;
		}

		/**
		 * Get account instance type name.
		 *
		 * @return Account instance type name.
		 */
		public String getName() {
			return name;
		}

		/**
		 * Gets account instance type enum from id.
		 *
		 * @param typeId Id to look for.
		 *
		 * @return Account instance type enum.
		 */
		public static OsAccountInstanceType fromID(int typeId) {
			for (OsAccountInstanceType statusType : OsAccountInstanceType.values()) {
				if (statusType.ordinal() == typeId) {
					return statusType;
				}
			}
			return null;
		}
	}

	/**
	 * Constructs an OsAccount with a realm/username and unique id, and
	 * signature
	 */
	OsAccount(long id, OsAccountRealm realm, String loginName, String uniqueId, String signature) {

		this.id = id;

		this.realm = realm;
		this.loginName = loginName;
		this.uniqueId = uniqueId;
		this.signature = signature;
	}

	/**
	 * Sets the account user's full name.
	 *
	 * @param fullName Full name.
	 */
	public void setFullName(String fullName) {
		this.fullName = fullName;
	}

	/**
	 * Sets the admin flag for the account.
	 *
	 * @param isAdmin Flag to indicate if the account is an admin account.
	 */
	public void setIsAdmin(boolean isAdmin) {
		this.isAdmin = isAdmin;
	}

	/**
	 * Sets account type for the account.
	 *
	 * @param osAccountType Account type..
	 */
	public void setOsAccountType(OsAccountType osAccountType) {
		this.osAccountType = osAccountType;
	}

	/**
	 * Sets account status for the account.
	 *
	 * @param osAccountStatus Account status.
	 */
	public void setOsAccountStatus(OsAccountStatus osAccountStatus) {
		this.osAccountStatus = osAccountStatus;
	}

	/**
	 * Set account creation time.
	 *
	 * @param creationTime Creation time.
	 */
	public void setCreationTime(long creationTime) {
		this.creationTime = creationTime;
	}

	/**
	 * Adds an account attribute to the account.
	 *
	 * @param osAccountAttribute Account attribute to add.
	 */
	void addAttribute(OsAccountAttribute osAccountAttribute) {
		osAccountAttributes.add(osAccountAttribute);
	}

	/**
	 * Get the account id.
	 *
	 * @return Account id.
	 */
	public long getId() {
		return id;
	}

	/**
	 * Get the unique identifier for the account. 
	 * The id is unique within the account realm.
	 *
	 * @return Optional unique identifier.
	 */
	public Optional<String> getUniqueIdWithinRealm() {
		return Optional.ofNullable(uniqueId);
	}

	/**
	 * Get the account signature.
	 *
	 * @return Account signature.
	 */
	public String getSignature() {
		return signature;
	}

	/**
	 * Get the account realm.
	 *
	 * @return Optional account realm.
	 */
	public Optional<OsAccountRealm> getRealm() {
		return Optional.ofNullable(realm);
	}

	/**
	 * Get account login name.
	 *
	 * @return Optional login name.
	 */
	public Optional<String> getLoginName() {
		return Optional.ofNullable(loginName);
	}

	/**
	 * Get account user full name.
	 *
	 * @return Optional with full name.
	 */
	public Optional<String> getFullName() {
		return Optional.ofNullable(fullName);
	}

	/**
	 * Check if account is an admin account.
	 *
	 * @return True if account is an admin account, false otherwise.
	 */
	public boolean isIsAdmin() {
		return isAdmin;
	}

	/**
	 * Get account creation time.
	 *
	 * @return Account creation time, returns 0 if creation time is not known.
	 */
	public long getCreationTime() {
		return creationTime;
	}

	/**
	 * Get account type.
	 *
	 * @return Account type.
	 */
	public OsAccountType getOsAccountType() {
		return osAccountType;
	}

	/**
	 * Get account status.
	 *
	 * @return Account status.
	 */
	public OsAccountStatus getOsAccountStatus() {
		return osAccountStatus;
	}

	/**
	 * Get additional account attributes.
	 *
	 * @return List of additional account attributes. May return an empty list.
	 */
	public List<OsAccountAttribute> getOsAccountAttributes() {
		return Collections.unmodifiableList(osAccountAttributes);
	}
}
