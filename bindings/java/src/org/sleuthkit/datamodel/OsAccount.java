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
import java.util.ResourceBundle;
import java.util.Set;

/**
 * Abstracts an OS user account.
 *
 * An OS user account may own files and (some) artifacts.
 *
 */
public final class OsAccount extends AbstractContent {
	
	private static final ResourceBundle bundle = ResourceBundle.getBundle("org.sleuthkit.datamodel.Bundle");

	final static Long NO_ACCOUNT = null;
	final static String NO_OWNER_ID = null;

	private final SleuthkitCase sleuthkitCase;
	
	private final long osAccountobjId;
	private final OsAccountRealm realm;		// realm where the username is unique - a domain or a host name.
	private final String loginName;	// user login name - may be null
	private final String uniqueId;	// a unique user sid/uid, may be null
	
	private String signature;		// This exists only to prevent duplicates.  
									// It is either ‘realm_id/unique_id’ if unique_id is defined,
									// or realm_id/login_name’ if login_name is defined.

	private String fullName;	// full name
	private boolean isAdmin = false;	// is admin account.
	private OsAccountType osAccountType = OsAccountType.UNKNOWN;
	private OsAccountStatus osAccountStatus;
	private long creationTime = 0;

	private final List<OsAccountAttribute> osAccountAttributes = new ArrayList<>();

	/**
	 * Encapsulates status of an account - whether is it active or disabled or
	 * deleted.
	 */
	public enum OsAccountStatus {
		UNKNOWN(0, bundle.getString("OsAccountStatus.Unknown.text")),
		ACTIVE(1, bundle.getString("OsAccountStatus.Active.text")),
		DISABLED(2, bundle.getString("OsAccountStatus.Disabled.text")),
		DELETED(3, bundle.getString("OsAccountStatus.Deleted.text"));

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
		public String getName() {
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
	 * Encapsulates an account type - whether it's an interactive login account
	 * or a service account.
	 */
	public enum OsAccountType {
		UNKNOWN(0, bundle.getString("OsAccountType.Unknown.text")),
		SERVICE(1, bundle.getString("OsAccountType.Service.text")),
		INTERACTIVE(2, bundle.getString("OsAccountType.Interactive.text"));

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
		PERFORMED_ACTION_ON(0, bundle.getString("OsAccountInstanceType.PerformedActionOn.text")), // the user performed actions on a host
		REFERENCED_ON(1, bundle.getString("OsAccountInstanceType.ReferencedOn.text") );	// user was simply referenced on a host

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
	 * signature.
	 *
	 * @param sleuthkitCase  The SleuthKit case (case database) that contains
	 *                       the artifact data.
	 * @param osAccountobjId Obj id of the account in tsk_objects table.
	 * @param realm	         Realm - defines the scope of this account.
	 * @param loginName      Login name for the account. May be null.
	 * @param uniqueId       An id unique within the realm - a SID or uid. May
	 *                       be null, only if login name is not null.
	 * @param signature	     A unique signature constructed from realm id and
	 *                       loginName or uniqueId.
	 * @param accountStatus  Account status.
	 */
	OsAccount(SleuthkitCase sleuthkitCase, long osAccountobjId, OsAccountRealm realm, String loginName, String uniqueId, String signature, OsAccountStatus accountStatus) {
		
		super(sleuthkitCase, osAccountobjId, signature);
		
		this.sleuthkitCase = sleuthkitCase;
		this.osAccountobjId = osAccountobjId;
		this.realm = realm;
		this.loginName = loginName;
		this.uniqueId = uniqueId;
		this.signature = signature;
		this.osAccountStatus = accountStatus;
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
	 * @param osAccountType Account type.
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
	 * Set the signature.
	 *
	 * The signature may change if the login name or unique id is updated after
	 * creation.
	 *
	 * @param signature Signature.
	 */
	void setSignature(String signature) {
		this.signature = signature;
	}
	
	/**
	 * Adds account attributes to the account.
	 *
	 * @param osAccountAttributes Collection of  attributes to add.
	 */
	void addAttributes(Set<OsAccountAttribute> osAccountAttributes) throws TskCoreException {
		sleuthkitCase.getOsAccountManager().addOsAccountAttributes(this, osAccountAttributes);
		osAccountAttributes.addAll(osAccountAttributes);
	}

	/**
	 * Get the account id.
	 *
	 * @return Account id.
	 */
	public long getId() {
		return osAccountobjId;
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
	 * Get the account realm.
	 *
	 * @return OsAccountRealm.
	 */
	public OsAccountRealm getRealm() {
		return realm;
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
	public boolean isAdmin() {
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
	
	/**
	 * Gets the SleuthKit case  database for this
	 * account.
	 *
	 * @return The SleuthKit case object.
	 */
	@Override
	public SleuthkitCase getSleuthkitCase() {
		return sleuthkitCase;
	}
	
	@Override
	public int read(byte[] buf, long offset, long len) throws TskCoreException {
		// No data to read. 
		return 0;
	}

	@Override
	public void close() {
		// nothing to close
	}

	@Override
	public long getSize() {
		// No data. 
		return 0;
	}

	@Override
	public <T> T accept(ContentVisitor<T> v) {
		// TODO: need to implement this when OS Accounts are part of the Autopsy tree.
		
		throw new UnsupportedOperationException("Not supported yet."); 
	}

	@Override
	public <T> T accept(SleuthkitItemVisitor<T> v) {
		// TODO: need to implement this when OS Accounts are part of the Autopsy tree.
		
		throw new UnsupportedOperationException("Not supported yet."); 
	}
}
