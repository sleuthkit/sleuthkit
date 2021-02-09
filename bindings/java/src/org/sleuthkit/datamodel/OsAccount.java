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
 * Abstracts an OS user account. OS Accounts have a scope,
 * which is defined by their parent OsAccountRealm.
 *
 * An OS user account may own files and (some) artifacts.
 *
 * OsAcounts can be created with minimal data and updated 
 * as more is learned. Caller must call update() to save
 * any new data. 
 */
public final class OsAccount extends AbstractContent {
	
	private static final ResourceBundle bundle = ResourceBundle.getBundle("org.sleuthkit.datamodel.Bundle");

	final static Long NO_ACCOUNT = null;
	final static String NO_OWNER_ID = null;

	private final SleuthkitCase sleuthkitCase;
	
	private final long osAccountobjId;	// Object ID within the database
	private final OsAccountRealm realm;		// realm where the loginname/uniqueId is unique - a domain or a host name.
	private String loginName;	// user login name - may be null
	private String uniqueId;	// a unique user sid/uid, may be null
	
	private String signature;		// This exists only to prevent duplicates.
									// Together realm_id & signature must be unique for each account.
									// It is either unique_id if unique_id is defined,
									// or the login_name if login_name is defined.

	private String fullName;	// full name, may be null
	private boolean isAdmin = false;	// is admin account.
	private OsAccountType osAccountType = OsAccountType.UNKNOWN;
	private OsAccountStatus osAccountStatus;
	private Long creationTime = null;

	private final List<OsAccountAttribute> osAccountAttributes = new ArrayList<>();
	
	private boolean isDirty = false; // indicates that some member value has changed since construction and it should be updated in the database.

	
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
		public int getId() {
			return id;
		}

		/**
		 * Get account type name.
		 *
		 * @return Account type name.
		 */
		public String getName() {
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
	 * just a reference to it was found on the host (such as in a log file)
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
	 * Set the account login name, such as "jdoe".
	 * 
	 * @param loginName Login name to set.
	 */
	public void setLoginName(String loginName) {
		if (this.loginName == null) {
			this.loginName = loginName;
			this.isDirty = true;
		}
	}

	/**
	 * Set the account unique id, such as SID or UID
	 * 
	 * @param uniqueId Id to set.
	 */
	public void setUniqueId(String uniqueId) {
		if (this.uniqueId == null) {
			this.uniqueId = uniqueId;
			this.isDirty = true;
		}
	}
	
	
	/**
	 * Sets the account user's full name, such as "John Doe"
	 *
	 * @param fullName Full name.
	 */
	public void setFullName(String fullName) {
		if (this.fullName == null) {
			this.fullName = fullName;
			this.isDirty = true;
		}
	}

	/**
	 * Sets the admin flag for the account.
	 *
	 * @param isAdmin Flag to indicate if the account is an admin account.
	 */
	public void setIsAdmin(boolean isAdmin) {
		this.isAdmin = isAdmin;
		this.isDirty = true;
	}

	/**
	 * Sets account type for the account.
	 *
	 * @param osAccountType Account type.
	 */
	public void setOsAccountType(OsAccountType osAccountType) {
		this.osAccountType = osAccountType;
		this.isDirty = true;
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
	public void setCreationTime(Long creationTime) {
		if (this.creationTime == null) {
			this.creationTime = creationTime;
			this.isDirty = true;
		}
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
	 * Reset the dirty flag. Indicates that the account has been updated in the
	 * database.
	 * 
	 */
	void resetDirty() {
		this.isDirty = false;
	}
	
	
	/**
	 * Adds account attributes to the account. Attributes can be at
	 * a host-level or domain-level (for domain-scoped accounts).
	 *
	 * @param osAccountAttributes Collection of  attributes to add.
	 */
	public void addAttributes(Set<OsAccountAttribute> osAccountAttributes) throws TskCoreException {
		sleuthkitCase.getOsAccountManager().addOsAccountAttributes(this, osAccountAttributes);
		osAccountAttributes.addAll(osAccountAttributes);
	}

	
	/**
	 * Updates the account in the database. This must be called after calling
	 * any of the 'set' methods. 
	 *
	 * @return OsAccount Updated account.
	 *
	 * @throws TskCoreException If there is an error in updating the account.
	 */
	public OsAccount update() throws TskCoreException {

		if (this.isDirty) {
			OsAccount updatedAccount = sleuthkitCase.getOsAccountManager().updateAccount(this);
			updatedAccount.resetDirty();
			return updatedAccount;
		} else {
			return this;
		}
	}
	
	/**
	 * Get the account Object Id that is unique within the scope of the case.
	 *
	 * @return Account id.
	 */
	public long getId() {
		return osAccountobjId;
	}

	/**
	 * Get the unique identifier for the account, such as UID or SID.
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
	 * Get account login name, such as "jdoe"
	 *
	 * @return Optional login name.
	 */
	public Optional<String> getLoginName() {
		return Optional.ofNullable(loginName);
	}

	/**
	 * Get account user full name, such as "John Doe"
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
	public Optional<Long> getCreationTime() {
		return Optional.of(creationTime);
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
