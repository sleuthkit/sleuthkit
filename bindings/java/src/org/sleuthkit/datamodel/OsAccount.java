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

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.ResourceBundle;

/**
 * Abstracts an OS user account. OS Accounts have a scope, which is defined by
 * their parent OsAccountRealm.
 *
 * An OS user account may own files and (some) artifacts.
 *
 * OsAcounts can be created with minimal data and updated as more is learned.
 * Caller must call update() to save any new data.
 */
public final class OsAccount extends AbstractContent {

	private static final ResourceBundle bundle = ResourceBundle.getBundle("org.sleuthkit.datamodel.Bundle");

	final static Long NO_ACCOUNT = null;
	final static String NO_OWNER_ID = null;

	private final SleuthkitCase sleuthkitCase;

	private final long osAccountObjId;	// Object ID within the database
	private final long realmId;		// realm where the account exists in (could be local or domain scoped)
	private final String loginName;	// user login name - may be null
	private final String addr;	// a unique user sid/uid, may be null

	private String signature;		// This exists only to prevent duplicates.
	// Together realm_id & signature must be unique for each account.
	// It is either addr if addr is defined,
	// or the login_name if login_name is defined.

	private final String fullName;	// full name, may be null
	private final OsAccountType osAccountType;
	private final OsAccountStatus osAccountStatus;
	private final OsAccountDbStatus osAccountDbStatus;  // Status of row in the database
	private final Long creationTime;

	private List<OsAccountAttribute> osAccountAttributes = null;
	private List<OsAccountInstance> osAccountInstances = null;

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
	 * Encapsulates status of OsAccount row. OsAccounts that are not "Active"
	 * are generally invisible - they will not be returned by any queries on the
	 * string fields.
	 */
	public enum OsAccountDbStatus {
		ACTIVE(0, "Active"),
		MERGED(1, "Merged"),
		DELETED(2, "Deleted");

		private final int id;
		private final String name;

		OsAccountDbStatus(int id, String name) {
			this.id = id;
			this.name = name;
		}

		public int getId() {
			return id;
		}

		String getName() {
			return name;
		}

		public static OsAccountDbStatus fromID(int typeId) {
			for (OsAccountDbStatus type : OsAccountDbStatus.values()) {
				if (type.ordinal() == typeId) {
					return type;
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
	 * Constructs an OsAccount with a realm/username and unique id, and
	 * signature.
	 *
	 * @param sleuthkitCase  The SleuthKit case (case database) that contains
	 *                       the artifact data.
	 * @param osAccountobjId Obj id of the account in tsk_objects table.
	 * @param realmId        Realm - defines the scope of this account.
	 * @param loginName      Login name for the account. May be null.
	 * @param uniqueId       An id unique within the realm - a SID or uid. May
	 *                       be null, only if login name is not null.
	 * @param signature	     A unique signature constructed from realm id and
	 *                       loginName or uniqueId.
	 * @param fullName       Full name.
	 * @param creationTime   Account creation time.
	 * @param accountType    Account type.
	 * @param accountStatus  Account status.
	 * @param dbStatus       Status of row in database.
	 */
	OsAccount(SleuthkitCase sleuthkitCase, long osAccountobjId, long realmId, String loginName, String uniqueId, String signature, 
			String fullName, Long creationTime, OsAccountType accountType, OsAccountStatus accountStatus, OsAccountDbStatus accountDbStatus) {

		super(sleuthkitCase, osAccountobjId, signature);

		this.sleuthkitCase = sleuthkitCase;
		this.osAccountObjId = osAccountobjId;
		this.realmId = realmId;
		this.loginName = loginName;
		this.addr = uniqueId;
		this.signature = signature;
		this.fullName = fullName;
		this.creationTime = creationTime;
		this.osAccountType = accountType;
		this.osAccountStatus = accountStatus;
		this.osAccountDbStatus = accountDbStatus;
	}

	/**
	 * This function is used by OsAccountManger to update the list of OsAccount
	 * attributes.
	 *
	 * @param osAccountAttributes The osAccount attributes that are to be added.
	 */
	synchronized void  setAttributesInternal(List<OsAccountAttribute> osAccountAttributes) {
		this.osAccountAttributes = osAccountAttributes;
	}

	/**
	 * This function is used by OsAccountManger to update the list of OsAccount
	 * instances.
	 *
	 * @param osAccountInstanes The osAccount instances that are to be added.
	 */
	synchronized void  setInstancesInternal(List<OsAccountInstance> osAccountInstances) {
		this.osAccountInstances = osAccountInstances;
	}
	
	/**
	 * Get the account Object Id that is unique within the scope of the case.
	 *
	 * @return Account id.
	 */
	public long getId() {
		return osAccountObjId;
	}

	/**
	 * Get the unique identifier for the account, such as UID or SID. The id is
	 * unique within the account realm.
	 *
	 * @return Optional unique identifier.
	 */
	public Optional<String> getAddr() {
		return Optional.ofNullable(addr);
	}

	/**
	 * Get the ID for the account realm. Get the Realm via
	 * OsAccountRealmManager.getRealmByRealmId() NOTE: The realm may get updated as
	 * more data is parsed, so listen for events to update as needed.
	 *
	 * @return
	 */
	public long getRealmId() {
		return realmId;
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
	 * Get the account signature.
	 *
	 * @return Account signature.
	 */
	String getSignature() {
		return signature;
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
	 * Get account creation time.
	 *
	 * @return Optional with account creation time.
	 */
	public Optional<Long> getCreationTime() {
		return Optional.ofNullable(creationTime);
	}

	/**
	 * Get account type.
	 *
	 * @return Optional with account type.
	 */
	public Optional<OsAccountType> getOsAccountType() {
		return Optional.ofNullable(osAccountType);
	}

	/**
	 * Get account status.
	 *
	 * @return Optional with account status.
	 */
	public Optional<OsAccountStatus> getOsAccountStatus() {
		return Optional.ofNullable(osAccountStatus);
	}

	/**
	 * Get account status in the database.
	 *
	 * @return Database account status.
	 */
	public OsAccountDbStatus getOsAccountDbStatus() {
		return osAccountDbStatus;
	}

	/**
	 * Get additional account attributes.
	 *
	 * @return List of additional account attributes. May return an empty list.
	 *
	 * @throws TskCoreException
	 */
	public synchronized List<OsAccountAttribute> getExtendedOsAccountAttributes() throws TskCoreException {
		if (osAccountAttributes == null) {
			osAccountAttributes = sleuthkitCase.getOsAccountManager().getOsAccountAttributes(this);
		}
		return Collections.unmodifiableList(osAccountAttributes);
	}

	/**
	 * Return the os account instances.
	 *
	 * @return List of all the OsAccountInstances. May return an empty list.
	 *
	 * @throws TskCoreException
	 */
	public synchronized List<OsAccountInstance> getOsAccountInstances() throws TskCoreException {
		if (osAccountInstances == null) {
			osAccountInstances = sleuthkitCase.getOsAccountManager().getOsAccountInstances(this);
		}

		return Collections.unmodifiableList(osAccountInstances);
	}

	/**
	 * Updates the account signature with unique id or name.
	 *
	 * @throws TskCoreException If there is an error updating the account
	 *                          signature.
	 */
	private void updateSignature() throws TskCoreException {
		signature = OsAccountManager.getOsAccountSignature(this.addr, this.loginName);
	}

	/**
	 * Gets the SleuthKit case database for this account.
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

		throw new UnsupportedOperationException("Not supported yet.");
	}

	@Override
	public <T> T accept(SleuthkitItemVisitor<T> v) {
		return v.visit(this);
	}

	/**
	 * Abstracts attributes of an OS account. An attribute may be specific to a
	 * host, or applicable across all hosts.
	 *
	 * As an example, last login time is host specific, whereas last password
	 * reset date is independent of a host.
	 *
	 */
	public final class OsAccountAttribute extends AbstractAttribute {

		private final long osAccountObjId;	// OS account to which this attribute belongs.
		private final Long hostId; // Host to which this attribute applies, may be null
		private final Long sourceObjId; // Object id of the source where the attribute was discovered.

		/**
		 * Creates an os account attribute with int value.
		 *
		 * @param attributeType Attribute type.
		 * @param valueInt      Int value.
		 * @param osAccount     Account which the attribute pertains to.
		 * @param host          Host on which the attribute applies to. Pass
		 *                      Null if the attribute applies to all the hosts in
		 *                      the realm.
		 * @param sourceObj     Source where the attribute was found, may be null.
		 */
		public OsAccountAttribute(BlackboardAttribute.Type attributeType, int valueInt, OsAccount osAccount, Host host, Content sourceObj) {
			super(attributeType, valueInt);

			this.osAccountObjId = osAccount.getId();
			this.hostId = (host != null ? host.getHostId() : null);
			this.sourceObjId = (sourceObj != null ? sourceObj.getId() : null);
		}

		/**
		 * Creates an os account attribute with long value.
		 *
		 * @param attributeType Attribute type.
		 * @param valueLong     Long value.
		 * @param osAccount     Account which the attribute pertains to.
		 * @param host          Host on which the attribute applies to. Pass
		 *                      Null if it applies across hosts.
		 * @param sourceObj     Source where the attribute was found.
		 */
		public OsAccountAttribute(BlackboardAttribute.Type attributeType, long valueLong, OsAccount osAccount, Host host, Content sourceObj) {
			super(attributeType, valueLong);

			this.osAccountObjId = osAccount.getId();
			this.hostId = (host != null ? host.getHostId() : null);
			this.sourceObjId = (sourceObj != null ? sourceObj.getId() : null);
		}

		/**
		 * Creates an os account attribute with double value.
		 *
		 * @param attributeType Attribute type.
		 * @param valueDouble   Double value.
		 * @param osAccount     Account which the attribute pertains to.
		 * @param host          Host on which the attribute applies to. Pass
		 *                      Null if it applies across hosts.
		 * @param sourceObj     Source where the attribute was found.
		 */
		public OsAccountAttribute(BlackboardAttribute.Type attributeType, double valueDouble, OsAccount osAccount, Host host, Content sourceObj) {
			super(attributeType, valueDouble);

			this.osAccountObjId = osAccount.getId();
			this.hostId = (host != null ? host.getHostId() : null);
			this.sourceObjId = (sourceObj != null ? sourceObj.getId() : null);
		}

		/**
		 * Creates an os account attribute with string value.
		 *
		 * @param attributeType Attribute type.
		 * @param valueString   String value.
		 * @param osAccount     Account which the attribute pertains to.
		 * @param host          Host on which the attribute applies to. Pass
		 *                      Null if applies across hosts.
		 * @param sourceObj     Source where the attribute was found.
		 */
		public OsAccountAttribute(BlackboardAttribute.Type attributeType, String valueString, OsAccount osAccount, Host host, Content sourceObj) {
			super(attributeType, valueString);

			this.osAccountObjId = osAccount.getId();
			this.hostId = (host != null ? host.getHostId() : null);
			this.sourceObjId = (sourceObj != null ? sourceObj.getId() : null);
		}

		/**
		 * Creates an os account attribute with byte-array value.
		 *
		 * @param attributeType Attribute type.
		 * @param valueBytes    Bytes value.
		 * @param osAccount     Account which the attribute pertains to.
		 * @param host          Host on which the attribute applies to. Pass
		 *                      Null if it applies across hosts.
		 * @param sourceObj     Source where the attribute was found.
		 */
		public OsAccountAttribute(BlackboardAttribute.Type attributeType, byte[] valueBytes, OsAccount osAccount, Host host, Content sourceObj) {
			super(attributeType, valueBytes);

			this.osAccountObjId = osAccount.getId();
			this.hostId = (host != null ? host.getHostId() : null);
			this.sourceObjId = (sourceObj != null ? sourceObj.getId() : null);
		}

		/**
		 * Constructor to be used when creating an attribute after reading the
		 * data from the table.
		 *
		 * @param attributeType Attribute type.
		 * @param valueInt      Int value.
		 * @param valueLong     Long value.
		 * @param valueDouble   Double value.
		 * @param valueString   String value.
		 * @param valueBytes    Bytes value.
		 * @param sleuthkitCase Sleuthkit case.
		 * @param osAccount     Account which the attribute pertains to.
		 * @param host          Host on which the attribute applies to. Pass
		 *                      Null if it applies across hosts.
		 * @param sourceObj     Source where the attribute was found.
		 */
		OsAccountAttribute(BlackboardAttribute.Type attributeType, int valueInt, long valueLong, double valueDouble, String valueString, byte[] valueBytes,
				SleuthkitCase sleuthkitCase, OsAccount osAccount, Host host, Content sourceObj) {

			super(attributeType,
					valueInt, valueLong, valueDouble, valueString, valueBytes,
					sleuthkitCase);
			this.osAccountObjId = osAccount.getId();
			this.hostId = (host != null ? host.getHostId() : null);
			this.sourceObjId = (sourceObj != null ? sourceObj.getId() : null);
		}

		/**
		 * Get the host id for the account attribute.
		 *
		 * @return Optional with Host id.
		 */
		public Optional<Long> getHostId() {
			return Optional.ofNullable(hostId);
		}

		/**
		 * Get the object id of account to which this attribute applies.
		 *
		 * @return Account row id.
		 */
		public long getOsAccountObjectId() {
			return osAccountObjId;
		}

		/**
		 * Get the object id of the source where the attribute was found.
		 *
		 * @return Object id of source.
		 */
		public Optional<Long> getSourceObjectId() {
			return Optional.ofNullable(sourceObjId);
		}
	}
}
