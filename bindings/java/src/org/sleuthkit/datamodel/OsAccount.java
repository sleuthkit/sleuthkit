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
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Abstracts an OS user account.
 *
 * An OS user account may own files and (some) artifacts.
 *
 */
public final class OsAccount implements Content {

	final static long NO_USER = -1;
	final static String NULL_UID_STR = null;

	private final SleuthkitCase sleuthkitCase;
	
	private final long objId;	
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
	OsAccount(SleuthkitCase sleuthkitCase, long objId, OsAccountRealm realm, String loginName, String uniqueId, String signature) {

		this.sleuthkitCase = sleuthkitCase;
		
		this.objId = objId;
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
		return objId;
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
	
	/**
	 * Gets the SleuthKit case  database for this
	 * account.
	 *
	 * @return The SleuthKit case object.
	 */
	public SleuthkitCase getSleuthkitCase() {
		return sleuthkitCase;
	}
	
	
	@Override
	public int read(byte[] buf, long offset, long len) throws TskCoreException {
		throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public void close() {
		throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public long getSize() {
		throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public <T> T accept(ContentVisitor<T> v) {
		throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public String getName() {
		return signature;
	}

	@Override
	public String getUniquePath() throws TskCoreException {
		throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public Content getDataSource() throws TskCoreException {
		throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public List<Content> getChildren() throws TskCoreException {
		return Collections.<Content>emptyList();
	}

	@Override
	public boolean hasChildren() throws TskCoreException {
		return false;
	}

	@Override
	public int getChildrenCount() throws TskCoreException {
		return 0;
	}

	@Override
	public Content getParent() throws TskCoreException {
		throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public List<Long> getChildrenIds() throws TskCoreException {
		return Collections.<Long>emptyList();
	}

	@Override
	public BlackboardArtifact newArtifact(int artifactTypeID) throws TskCoreException {
		throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public BlackboardArtifact newArtifact(BlackboardArtifact.ARTIFACT_TYPE type) throws TskCoreException {
		throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public AnalysisResultAdded newAnalysisResult(BlackboardArtifact.Type artifactType, Score score, String conclusion, String configuration, String justification, Collection<BlackboardAttribute> attributesList) throws TskCoreException {
		throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public Score getAggregateScore() throws TskCoreException {
		throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public ArrayList<BlackboardArtifact> getArtifacts(String artifactTypeName) throws TskCoreException {
		throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public List<AnalysisResult> getAnalysisResults(BlackboardArtifact.Type artifactType) throws TskCoreException {
		throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public BlackboardArtifact getGenInfoArtifact() throws TskCoreException {
		throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public BlackboardArtifact getGenInfoArtifact(boolean create) throws TskCoreException {
		throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public ArrayList<BlackboardAttribute> getGenInfoAttributes(BlackboardAttribute.ATTRIBUTE_TYPE attr_type) throws TskCoreException {
		throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public ArrayList<BlackboardArtifact> getArtifacts(int artifactTypeID) throws TskCoreException {
		throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public ArrayList<BlackboardArtifact> getArtifacts(BlackboardArtifact.ARTIFACT_TYPE type) throws TskCoreException {
		throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public ArrayList<BlackboardArtifact> getAllArtifacts() throws TskCoreException {
		throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public List<AnalysisResult> getAllAnalysisResults() throws TskCoreException {
		throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public Set<String> getHashSetNames() throws TskCoreException {
		throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public long getArtifactsCount(String artifactTypeName) throws TskCoreException {
		throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public long getArtifactsCount(int artifactTypeID) throws TskCoreException {
		throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public long getArtifactsCount(BlackboardArtifact.ARTIFACT_TYPE type) throws TskCoreException {
		throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public long getAllArtifactsCount() throws TskCoreException {
		throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public <T> T accept(SleuthkitItemVisitor<T> v) {
		throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
	}
}
