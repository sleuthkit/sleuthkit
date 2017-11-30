/*
 * Sleuth Kit Data Model
 *
 * Copyright 2017 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.datamodel;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbConnection;
import static org.sleuthkit.datamodel.SleuthkitCase.closeResultSet;
import static org.sleuthkit.datamodel.SleuthkitCase.closeStatement;

/**
 * Provides an API to create Accounts and communications/relationships between
 * accounts.
 */
public class CommunicationsManager {

	private static final Logger LOGGER = Logger.getLogger(CommunicationsManager.class.getName());

	private final SleuthkitCase db;

	private final Map<Account.Type, Integer> accountTypeToTypeIdMap
			= new ConcurrentHashMap<Account.Type, Integer>();
	private final Map<String, Account.Type> typeNameToAccountTypeMap
			= new ConcurrentHashMap<String, Account.Type>();

	// Artifact types that represent a relationship between accounts 
	private final static Set<Integer> RELATIONSHIP_ARTIFACT_TYPE_IDS
			= new HashSet<Integer>(Arrays.asList(
					BlackboardArtifact.ARTIFACT_TYPE.TSK_MESSAGE.getTypeID(),
					BlackboardArtifact.ARTIFACT_TYPE.TSK_EMAIL_MSG.getTypeID(),
					BlackboardArtifact.ARTIFACT_TYPE.TSK_CONTACT.getTypeID(),
					BlackboardArtifact.ARTIFACT_TYPE.TSK_CALLLOG.getTypeID()
			));
	private static final String RELATIONSHIP_ARTIFACT_TYPE_IDS_CSV_STR
			= StringUtils.buildCSVString(RELATIONSHIP_ARTIFACT_TYPE_IDS);

	// Artifact types that represent communications between accounts 
	private static final Set<Integer> COMMUNICATION_ARTIFACT_TYPE_IDS
			= new HashSet<Integer>(Arrays.asList(
					BlackboardArtifact.ARTIFACT_TYPE.TSK_MESSAGE.getTypeID(),
					BlackboardArtifact.ARTIFACT_TYPE.TSK_EMAIL_MSG.getTypeID(),
					BlackboardArtifact.ARTIFACT_TYPE.TSK_CALLLOG.getTypeID()
			));
	private static final String COMMUNICATION_ARTIFACT_TYPE_IDS_CSV_STR
			= StringUtils.buildCSVString(COMMUNICATION_ARTIFACT_TYPE_IDS);

	CommunicationsManager(SleuthkitCase db) throws TskCoreException {
		this.db = db;

		initAccountTypes();
	}

	/**
	 * Make sure the predefined account types are in the account types table.
	 *
	 * @throws TskCoreException
	 */
	private void initAccountTypes() throws TskCoreException {
		CaseDbConnection connection = db.getConnection();
		Statement statement = null;
		ResultSet resultSet = null;

		try {
			statement = connection.createStatement();
			// Read the table
			int count = readAccountTypes();
			if (0 == count) {
				// Table is empty, populate it with predefined types
				for (Account.Type type : Account.Type.PREDEFINED_ACCOUNT_TYPES) {
					try {
						statement.execute("INSERT INTO account_types (type_name, display_name) VALUES ( '" + type.getTypeName() + "', '" + type.getDisplayName() + "')"); //NON-NLS
					} catch (SQLException ex) {
						resultSet = connection.executeQuery(statement, "SELECT COUNT(*) AS count FROM account_types WHERE type_name = '" + type.getTypeName() + "'"); //NON-NLS
						resultSet.next();
						if (resultSet.getLong("count") == 0) {
							throw ex;
						}
						resultSet.close();
						resultSet = null;
					}

					ResultSet rs2 = connection.executeQuery(statement, "SELECT account_type_id FROM account_types WHERE type_name = '" + type.getTypeName() + "'"); //NON-NLS
					rs2.next();
					int typeID = rs2.getInt("account_type_id");
					rs2.close();

					Account.Type accountType = new Account.Type(type.getTypeName(), type.getDisplayName());
					this.accountTypeToTypeIdMap.put(accountType, typeID);
					this.typeNameToAccountTypeMap.put(type.getTypeName(), accountType);
				}
			}
		} catch (SQLException ex) {
			LOGGER.log(Level.SEVERE, "Failed to add row to account_types", ex);
		} finally {
			closeResultSet(resultSet);
			closeStatement(statement);
			connection.close();
		}
	}

	/**
	 * Reads in in the account types table.
	 *
	 * Returns the number of account types read in
	 *
	 * @return The number of account types read.
	 *
	 * @throws SQLException
	 * @throws TskCoreException
	 */
	private int readAccountTypes() throws SQLException, TskCoreException {
		CaseDbConnection connection = db.getConnection();
		Statement statement = null;
		ResultSet resultSet = null;
		int count = 0;

		try {
			statement = connection.createStatement();

			// If the account_types table is already populated, say when opening a case,  then load it
			resultSet = connection.executeQuery(statement, "SELECT COUNT(*) AS count FROM account_types"); //NON-NLS
			resultSet.next();
			if (resultSet.getLong("count") > 0) {

				resultSet.close();
				resultSet = connection.executeQuery(statement, "SELECT * FROM account_types");
				while (resultSet.next()) {
					Account.Type accountType = new Account.Type(resultSet.getString("type_name"), resultSet.getString("display_name"));
					this.accountTypeToTypeIdMap.put(accountType, resultSet.getInt("account_type_id"));
					this.typeNameToAccountTypeMap.put(accountType.getTypeName(), accountType);
				}
				count = this.typeNameToAccountTypeMap.size();
			}

		} catch (SQLException ex) {
			LOGGER.log(Level.SEVERE, "Failed to read account_types", ex);
		} finally {
			closeResultSet(resultSet);
			closeStatement(statement);
			connection.close();
		}

		return count;
	}

	/**
	 * Gets the SleuthKit case.
	 *
	 * @return The SleuthKit case (case database) object.
	 */
	SleuthkitCase getSleuthkitCase() {
		return this.db;
	}

	/**
	 * Add an account type. Returns the type if it is already defined.
	 *
	 * @param accountTypeName account type name
	 * @param displayName     account type display name
	 *
	 * @return Account.Type
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	public Account.Type addAccountType(String accountTypeName, String displayName) throws TskCoreException {
		Account.Type accountType = new Account.Type(accountTypeName, displayName);

		// check if already in map
		if (this.accountTypeToTypeIdMap.containsKey(accountType)) {
			return accountType;
		}

		CaseDbConnection connection = db.getConnection();
		db.acquireSingleUserCaseWriteLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			connection.beginTransaction();
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT * FROM account_types WHERE type_name = '" + accountTypeName + "'"); //NON-NLS
			if (!rs.next()) {
				rs.close();

				s.execute("INSERT INTO account_types (type_name, display_name) VALUES ( '" + accountTypeName + "', '" + displayName + "')"); //NON-NLS

				// Read back the typeID
				rs = connection.executeQuery(s, "SELECT * FROM account_types WHERE type_name = '" + accountTypeName + "'"); //NON-NLS
				rs.next();

				int typeID = rs.getInt("account_type_id");
				accountType = new Account.Type(rs.getString("type_name"), rs.getString("display_name"));

				this.accountTypeToTypeIdMap.put(accountType, typeID);
				this.typeNameToAccountTypeMap.put(accountTypeName, accountType);

				connection.commitTransaction();

				return accountType;
			} else {
				int typeID = rs.getInt("account_type_id");

				accountType = new Account.Type(rs.getString("type_name"), rs.getString("display_name"));
				this.accountTypeToTypeIdMap.put(accountType, typeID);

				return accountType;
			}
		} catch (SQLException ex) {
			connection.rollbackTransaction();
			throw new TskCoreException("Error adding account type", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			connection.close();
			db.releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Records that an account was used in a specific file. Behind the scenes,
	 * it will create a case-specific Account object if it does not already
	 * exist and create the needed database entries (which currently include
	 * making a BlackboardArtifact.
	 *
	 * @param accountType     account type
	 * @param accountUniqueID unique account identifier (such as email address)
	 * @param moduleName      module creating the account
	 * @param sourceFile      source file the account was found in (for the
	 *                        blackboard)
	 *
	 * @return AccountFileInstance
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	public AccountFileInstance createAccountFileInstance(Account.Type accountType, String accountUniqueID, String moduleName, Content sourceFile) throws TskCoreException {

		// make or get the Account (unique at the case-level)
		Account account = getOrCreateAccount(accountType, normalizeAccountID(accountType, accountUniqueID));

		/*
		 * make or get the artifact. Will not create one if it already exists
		 * for the sourceFile. Such as an email PST that has the same email
		 * address multiple times. Only one artifact is created for each email
		 * message in that PST.
		 */
		BlackboardArtifact accountArtifact = getOrCreateAccountFileInstanceArtifact(accountType, normalizeAccountID(accountType, accountUniqueID), moduleName, sourceFile);

		// The account instance map was unused so we have removed it from the database, 
		// but we expect we may need it so I am preserving this method comment and usage here.
		// add a row to Accounts to Instances mapping table
		// @@@ BC: Seems like we should only do this if we had to create the artifact. 
		// But, it will probably fail to create a new one based on unique constraints. 
		// addAccountFileInstanceMapping(account.getAccountID(), accountArtifact.getArtifactID());
		return new AccountFileInstance(accountArtifact, account);
	}

	/**
	 * Get the Account with the given account type and account ID.
	 *
	 * @param accountType     account type
	 * @param accountUniqueID unique account identifier (such as an email
	 *                        address)
	 *
	 * @return Account, returns NULL is no matching account found
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	public Account getAccount(Account.Type accountType, String accountUniqueID) throws TskCoreException {
		Account account = null;
		CaseDbConnection connection = db.getConnection();
		db.acquireSingleUserCaseReadLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT * FROM accounts WHERE account_type_id = " + getAccountTypeId(accountType)
					+ " AND account_unique_identifier = '" + normalizeAccountID(accountType, accountUniqueID) + "'"); //NON-NLS

			if (rs.next()) {
				account = new Account(rs.getInt("account_id"), accountType,
						rs.getString("account_unique_identifier"));
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting account type id", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			connection.close();
			db.releaseSingleUserCaseReadLock();
		}

		return account;
	}

	/**
	 * Returns an account instance for the given account instance artifact
	 *
	 * @param artifact
	 *
	 * @return Account
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 *
	 */
//	public AccountFileInstance getAccountFileInstance(BlackboardArtifact artifact) throws TskCoreException {
//		AccountFileInstance accountInstance = null;
//		if (artifact.getArtifactTypeID() == BlackboardArtifact.ARTIFACT_TYPE.TSK_ACCOUNT.getTypeID()) {
//			String accountTypeStr = artifact.getAttribute(new BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_ACCOUNT_TYPE)).getValueString();
//			String accountID = artifact.getAttribute(new BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_ID)).getValueString();
//			Account.Type accountType = getAccountType(accountTypeStr);
//
//			Account account = getAccount(accountType, accountID);
//			accountInstance = new AccountFileInstance(artifact, account);
//		} else {
//			throw new TskCoreException("Unexpected Artifact type = " + artifact.getArtifactTypeID());
//		}
//
//		return accountInstance;
//	}
	/**
	 * Add relationships between the sender and recipient account instances. All
	 * accounts the relationship must be from the same data source.
	 *
	 * @param sender               sender account
	 * @param recipients           list of recipients
	 * @param relationshipArtifact relationship artifact
	 * @param dateTime				         date of communications/relationship, as epoch
	 *                             seconds
	 *
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 * @throws org.sleuthkit.datamodel.TskDataException If the all the accounts
	 *                                                  and the relationship are
	 *                                                  not from the same data
	 *                                                  source.
	 */
	public void addRelationships(AccountFileInstance sender, List<AccountFileInstance> recipients,
			BlackboardArtifact relationshipArtifact, long dateTime) throws TskCoreException, TskDataException {

		if (false == RELATIONSHIP_ARTIFACT_TYPE_IDS.contains(relationshipArtifact.getArtifactTypeID())) {
			throw new TskCoreException("Unexpected Artifact type = " + relationshipArtifact.getArtifactTypeID());
		}

		/*
		 * Enforce that all accounts and the relationship between them on from
		 * the same 'source'. This is required for the queries to work
		 * correctly.
		 */
		// Currently we do not save the direction of communication
		List<Long> accountIDs = new ArrayList<Long>();

		if (null != sender) {
			accountIDs.add(sender.getAccount().getAccountID());
			if (sender.getDataSourceObjectID() != relationshipArtifact.getDataSourceObjectID()) {
				throw new TskDataException("Sender and relationship are from different data sources :"
						+ "Sender source ID" + sender.getDataSourceObjectID() + " != relationship source ID" + relationshipArtifact.getDataSourceObjectID());
			}
		}

		for (AccountFileInstance recipient : recipients) {
			accountIDs.add(recipient.getAccount().getAccountID());
			if (recipient.getDataSourceObjectID() != relationshipArtifact.getDataSourceObjectID()) {
				throw new TskDataException("Recipient and relationship are from different data sources :"
						+ "Recipient source ID" + recipient.getDataSourceObjectID() + " != relationship source ID" + relationshipArtifact.getDataSourceObjectID());
			}
		}

		Set<UnorderedAccountPair> relationships = listToUnorderedPairs(accountIDs);
		Iterator<UnorderedAccountPair> iter = relationships.iterator();

		while (iter.hasNext()) {
			try {
				UnorderedAccountPair accountPair = iter.next();
				addAccountsRelationship(accountPair.getFirst(), accountPair.getSecond(), relationshipArtifact.getId(), dateTime, relationshipArtifact.getArtifactTypeID(), relationshipArtifact.getDataSourceObjectID());
			} catch (TskCoreException ex) {
				LOGGER.log(Level.WARNING, "Could not get timezone for image", ex); //NON-NLS
			}
		}

	}

	/**
	 * Get the Account for the given account type and account ID. Create an a
	 * new account if one doesn't exist
	 *
	 * @param accountType     account type
	 * @param accountUniqueID unique account identifier
	 *
	 * @return blackboard artifact, returns NULL is no matching account found
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	private Account getOrCreateAccount(Account.Type accountType, String accountUniqueID) throws TskCoreException {
		Account account = null;

		account = getAccount(accountType, accountUniqueID);
		if (null == account) {

			CaseDbConnection connection = db.getConnection();
			db.acquireSingleUserCaseWriteLock();
			Statement s = null;
			ResultSet rs = null;
			try {
				connection.beginTransaction();
				s = connection.createStatement();
				s.execute("INSERT INTO accounts (account_type_id, account_unique_identifier) VALUES ( " + getAccountTypeId(accountType) + ", '" + normalizeAccountID(accountType, accountUniqueID) + "'" + ")"); //NON-NLS

				connection.commitTransaction();
				account = getAccount(accountType, accountUniqueID);
			} catch (SQLException ex) {
				connection.rollbackTransaction();
				throw new TskCoreException("Error adding an account", ex);
			} finally {
				closeResultSet(rs);
				closeStatement(s);
				connection.close();
				db.releaseSingleUserCaseWriteLock();
			}
		}

		return account;
	}

	/**
	 * Get the blackboard artifact for the given account type, account ID, and
	 * source file. Create an artifact and return that, of a matching doesn't
	 * exists
	 *
	 * @param accountType     account type
	 * @param accountUniqueID accountID
	 * @param sourceFile		    Source file (for the artifact)
	 *
	 * @return blackboard artifact, returns NULL is no matching account found
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	BlackboardArtifact getOrCreateAccountFileInstanceArtifact(Account.Type accountType, String accountUniqueID, String moduleName, Content sourceFile) throws TskCoreException {

		// see if it already exists
		BlackboardArtifact accountArtifact = getAccountFileInstanceArtifact(accountType, accountUniqueID, sourceFile);
		if (null != accountArtifact) {
			return accountArtifact;
		}

		// Create a new artifact.
		accountArtifact = db.newBlackboardArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_ACCOUNT, sourceFile.getId());

		Collection<BlackboardAttribute> attributes = new ArrayList<BlackboardAttribute>();
		attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_ACCOUNT_TYPE, moduleName, accountType.getTypeName()));
		attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_ID, moduleName, accountUniqueID));
		accountArtifact.addAttributes(attributes);

		return accountArtifact;
	}

	/**
	 * Get the blackboard artifact for the given account type, account ID, and
	 * source file
	 *
	 * @param accountType     account type
	 * @param accountUniqueID accountID
	 * @param sourceFile		    Source file (for the artifact)
	 *
	 * @return blackboard artifact, returns NULL is no matching account found
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	private BlackboardArtifact getAccountFileInstanceArtifact(Account.Type accountType, String accountUniqueID, Content sourceFile) throws TskCoreException {
		BlackboardArtifact accountArtifact = null;
		CaseDbConnection connection = db.getConnection();
		db.acquireSingleUserCaseReadLock();
		Statement s = null;
		ResultSet rs = null;

		try {
			s = connection.createStatement();
			String queryStr = "SELECT artifacts.artifact_id AS artifact_id,"
					+ " artifacts.obj_id AS obj_id,"
					+ " artifacts.artifact_obj_id AS artifact_obj_id,"
					+ " artifacts.data_source_obj_id AS data_source_obj_id,"
					+ " artifacts.artifact_type_id AS artifact_type_id,"
					+ " artifacts.review_status_id AS review_status_id"
					+ " FROM blackboard_artifacts AS artifacts"
					+ "	JOIN blackboard_attributes AS attr_account_type"
					+ "		ON artifacts.artifact_id = attr_account_type.artifact_id"
					+ " JOIN blackboard_attributes AS attr_account_id"
					+ "		ON artifacts.artifact_id = attr_account_id.artifact_id"
					+ "		AND attr_account_id.attribute_type_id = " + BlackboardAttribute.ATTRIBUTE_TYPE.TSK_ID.getTypeID()
					+ "	    AND attr_account_id.value_text = '" + accountUniqueID + "'"
					+ " WHERE artifacts.artifact_type_id = " + BlackboardArtifact.ARTIFACT_TYPE.TSK_ACCOUNT.getTypeID()
					+ " AND attr_account_type.attribute_type_id = " + BlackboardAttribute.ATTRIBUTE_TYPE.TSK_ACCOUNT_TYPE.getTypeID()
					+ " AND attr_account_type.value_text = '" + accountType.getTypeName() + "'"
					+ " AND artifacts.obj_id = " + sourceFile.getId(); //NON-NLS

			rs = connection.executeQuery(s, queryStr); //NON-NLS
			if (rs.next()) {
				BlackboardArtifact.Type bbartType = db.getArtifactType(rs.getInt("artifact_type_id"));

				accountArtifact = new BlackboardArtifact(db, rs.getLong("artifact_id"), rs.getLong("obj_id"), rs.getLong("artifact_obj_id"), rs.getLong("data_source_obj_id"),
						bbartType.getTypeID(), bbartType.getTypeName(), bbartType.getDisplayName(),
						BlackboardArtifact.ReviewStatus.withID(rs.getInt("review_status_id")));
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting account", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			connection.close();
			db.releaseSingleUserCaseReadLock();
		}

		return accountArtifact;
	}

	/**
	 * Get the Account.Type for the give type name.
	 *
	 * @param accountTypeName An attribute type name.
	 *
	 * @return An account type or null if the account type does not exist.
	 *
	 * @throws TskCoreException If an error occurs accessing the case database.
	 *
	 */
	public Account.Type getAccountType(String accountTypeName) throws TskCoreException {
		if (this.typeNameToAccountTypeMap.containsKey(accountTypeName)) {
			return this.typeNameToAccountTypeMap.get(accountTypeName);
		}
		CaseDbConnection connection = db.getConnection();
		db.acquireSingleUserCaseReadLock();
		Statement s = null;
		ResultSet rs = null;

		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT account_type_id, type_name, display_name, value_type FROM account_types WHERE type_name = '" + accountTypeName + "'"); //NON-NLS
			Account.Type accountType = null;
			if (rs.next()) {
				accountType = new Account.Type(accountTypeName, rs.getString("display_name"));
				this.accountTypeToTypeIdMap.put(accountType, rs.getInt("account_type_id"));
				this.typeNameToAccountTypeMap.put(accountTypeName, accountType);
			}
			return accountType;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting account type id", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			connection.close();
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get the Account object for the given account_id returns null, if does not
	 * exist
	 *
	 * @param account_id account_id
	 *
	 * @return Account, returns NULL is no matching account found
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	private Account getAccount(long account_id) throws TskCoreException {
		Account account = null;
		CaseDbConnection connection = db.getConnection();
		db.acquireSingleUserCaseReadLock();
		Statement s = null;
		ResultSet rs = null;

		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT account_types.type_name as type_name,"
					+ " account_types.display_name as display_name,"
					+ " accounts.account_id as account_id,"
					+ " accounts.account_unique_identifier as account_unique_identifier"
					+ " FROM accounts as accounts"
					+ " JOIN account_types as account_types"
					+ " ON accounts.account_type_id = account_types.account_type_id"
					+ " WHERE accounts.account_id = " + account_id); //NON-NLS

			if (rs.next()) {
				Account.Type accountType = new Account.Type(rs.getString("type_name"), rs.getString("display_name"));
				account = new Account(rs.getInt("account_id"), accountType, rs.getString("account_unique_identifier"));
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting account from account_id", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			connection.close();
			db.releaseSingleUserCaseReadLock();
		}

		return account;
	}

	/**
	 * Adds a row in account relationships table
	 *
	 * @param account1_id                account_id for account1
	 * @param account2_id                account_id for account2
	 * @param relationship_source_obj_id obj_id of the relationship source
	 *                                   object
	 * @param dateTime                   datetime of communication/relationship
	 * @param relationship_type          relationship type
	 * @param data_source_obj_id         datasource object id from where
	 *                                   relationship is extracted
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	private void addAccountsRelationship(long account1_id, long account2_id, long relationship_source_obj_id, long dateTime, int relationship_type, long data_source_obj_id) throws TskCoreException {
		CaseDbConnection connection = db.getConnection();
		db.acquireSingleUserCaseWriteLock();
		Statement s = null;
		ResultSet rs = null;

		try {
			connection.beginTransaction();
			s = connection.createStatement();

			s.execute("INSERT INTO account_relationships (account1_id, account2_id, relationship_source_obj_id, date_time, relationship_type, data_source_obj_id  ) "
					+ "VALUES ( " + account1_id + ", " + account2_id + ", " + relationship_source_obj_id + ", " + dateTime + ", " + relationship_type + ", " + data_source_obj_id + ")"); //NON-NLS
			connection.commitTransaction();
		} catch (SQLException ex) {
			connection.rollbackTransaction();
			throw new TskCoreException("Error adding accounts relationship", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			connection.close();
			db.releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Returns a list of AccountDeviceInstances that have any relationships.
	 *
	 * Applicable filters: DeviceFilter, AccountTypeFilter, DateRangeFilter,
	 * RelationshipTypeFilter
	 *
	 * @param filter filters to apply
	 *
	 * @return list of AccountDeviceInstances
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	public List<AccountDeviceInstance> getAccountDeviceInstancesWithRelationships(CommunicationsFilter filter) throws TskCoreException {
		CaseDbConnection connection = db.getConnection();
		db.acquireSingleUserCaseReadLock();
		Statement s = null;
		ResultSet rs = null;

		try {
			s = connection.createStatement();

			//set up applicable filters 
			Set<String> applicableInnerQueryFilters = new HashSet<String>(Arrays.asList(
					CommunicationsFilter.DateRangeFilter.class.getName(),
					CommunicationsFilter.DeviceFilter.class.getName(),
					CommunicationsFilter.RelationshipTypeFilter.class.getName()
			));
			String innerQueryfilterSQL = getCommunicationsFilterSQL(filter, applicableInnerQueryFilters);

			String innerQueryTemplate
					= " SELECT %1$1s as account_id,"
					+ "		  data_source_obj_id"
					+ " FROM account_relationships as relationships"
					+ (innerQueryfilterSQL.isEmpty() ? "" : " WHERE " + innerQueryfilterSQL);

			String innerQuery1 = String.format(innerQueryTemplate, "account1_id");
			String innerQuery2 = String.format(innerQueryTemplate, "account2_id");

			//this query groups by account_id and data_source_obj_id across both innerQueries
			String combinedInnerQuery
					= "SELECT count(*) as relationship_count, account_id, data_source_obj_id "
					+ " FROM ( " + innerQuery1 + " UNION " + innerQuery2 + " ) "
					+ " GROUP BY account_id, data_source_obj_id";

			// set up applicable filters
			Set<String> applicableFilters = new HashSet<String>(Arrays.asList(
					CommunicationsFilter.AccountTypeFilter.class.getName()
			));
			String filterSQL = getCommunicationsFilterSQL(filter, applicableFilters);

			String queryStr = "SELECT "
					//account info
					+ " accounts.account_id AS account_id,"
					+ " accounts.account_unique_identifier AS account_unique_identifier,"
					//account type info
					+ " account_types.type_name AS type_name,"
					//Account device instance info
					+ " relationship_count,"
					+ " data_source_info.device_id AS device_id"
					+ " FROM ( " + combinedInnerQuery + " ) AS account_device_instances"
					+ " JOIN accounts AS accounts"
					+ "		ON accounts.account_id = account_device_instances.account_id"
					+ " JOIN account_types AS account_types"
					+ "		ON accounts.account_type_id = account_types.account_type_id"
					+ " JOIN data_source_info AS data_source_info"
					+ "		ON account_device_instances.data_source_obj_id = data_source_info.obj_id"
					+ (filterSQL.isEmpty() ? "" : " WHERE " + filterSQL)
					+ " GROUP BY accounts.account_id, data_source_info.device_id";

			rs = connection.executeQuery(s, queryStr); //NON-NLS
			ArrayList<AccountDeviceInstance> accountDeviceInstances = new ArrayList<AccountDeviceInstance>();
			while (rs.next()) {
				long account_id = rs.getLong("account_id");
				String deviceID = rs.getString("device_id");
				final String type_name = rs.getString("type_name");
				final String account_unique_identifier = rs.getString("account_unique_identifier");

				Account.Type accountType = typeNameToAccountTypeMap.get(type_name);
				Account account = new Account(account_id, accountType, account_unique_identifier);
				accountDeviceInstances.add(new AccountDeviceInstance(account, deviceID));
			}
			return accountDeviceInstances;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting account device instances. " + ex.getMessage(), ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			connection.close();
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get the number of unique relationship sources found for the given account
	 * device instance.
	 *
	 * Applicable filters: RelationshipTypeFilter, DateRangeFilter
	 *
	 * @param accountDeviceInstance Account Device.
	 * @param filter                Filters to apply.
	 *
	 * @return number of account relationships found for this account.
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 *
	 */
	public long getRelationshipSourcesCount(AccountDeviceInstance accountDeviceInstance, CommunicationsFilter filter) throws TskCoreException {

		long account_id = accountDeviceInstance.getAccount().getAccountID();

		// Get the list of Data source objects IDs correpsonding to this DeviceID.
		String datasourceObjIdsCSV = StringUtils.buildCSVString(
				db.getDataSourceObjIds(accountDeviceInstance.getDeviceId()));

		// set up applicable filters
		Set<String> applicableFilters = new HashSet<String>(Arrays.asList(
				CommunicationsFilter.RelationshipTypeFilter.class.getName(),
				CommunicationsFilter.DateRangeFilter.class.getName()
		));
		String filterSQL = getCommunicationsFilterSQL(filter, applicableFilters);

		CaseDbConnection connection = db.getConnection();
		db.acquireSingleUserCaseReadLock();
		Statement s = null;
		ResultSet rs = null;

		try {
			s = connection.createStatement();

			String queryStr
					= "SELECT count(DISTINCT relationships.relationship_source_obj_id) as count "
					+ "	FROM account_relationships AS relationships"
					+ " WHERE relationships.data_source_obj_id IN ( " + datasourceObjIdsCSV + " )"
					+ " AND ( relationships.account1_id = " + account_id
					+ "      OR  relationships.account2_id = " + account_id + " )"
					+ (filterSQL.isEmpty() ? "" : " AND " + filterSQL);

			System.out.println("JONATHAN: " + queryStr);
			rs = connection.executeQuery(s, queryStr); //NON-NLS
			rs.next();
			return (rs.getLong("count"));
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting relationships count for account device instance. " + ex.getMessage(), ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			connection.close();
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get the unique relationship sources found for the given account device
	 * instances.
	 *
	 * Applicable filters: RelationshipTypeFilter, DateRangeFilter
	 *
	 * @param accountDeviceInstanceList set of account device instances for
	 *                                  which to get the relationship sources.
	 * @param filter                    Filters to apply.
	 *
	 * @return number of relationship sources found for given account(s).
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	public Set<BlackboardArtifact> getRelationshipSources(Set<AccountDeviceInstance> accountDeviceInstanceList, CommunicationsFilter filter) throws TskCoreException {

		if (accountDeviceInstanceList.isEmpty()) {
			//log this?
			return Collections.emptySet();
		}
		System.out.println("RAMAN getCommunications() Num AccountDeviceInstancees = " + accountDeviceInstanceList.size());

		Map<Long, Set<Long>> accountIdToDatasourceObjIdMap = new HashMap<Long, Set<Long>>();
		for (AccountDeviceInstance accountDeviceInstance : accountDeviceInstanceList) {
			long accountID = accountDeviceInstance.getAccount().getAccountID();
			List<Long> dataSourceObjIds = db.getDataSourceObjIds(accountDeviceInstance.getDeviceId());

			if (accountIdToDatasourceObjIdMap.containsKey(accountID)) {
				accountIdToDatasourceObjIdMap.get(accountID).addAll(dataSourceObjIds);
			} else {
				accountIdToDatasourceObjIdMap.put(accountID, new HashSet<Long>(dataSourceObjIds));
			}
		}

		List<String> adiSQLClauses = new ArrayList<String>();
		for (Map.Entry<Long, Set<Long>> entry : accountIdToDatasourceObjIdMap.entrySet()) {
			final Long accountID = entry.getKey();
			String datasourceObjIdsCSV = StringUtils.buildCSVString(entry.getValue());

			adiSQLClauses.add(
					"( relationships.data_source_obj_id IN ( " + datasourceObjIdsCSV + " ) )"
					+ " AND ( relationships.account1_id = " + accountID
					+ " OR relationships.account2_id = " + accountID + " )"
			);
		}
		String adiSQLClause = StringUtils.joinAsStrings(adiSQLClauses, " OR ");

		// set up applicable filters
		Set<String> applicableFilters = new HashSet<String>(Arrays.asList(
				CommunicationsFilter.RelationshipTypeFilter.class.getName(),
				CommunicationsFilter.DateRangeFilter.class.getName()
		));
		String filterSQL = getCommunicationsFilterSQL(filter, applicableFilters);

		CaseDbConnection connection = db.getConnection();
		db.acquireSingleUserCaseReadLock();
		Statement s = null;
		ResultSet rs = null;

		try {
			s = connection.createStatement();
			String queryStr
					= "SELECT DISTINCT "
					+ " artifacts.artifact_id AS artifact_id,"
					+ " artifacts.obj_id AS obj_id,"
					+ " artifacts.artifact_obj_id AS artifact_obj_id,"
					+ " artifacts.data_source_obj_id AS data_source_obj_id, "
					+ " artifacts.artifact_type_id AS artifact_type_id, "
					+ " artifacts.review_status_id AS review_status_id  "
					+ " FROM blackboard_artifacts as artifacts"
					+ "	JOIN account_relationships AS relationships"
					+ "		ON artifacts.artifact_obj_id = relationships.relationship_source_obj_id"
					// append sql to restrict search to specified account device instances 
					+ " WHERE (" + adiSQLClause + " )"
					// plus other filters
					+ (filterSQL.isEmpty() ? "" : " AND (" + filterSQL + " )");

			System.out.println("RAMAN getCommunications() adiSQLClause = " + adiSQLClause);
			System.out.println("RAMAN getCommunications() FilterSQL = " + filterSQL);
			System.out.println("RAMAN getCommunications() QueryStr = " + queryStr);

			long startTime = System.nanoTime();
			rs = connection.executeQuery(s, queryStr); //NON-NLS
			Set<BlackboardArtifact> artifacts = new HashSet<BlackboardArtifact>();
			while (rs.next()) {
				BlackboardArtifact.Type bbartType = db.getArtifactType(rs.getInt("artifact_type_id"));
				artifacts.add(new BlackboardArtifact(db, rs.getLong("artifact_id"),
						rs.getLong("obj_id"), rs.getLong("artifact_obj_id"),
						rs.getLong("data_source_obj_id"), bbartType.getTypeID(),
						bbartType.getTypeName(), bbartType.getDisplayName(),
						BlackboardArtifact.ReviewStatus.withID(rs.getInt("review_status_id"))));
			}

			long endTime = System.nanoTime();
			System.out.println("RAMAN getCommunications() Time taken = " + (endTime - startTime) / 1000000L);
			System.out.println("");

			return artifacts;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting relationships for account. " + ex.getMessage(), ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			connection.close();
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get account_type_if for the given account type.
	 *
	 * @param accountType account type to lookup.
	 *
	 * @return account_type_id for the given account type. 0 if not known.
	 */
	int getAccountTypeId(Account.Type accountType) {
		if (accountTypeToTypeIdMap.containsKey(accountType)) {
			return accountTypeToTypeIdMap.get(accountType);
		}

		return 0;
	}

	/**
	 * Converts a list of accountIDs into a set of possible unordered pairs.
	 *
	 * @param account_ids - list of accountID.
	 *
	 * @return Set<UnorderedPair<Long>>
	 */
	private Set<UnorderedAccountPair> listToUnorderedPairs(List<Long> account_ids) {
		Set<UnorderedAccountPair> relationships = new HashSet<UnorderedAccountPair>();

		for (int i = 0; i < account_ids.size(); i++) {
			for (int j = i + 1; j < account_ids.size(); j++) {
				relationships.add(new UnorderedAccountPair(account_ids.get(i), account_ids.get(j)));
			}
		}

		return relationships;
	}

	private String normalizeAccountID(Account.Type accountType, String accountUniqueID) {
		String normailzeAccountID = accountUniqueID;

		if (accountType.equals(Account.Type.PHONE)) {
			normailzeAccountID = normalizePhoneNum(accountUniqueID);
		} else if (accountType.equals(Account.Type.EMAIL)) {
			normailzeAccountID = normalizeEmailAddress(accountUniqueID);
		}

		return normailzeAccountID;
	}

	private String normalizePhoneNum(String phoneNum) {
		String normailzedPhoneNum = phoneNum.replaceAll("\\D", "");

		if (phoneNum.startsWith("+")) {
			normailzedPhoneNum = "+" + normailzedPhoneNum;
		}

		return normailzedPhoneNum;
	}

	private String normalizeEmailAddress(String emailAddress) {
		String normailzedEmailAddr = emailAddress.toLowerCase();

		return normailzedEmailAddr;
	}

	/**
	 * Builds the SQL for the given CommunicationsFilter.
	 *
	 * Gets the SQL for each subfilter and combines using AND.
	 *
	 * @param commFilter        The CommunicationsFilter to get the SQL for.
	 * @param applicableFilters A Set of names of classes of subfilters that are
	 *                          applicable. SubFilters not in this list will be
	 *                          ignored.
	 *
	 * @return return SQL suitible for use IN a where clause.
	 */
	private String getCommunicationsFilterSQL(CommunicationsFilter commFilter, Set<String> applicableFilters) {
		if (null == commFilter || commFilter.getAndFilters().isEmpty()) {
			return "";
		}

		String sqlStr = "";
		StringBuilder sqlSB = new StringBuilder();
		boolean first = true;
		for (CommunicationsFilter.SubFilter subFilter : commFilter.getAndFilters()) {

			// If the filter is applicable
			if (applicableFilters.contains(subFilter.getClass().getName())) {
				String subfilterSQL = subFilter.getSQL(this);
				if (!subfilterSQL.isEmpty()) {
					if (first) {
						first = false;
					} else {
						sqlSB.append(" AND ");
					}
					sqlSB.append("( ");
					sqlSB.append(subfilterSQL);
					sqlSB.append(" )");
				}
			}
		}

		if (!sqlSB.toString().isEmpty()) {
			sqlStr = "( " + sqlSB.toString() + " )";
		}
		return sqlStr;
	}

	/**
	 * Class representing an unordered pair of account ids. <a,b> is same as
	 * <b,a>
	 */
	private final class UnorderedAccountPair {

		private final long account1_id;
		private final long account2_id;

		UnorderedAccountPair(long account1_id, long account2_id) {
			this.account1_id = account1_id;
			this.account2_id = account2_id;
		}

		@Override
		public int hashCode() {
			return new Long(account1_id).hashCode() + new Long(account2_id).hashCode();
		}

		@Override
		public boolean equals(Object other) {
			if (other == this) {
				return true;
			}
			if (!(other instanceof UnorderedAccountPair)) {
				return false;
			}

			UnorderedAccountPair otherPair = (UnorderedAccountPair) other;
			return ((account1_id == otherPair.account1_id && account2_id == otherPair.account2_id)
					|| (account1_id == otherPair.account2_id && account2_id == otherPair.account1_id));
		}

		public long getFirst() {
			return account1_id;
		}

		public long getSecond() {
			return account2_id;
		}
	}

//	 /**
//	 * Get all account instances of a given type
//	 *
//	 * @param accountType account type
//	 *
//	 * @return List <Account.Type>, list of accounts
//	 *
//	 * @throws TskCoreException exception thrown if a critical error occurs
//	 *                          within TSK core
//	 */
//	public List<AccountInstance> getAccountInstances(Account.Type accountType) throws TskCoreException {
//		List<AccountInstance> accountInstances = new ArrayList<AccountInstance>();
//
//		// First get all accounts of the type
//		List<Account> accounts = getAccounts(accountType);
//
//		// get all instances for each account
//		for (Account account : accounts) {
//			List<Long> accountInstanceIds = getAccountInstanceIds(account.getAccountID());
//
//			for (long artifact_id : accountInstanceIds) {
//				accountInstances.add(new AccountFileInstance(db, db.getBlackboardArtifact(artifact_id), account));
//			}
//		}
//
//		return accountInstances;
//	}
//	/**
//	 * Given an account ID, returns the ids of all instances of the account
//	 *
//	 * @param account_id account id
//	 *
//	 * @return List <Long>, list of account instance IDs
//	 *
//	 * @throws TskCoreException exception thrown if a critical error occurs
//	 *                          within TSK core
//	 */
//	List<Long> getAccountInstanceIds(long account_id) throws TskCoreException {
//		ArrayList<Long> accountInstanceIDs = new ArrayList<Long>();
//		CaseDbConnection connection = db.getConnection();
//		db.acquireSingleUserCaseReadLock();
//		Statement s = null;
//		ResultSet rs = null;
//
//		try {
//			s = connection.createStatement();
//			rs = connection.executeQuery(s, "SELECT * FROM account_to_instances_map WHERE account_id = " + account_id); //NON-NLS
//			while (rs.next()) {
//				accountInstanceIDs.add(rs.getLong("account_instance_id"));
//			}
//			return accountInstanceIDs;
//		} catch (SQLException ex) {
//			throw new TskCoreException("Error getting account_instance_id from by account_id. " + ex.getMessage(), ex);
//		} finally {
//			closeResultSet(rs);
//			closeStatement(s);
//			connection.close();
//			db.releaseSingleUserCaseReadLock();
//		}
//	}
//	/**
//	 * Get all account types in use
//	 *
//	 * @return List <Account.Type>, list of account types in use
//	 *
//	 * @throws TskCoreException exception thrown if a critical error occurs
//	 *                          within TSK core
//	 */
//	public List<Account.Type> getAccountTypesInUse() throws TskCoreException {
//		String query = "SELECT DISTINCT value_text FROM blackboard_attributes "
//				+ "WHERE attribute_type_id = " + BlackboardAttribute.ATTRIBUTE_TYPE.TSK_ACCOUNT_TYPE.getTypeID();
//		CaseDbConnection connection = db.getConnection();
//		db.acquireSingleUserCaseReadLock();
//		Statement s = null;
//		ResultSet rs = null;
//
//		try {
//			s = connection.createStatement();
//			rs = connection.executeQuery(s, query);
//			ArrayList<Account.Type> usedAccountTypes = new ArrayList<Account.Type>();
//			while (rs.next()) {
//				String accountTypeString = rs.getString("value_text");
//				usedAccountTypes.add(getAccountType(accountTypeString));
//			}
//
//			return usedAccountTypes;
//		} catch (SQLException ex) {
//			throw new TskCoreException("Error getting account types in use", ex);
//		} finally {
//			closeResultSet(rs);
//			closeStatement(s);
//			connection.close();
//			db.releaseSingleUserCaseReadLock();
//		}
//	}
//	/**
//	 * Get all accounts of given type
//	 *
//	 * @param accountType account type
//	 *
//	 * @return List <Account.Type>, list of accounts
//	 *
//	 * @throws TskCoreException exception thrown if a critical error occurs
//	 *                          within TSK core
//	 */
//	public List<Account> getAccounts(Account.Type accountType) throws TskCoreException {
//		ArrayList<Account> accounts = new ArrayList<Account>();
//		CaseDbConnection connection = db.getConnection();
//		db.acquireSingleUserCaseReadLock();
//		Statement s = null;
//		ResultSet rs = null;
//
//		try {
//			s = connection.createStatement();
//			rs = connection.executeQuery(s, "SELECT * FROM accounts WHERE account_type_id = " + getAccountTypeId(accountType)); //NON-NLS
//			while (rs.next()) {
//				accounts.add(new Account(rs.getInt("account_id"), accountType,
//						rs.getString("account_unique_identifier")));
//
//			}
//
//			return accounts;
//		} catch (SQLException ex) {
//			throw new TskCoreException("Error getting accounts by type. " + ex.getMessage(), ex);
//		} finally {
//			closeResultSet(rs);
//			closeStatement(s);
//			connection.close();
//			db.releaseSingleUserCaseReadLock();
//		}
//	}
//	/**
//	 * Get all accounts that have a relationship with the given account
//	 *
//	 * @param account account for which to search relationships
//	 *
//	 * @return list of accounts with relationships to the given account
//	 *
//	 * @throws TskCoreException exception thrown if a critical error occurs
//	 *                          within TSK core
//	 */
//	public List<Account> getAccountsWithRelationship(Account account) throws TskCoreException {
//		return getAccountsWithRelationship(account.getAccountID());
//	}
//	/**
//	 * Get all account that have a relationship with a given account
//	 *
//	 * @param account_id account id
//	 *
//	 * @return List<Account>, list of accounts
//	 *
//	 * @throws TskCoreException exception thrown if a critical error occurs
//	 *                          within TSK core
//	 */
//	List<Account> getAccountsWithRelationship(long accountID) throws TskCoreException {
//		CaseDbConnection connection = db.getConnection();
//		db.acquireSingleUserCaseReadLock();
//		Statement s = null;
//		ResultSet rs = null;
//
//		try {
//			s = connection.createStatement();
//			rs = connection.executeQuery(s, "SELECT account1_id, account2_id "
//					+ " FROM relationships"
//					+ " WHERE  account1_id = " + accountID
//					+ "        OR  account2_id = " + accountID); //NON-NLS
//
//			ArrayList<Account> accounts = new ArrayList<Account>();
//			while (rs.next()) {
//				long otherAccountID = (accountID == rs.getLong("account1_id")) ? rs.getLong("account2_id") : rs.getLong("account1_id");
//				Account account = getAccount(otherAccountID);
//				if (null != account) {
//					accounts.add(account);
//				}
//			}
//
//			return accounts;
//		} catch (SQLException ex) {
//			throw new TskCoreException("Error getting relationships by account by ID. " + ex.getMessage(), ex);
//		} finally {
//			closeResultSet(rs);
//			closeStatement(s);
//			connection.close();
//			db.releaseSingleUserCaseReadLock();
//		}
//	}
//	/**
//	 * Return folders found in the email source file
//	 *
//	 * @param srcObjID pbjectID of the email PST/Mbox source file
//	 *
//	 * @return list of message folders
//	 *
//	 * @throws TskCoreException exception thrown if a critical error occurs
//	 *                          within TSK core
//	 */
//	public List<MessageFolder> getMessageFolders(long srcObjID) throws TskCoreException {
//		CaseDbConnection connection = db.getConnection();
//		db.acquireSingleUserCaseReadLock();
//		Statement s = null;
//		ResultSet rs = null;
//
//		try {
//			s = connection.createStatement();
//			rs = connection.executeQuery(s, "SELECT DISTINCT attributes.value_text AS folder_path"
//					+ " FROM blackboard_artifacts AS artifacts"
//					+ "	JOIN blackboard_attributes AS attributes"
//					+ "		ON artifacts.artifact_id = attributes.artifact_id"
//					+ "		AND artifacts.obj_id = " + srcObjID
//					+ " WHERE artifacts.artifact_type_id = " + BlackboardArtifact.ARTIFACT_TYPE.TSK_EMAIL_MSG.getTypeID()
//					+ "     AND attributes.attribute_type_id =  " + BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PATH.getTypeID()
//			); //NON-NLS
//
//			ArrayList<MessageFolder> messageFolders = new ArrayList<MessageFolder>();
//			while (rs.next()) {
//				String folder = rs.getString("folder_path");
//
//				// TBD: check if this folder has subfolders and set hasSubFolders accordingly.
//				messageFolders.add(new MessageFolder(folder, srcObjID));
//			}
//
//			return messageFolders;
//		} catch (SQLException ex) {
//			throw new TskCoreException("Error getting message folders. " + ex.getMessage(), ex);
//		} finally {
//			closeResultSet(rs);
//			closeStatement(s);
//			connection.close();
//			db.releaseSingleUserCaseReadLock();
//		}
//
//	}
//
//	/**
//	 * Return subfolders found in the email source file under the specified
//	 * folder
//	 *
//	 * @param srcObjID     objectID of the email PST/Mbox source file
//	 * @param parentfolder parent folder of messages to return
//	 *
//	 * @return list of message sub-folders
//	 *
//	 * @throws TskCoreException exception thrown if a critical error occurs
//	 *                          within TSK core
//	 */
//	public List<MessageFolder> getMessageFolders(long srcObjID, MessageFolder parentfolder) throws TskCoreException {
//		CaseDbConnection connection = db.getConnection();
//		db.acquireSingleUserCaseReadLock();
//		Statement s = null;
//		ResultSet rs = null;
//
//		try {
//			s = connection.createStatement();
//			rs = connection.executeQuery(s, "SELECT DISTINCT attributes.value_text AS folder_path"
//					+ " FROM blackboard_artifacts AS artifacts"
//					+ "	JOIN blackboard_attributes AS attributes"
//					+ "		ON artifacts.artifact_id = attributes.artifact_id"
//					+ "		AND artifacts.obj_id = " + srcObjID
//					+ "     WHERE artifacts.artifact_type_id = " + BlackboardArtifact.ARTIFACT_TYPE.TSK_EMAIL_MSG.getTypeID()
//					+ " AND attributes.attribute_type_id =  " + BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PATH.getTypeID()
//					+ " AND attributes.value_text LIKE '" + parentfolder.getName() + "%'"
//			); //NON-NLS
//
//			ArrayList<MessageFolder> messageFolders = new ArrayList<MessageFolder>();
//			while (rs.next()) {
//				String folder = rs.getString("folder_path");
//				messageFolders.add(new MessageFolder(folder, srcObjID));
//			}
//
//			return messageFolders;
//		} catch (SQLException ex) {
//			throw new TskCoreException("Error getting message folders. " + ex.getMessage(), ex);
//		} finally {
//			closeResultSet(rs);
//			closeStatement(s);
//			connection.close();
//			db.releaseSingleUserCaseReadLock();
//		}
//
//	}
//	/**
//	 * Return email messages under given folder
//	 *
//	 * @param parentfolder parent folder of messages to return
//	 *
//	 * @return list of messages
//	 *
//	 * @throws TskCoreException exception thrown if a critical error occurs
//	 *                          within TSK core
//	 */
//	public List<BlackboardArtifact> getMessages(MessageFolder parentfolder) throws TskCoreException {
//		CaseDbConnection connection = db.getConnection();
//		db.acquireSingleUserCaseReadLock();
//		Statement s = null;
//		ResultSet rs = null;
//
//		try {
//			s = connection.createStatement();
//			rs = connection.executeQuery(s, "SELECT artifacts.artifact_id AS artifact_id,"
//					+ " artifacts.obj_id AS obj_id,"
//					+ " artifacts.artifact_obj_id AS artifact_obj_id,"
//					+ " artifacts.data_source_obj_id AS data_source_obj_id, "
//					+ " artifacts.artifact_type_id AS artifact_type_id, "
//					+ " artifacts.review_status_id AS review_status_id,  "
//					+ " FROM blackboard_artifacts AS artifacts"
//					+ "	JOIN blackboard_attributes AS attributes"
//					+ "		ON artifacts.artifact_id = attributes.artifact_id"
//					+ "		AND artifacts.artifact_type_id = " + BlackboardArtifact.ARTIFACT_TYPE.TSK_EMAIL_MSG.getTypeID()
//					+ " WHERE attributes.attribute_type_id =  " + BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PATH.getTypeID()
//					+ " AND attributes.value_text  =  '" + parentfolder.getName() + "' "
//			); //NON-NLS
//
//			ArrayList<BlackboardArtifact> artifacts = new ArrayList<BlackboardArtifact>();
//			while (rs.next()) {
//				BlackboardArtifact.Type bbartType = db.getArtifactType(rs.getInt("artifact_type_id"));
//				artifacts.add(new BlackboardArtifact(db, rs.getLong("artifact_id"), rs.getLong("obj_id"), rs.getLong("artifact_obj_id"), rs.getLong("data_source_obj_id"),
//						bbartType.getTypeID(), bbartType.getTypeName(), bbartType.getDisplayName(),
//						BlackboardArtifact.ReviewStatus.withID(rs.getInt("review_status_id"))));
//			}
//
//			return artifacts;
//		} catch (SQLException ex) {
//			throw new TskCoreException("Error getting messages. " + ex.getMessage(), ex);
//		} finally {
//			closeResultSet(rs);
//			closeStatement(s);
//			connection.close();
//			db.releaseSingleUserCaseReadLock();
//		}
//
//	}
//	/**
//	 * Returns unique relation types between two accounts
//	 *
//	 * @param account1 account
//	 * @param account2 account
//	 *
//	 * @return list of unique relationship types between two accounts
//	 *
//	 * @throws TskCoreException exception thrown if a critical error occurs
//	 *                          within TSK core
//	 */
//	public List<BlackboardArtifact.Type> getRelationshipTypes(Account account1, Account account2) throws TskCoreException {
//		return getRelationshipTypes(account1.getAccountID(), account2.getAccountID());
//	}
//	/**
//	 * Returns unique relation types between two accounts
//	 *
//	 * @param account1_id account1 artifact ID
//	 * @param account2_id account2 artifact ID
//	 *
//	 * @throws TskCoreException exception thrown if a critical error occurs
//	 *                          within TSK core
//	 */
//	List<BlackboardArtifact.Type> getRelationshipTypes(long account1_id, long account2_id) throws TskCoreException {
//		CaseDbConnection connection = db.getConnection();
//		db.acquireSingleUserCaseReadLock();
//		Statement s = null;
//		ResultSet rs = null;
//
//		try {
//			s = connection.createStatement();
//			rs = connection.executeQuery(s, "SELECT DISTINCT artifacts.artifact_id AS artifact_id,"
//					+ " artifacts.obj_id AS obj_id,"
//					+ " artifacts.artifact_obj_id AS artifact_obj_id,"
//					+ " artifacts.artifact_type_id AS artifact_type_id,"
//					+ " artifacts.review_status_id AS review_status_id"
//					+ " FROM blackboard_artifacts AS artifacts"
//					+ "	JOIN relationships AS relationships"
//					+ "		ON artifacts.artifact_obj_id = relationships.relationship_source_obj_id"
//					+ " WHERE relationships.account1_id IN ( " + account1_id + ", " + account2_id + " )"
//					+ " AND relationships.account2_id IN ( " + account1_id + ", " + account2_id + " )"
//			); //NON-NLS
//
//			ArrayList<BlackboardArtifact.Type> artifactTypes = new ArrayList<BlackboardArtifact.Type>();
//			while (rs.next()) {
//				BlackboardArtifact.Type bbartType = db.getArtifactType(rs.getInt("artifact_type_id"));
//				artifactTypes.add(bbartType);
//			}
//
//			return artifactTypes;
//		} catch (SQLException ex) {
//			throw new TskCoreException("Error getting relationship types." + ex.getMessage(), ex);
//		} finally {
//			closeResultSet(rs);
//			closeStatement(s);
//			connection.close();
//			db.releaseSingleUserCaseReadLock();
//		}
//	}
//	/**
//	 * Returns relationships between two accounts
//	 *
//	 * @param account1_id account_id for account1
//	 * @param account2_id account_id for account2
//	 *
//	 * @throws TskCoreException exception thrown if a critical error occurs
//	 *                          within TSK core
//	 */
//	public List<BlackboardArtifact> getRelationships(long account1_id, long account2_id) throws TskCoreException {
//		CaseDbConnection connection = db.getConnection();
//		db.acquireSingleUserCaseReadLock();
//		Statement s = null;
//		ResultSet rs = null;
//
//		try {
//			s = connection.createStatement();
//			rs = connection.executeQuery(s, "SELECT artifacts.artifact_id AS artifact_id,"
//					+ " artifacts.obj_id AS obj_id,"
//					+ " artifacts.artifact_obj_id AS artifact_obj_id,"
//					+ " artifacts.data_source_obj_id AS data_source_obj_id,"
//					+ " artifacts.artifact_type_id AS artifact_type_id,"
//					+ " artifacts.review_status_id AS review_status_id"
//					+ " FROM blackboard_artifacts AS artifacts"
//					+ "	JOIN relationships AS relationships"
//					+ "		ON artifacts.artifact_obj_id = relationships.relationship_source_obj_id"
//					+ " WHERE relationships.account1_id IN ( " + account1_id + ", " + account2_id + " )"
//					+ " AND relationships.account2_id IN ( " + account1_id + ", " + account2_id + " )"
//			); //NON-NLS
//
//			ArrayList<BlackboardArtifact> artifacts = new ArrayList<BlackboardArtifact>();
//			while (rs.next()) {
//				BlackboardArtifact.Type bbartType = db.getArtifactType(rs.getInt("artifact_type_id"));
//				artifacts.add(new BlackboardArtifact(db, rs.getLong("artifact_id"), rs.getLong("obj_id"), rs.getLong("artifact_obj_id"), rs.getLong("data_source_obj_id"),
//						bbartType.getTypeID(), bbartType.getTypeName(), bbartType.getDisplayName(),
//						BlackboardArtifact.ReviewStatus.withID(rs.getInt("review_status_id"))));
//			}
//
//			return artifacts;
//		} catch (SQLException ex) {
//			throw new TskCoreException("Error getting relationships bteween accounts. " + ex.getMessage(), ex);
//		} finally {
//			closeResultSet(rs);
//			closeStatement(s);
//			connection.close();
//			db.releaseSingleUserCaseReadLock();
//		}
//	}
//	/**
//	 * Returns relationships, of given type, between two accounts
//	 *
//	 * @param account1_id  account1 artifact ID
//	 * @param account2_id  account2 artifact ID
//	 * @param artifactType artifact type
//	 *
//	 *
//	 * @throws TskCoreException exception thrown if a critical error occurs
//	 *                          within TSK core
//	 */
//	public List<BlackboardArtifact> getRelationshipsOfType(long account1_id, long account2_id, BlackboardArtifact.Type artifactType) throws TskCoreException {
//		CaseDbConnection connection = db.getConnection();
//		db.acquireSingleUserCaseReadLock();
//		Statement s = null;
//		ResultSet rs = null;
//
//		try {
//			s = connection.createStatement();
//			rs = connection.executeQuery(s, "SELECT artifacts.artifact_id AS artifact_id,"
//					+ " artifacts.obj_id AS obj_id,"
//					+ " artifacts.artifact_obj_id AS artifact_obj_id,"
//					+ " artifacts.data_source_obj_id AS data_source_obj_id,"
//					+ " artifacts.artifact_type_id AS artifact_type_id,"
//					+ " artifacts.review_status_id AS review_status_id"
//					+ "	FROM relationships AS relationships"
//					+ " WHERE artifacts.artifact_type_id = " + artifactType.getTypeID()
//					+ "     AND relationships.account1_id IN ( " + account1_id + ", " + account2_id + " )"
//					+ "     AND relationships.account2_id IN ( " + account1_id + ", " + account2_id + " )"
//			); //NON-NLS
//
//			ArrayList<BlackboardArtifact> artifacts = new ArrayList<BlackboardArtifact>();
//			while (rs.next()) {
//				BlackboardArtifact.Type bbartType = db.getArtifactType(rs.getInt("artifact_type_id"));
//				artifacts.add(new BlackboardArtifact(db, rs.getLong("artifact_id"), rs.getLong("obj_id"), rs.getLong("artifact_obj_id"), rs.getLong("data_source_obj_id"),
//						bbartType.getTypeID(), bbartType.getTypeName(), bbartType.getDisplayName(),
//						BlackboardArtifact.ReviewStatus.withID(rs.getInt("review_status_id"))));
//			}
//
//			return artifacts;
//		} catch (SQLException ex) {
//			throw new TskCoreException("Error getting relationships bteween accounts. " + ex.getMessage(), ex);
//		} finally {
//			closeResultSet(rs);
//			closeStatement(s);
//			connection.close();
//			db.releaseSingleUserCaseReadLock();
//		}
//	}
//	/**
//	 * Get the number of relationships found on the given device
//	 *
//	 * @param deviceId device to look up
//	 *
//	 * RAMAN TBD: add filter param
//	 *
//	 * @return number of account relationships found on this device
//	 *
//	 * @throws org.sleuthkit.datamodel.TskCoreException
//	 */
//	public long getRelationshipsCountByDevice(String deviceId) throws TskCoreException {
//		List<Long> ds_ids = db.getDataSourceObjIds(deviceId);
//		String datasource_obj_ids_list = buildCSVString(ds_ids);
//		CaseDbConnection connection = db.getConnection();
//		db.acquireSingleUserCaseReadLock();
//		Statement s = null;
//		ResultSet rs = null;
//
//		try {
//			s = connection.createStatement();
//			String queryStr = "SELECT COUNT(*) AS count "
//					+ " FROM blackboard_artifacts as artifacts"
//					+ "	JOIN relationships AS relationships"
//					+ "		ON artifacts.artifact_id = relationships.relationship_source_obj_id"
//					+ " WHERE artifacts.data_source_obj_id IN ( " + datasource_obj_ids_list + " )"
//					+ " AND   artifacts.artifact_type_id IN ( " + RELATIONSHIP_ARTIFACT_TYPE_IDS_CSV_STR + " )";
//
//			System.out.println("RAMAN QueryStr = " + queryStr);
//			System.out.println("");
//
//			// RAMAN TBD: add SQL from filters
//			rs = connection.executeQuery(s, queryStr); //NON-NLS
//			rs.next();
//
//			return (rs.getLong("count"));
//		} catch (SQLException ex) {
//			throw new TskCoreException("Error getting relationships bteween accounts. " + ex.getMessage(), ex);
//		} finally {
//			closeResultSet(rs);
//			closeStatement(s);
//			connection.close();
//			db.releaseSingleUserCaseReadLock();
//		}
//	}
//	/**
//	 *
//	 * @param accountId         - database row id
//	 * @param accountInstanceId - Artifact ID of instance
//	 *
//	 * @throws TskCoreException
//	 */
//	private void addAccountFileInstanceMapping(long accountId, long accountInstanceId) throws TskCoreException {
//		CaseDbConnection connection = db.getConnection();
//		db.acquireSingleUserCaseWriteLock();
//		Statement s = null;
//		ResultSet rs = null;
//
//		try {
//			connection.beginTransaction();
//			s = connection.createStatement();
//
//			s.execute("INSERT INTO account_to_instances_map (account_id, account_instance_id) VALUES ( " + accountId + ", " + accountInstanceId + " )"); //NON-NLS
//			connection.commitTransaction();
//		} catch (SQLException ex) {
//			connection.rollbackTransaction();
//			throw new TskCoreException("Error adding an account to instance mapping", ex);
//		} finally {
//			closeResultSet(rs);
//			closeStatement(s);
//			connection.close();
//			db.releaseSingleUserCaseWriteLock();
//		}
//	}
}
