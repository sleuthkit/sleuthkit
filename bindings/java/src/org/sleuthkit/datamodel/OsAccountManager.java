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

import com.google.common.base.Strings;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.sleuthkit.datamodel.BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbConnection;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbTransaction;

/**
 * Responsible for creating/updating/retrieving the OS user accounts for files
 * and artifacts.
 *
 */
public final class OsAccountManager {

	private static final Logger LOGGER = Logger.getLogger(OsAccountManager.class.getName());

	private final SleuthkitCase db;

	/**
	 * Construct a OsUserManager for the given SleuthkitCase.
	 *
	 * @param skCase The SleuthkitCase
	 *
	 */
	OsAccountManager(SleuthkitCase skCase) {
		this.db = skCase;
	}

	/**
	 * Gets or creates a OS user account with given unique id or given user name
	 * for the given data source.
	 *
	 * @param uniqueAccountId User sid/uid.
	 * @param loginName       User login name.
	 * @param realmName       Realm within which the accountId/userName is
	 *                        unique.
	 * @param host			  Host for the realm, may be null.
	 * @param transaction     Transaction to use for database operation.
	 *
	 * @return Row id of the row matching the given user id and data source.
	 */
	OsAccount getOrCreateOsAccount(String uniqueAccountId, String loginName, String realmName, Host host, CaseDbTransaction transaction) throws TskCoreException {

		// ensure at least one of the two is supplied - unique id or a login name
		if (Strings.isNullOrEmpty(uniqueAccountId) && Strings.isNullOrEmpty(loginName)) {
			throw new IllegalArgumentException("Cannot create OS User with both uniqueId and loginName as null.");
		}

		CaseDbConnection connection = transaction.getConnection();

		OsAccount osAccount = null;
		// First search for user by uniqueId
		if (!Strings.isNullOrEmpty(uniqueAccountId)) {
			osAccount = getOsAccountByUniqueId(uniqueAccountId, host, connection);
			if (osAccount != null) {
				return osAccount;
			}
		}

		// get/create the realm with given name
		OsAccountRealm realm = null;
		if (Strings.isNullOrEmpty(realmName) == false) {
			realm = db.getOsAccountRealmManager().getOrCreateRealmByName(realmName, host, transaction);
		}
			
		// search by loginName
		if (!Strings.isNullOrEmpty(loginName)) {
			osAccount = getOsAccountByLoginName(loginName, realm, connection);
			if (osAccount != null) {
				return osAccount;
			}
		}

		// couldn't find it, create a new account
		return createOsAccount(uniqueAccountId, loginName, realm, connection);

	}

	/**
	 * Creates a user with the given uid, name, and realm.
	 *
	 * @param uniqueId     User sid/uid. May be null/empty.
	 * @param loginName    User name. may be null or empty.
	 * @param realm	       Realm. May be null.
	 * @param connection   Database connection to use.
	 *
	 * @return OS account.
	 *
	 * @throws TskCoreException
	 */
	private OsAccount createOsAccount(String uniqueId, String loginName, OsAccountRealm realm, CaseDbConnection connection) throws TskCoreException {

		String signature;
		if (Strings.isNullOrEmpty(uniqueId) == false) {
			signature = uniqueId;
		} else {
			if (Objects.isNull(realm)) {
				signature = loginName;
			} else {
				signature = String.format("%s/%s", realm.getName(), loginName);
			}
		}

		db.acquireSingleUserCaseWriteLock();
		try {
			
			// first create a tsk_object for the OsAccount.
			
			// RAMAN TBD: need to get the correct parnt obj id.  
			//            Create an Object Directory parent and used its id.
			// RAMAN TBD: what is the object type ??
			
			long parentObjId = 1;
			int objTypeId = TskData.ObjectType.ARTIFACT.getObjectType();
			
			long osAccountObjId = db.addObject(parentObjId, objTypeId, connection);
			
			String userInsertSQL = "INSERT INTO tsk_os_accounts(os_account_obj_id, login_name, realm_id, unique_id, signature)"
					+ " VALUES (?, ?, ?, ?, ?)"; // NON-NLS

			PreparedStatement preparedStatement = connection.getPreparedStatement(userInsertSQL, Statement.NO_GENERATED_KEYS);
			preparedStatement.clearParameters();

			preparedStatement.setLong(1, osAccountObjId);
			
			preparedStatement.setString(2, loginName);
			if (!Objects.isNull(realm)) {
				preparedStatement.setLong(3, realm.getId());
			} else {
				preparedStatement.setNull(3, java.sql.Types.BIGINT);
			}

			preparedStatement.setString(4, uniqueId);
			preparedStatement.setString(5, signature);

			connection.executeUpdate(preparedStatement);

			return new OsAccount(db, osAccountObjId, realm, loginName, uniqueId, signature);
			
		} catch (SQLException ex) {
			LOGGER.log(Level.SEVERE, null, ex);
			throw new TskCoreException(String.format("Error adding OS user account with uniqueId = %s, userName = %s", uniqueId, loginName), ex);
		} finally {
			db.releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Get the OsUser with the given unique user id.
	 *
	 * @param uniqueId User sid/uid.
	 * @param host     Host for account realm, may be null.
	 *
	 * @return OsUser.
	 *
	 * @throws TskCoreException         If there is an error getting the user.
	 * @throws IllegalArgumentException If no matching user is found.
	 */
	public OsAccount getOsAccount(String uniqueId, Host host) throws TskCoreException {

		try (CaseDbConnection connection = this.db.getConnection()) {

			OsAccount osAccount = getOsAccountByUniqueId(uniqueId, host, connection);
			if (osAccount == null) {
				throw new IllegalArgumentException(String.format("No user found with id %s ", uniqueId));
			}

			return osAccount;
		}
	}

	/**
	 * Gets a user by the uniqueId. Returns null if no matching user is found.
	 *
	 * @param uniqueId Account SID/uid.
	 * @param Host Host to match the realm, may be null.
	 * @param connection Database connection to use.
	 *
	 * @return OsUser, null if no user with matching uniqueId is found.
	 *
	 * @throws TskCoreException
	 */
	private OsAccount getOsAccountByUniqueId(String uniqueId, Host host, CaseDbConnection connection) throws TskCoreException {

		String whereHostClause = (host == null) 
							? " realms.host_id IS NULL " 
							: " realms.host_id = " + host.getId() + " ";
		String queryString = "SELECT accounts.os_account_obj_id as os_account_obj_id, accounts.login_name, accounts.full_name, "
								+ " accounts.realm_id, accounts.unique_id, accounts.signature, "
								+ "	accounts.type, accounts.status, accounts.admin, accounts.creation_date_time, "
								+ " realms.name as realm_name, realms.unique_id as realm_unique_id, realms.host_id, realms.name_type "
							+ " FROM tsk_os_accounts as accounts"
							+ "		LEFT JOIN tsk_os_account_realms as realms"
							+ " ON accounts.realm_id = realms.id"
							+ " WHERE " + whereHostClause
							+ "		AND LOWER(accounts.unique_id) = LOWER('" + uniqueId + "')";
		
		try (Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			if (!rs.next()) {
				return null;	// no match found
			} else {
				OsAccountRealm realm = null;
				long realmId = rs.getLong("realm_id");
				if (!rs.wasNull()) {
					realm = new OsAccountRealm(realmId, rs.getString("realm_name"), 
									OsAccountRealm.RealmNameType.fromID(rs.getInt("name_type")), 
									rs.getString("realm_unique_id"), host );
				}

				return osAccountFromResultSet(rs, realm);
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting OS user account for unique id = %s", uniqueId), ex);
		}
	}

	/**
	 * Gets a user by the realm/userName. Returns null if no matching user is
	 * found.
	 *
	 * @param loginName    User login name.
	 * @param realm	       Account Realm, may be null.
	 * @param connection   Database connection to use.
	 *
	 * @return OsUser, null if no user with matching uniqueId is found.
	 *
	 * @throws TskCoreException
	 */
	private OsAccount getOsAccountByLoginName(String loginName, OsAccountRealm realm, CaseDbConnection connection) throws TskCoreException {

		String queryString = "SELECT * FROM tsk_os_accounts"
				+ " WHERE LOWER(login_name) = LOWER('" + loginName + "')";
		
		if (realm != null) {
				queryString += " AND realm_id = " + realm.getId();
		}

		try (Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			if (!rs.next()) {
				return null;	// no match found
			} else {
				return osAccountFromResultSet(rs, realm);
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting OS user account for realm = %s and loginName = %s.", (realm != null) ? realm.getName() : "NULL", loginName), ex);
		}
	}

	/**
	 * Get the OsAccount with the given object id.
	 *
	 * @param osAccountObjId Obj id for the user account.
	 *
	 * @return OsAccount.
	 *
	 * @throws TskCoreException         If there is an error getting the user.
	 * @throws IllegalArgumentException If no matching user is found.
	 */
	public OsAccount getOsAccount(long osAccountObjId) throws TskCoreException {

		try (CaseDbConnection connection = this.db.getConnection()) {
			return getOsAccount(osAccountObjId, connection);
		}
	}
	
	/**
	 * Get the OsAccount with the given row id.
	 *
	 * @param osAccountObjId Object id for the user account.
	 * @param connection Database connection to use.
	 *
	 * @return OsAccount.
	 *
	 * @throws TskCoreException         If there is an error getting the user.
	 * @throws IllegalArgumentException If no matching user is found.
	 */
	private OsAccount getOsAccount(long osAccountObjId, CaseDbConnection connection) throws TskCoreException {

		String queryString = "SELECT * FROM tsk_os_accounts"
				+ " WHERE os_account_obj_id = " + osAccountObjId;

		try (	Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			if (!rs.next()) {
				throw new IllegalArgumentException(String.format("No user found with obj id = %d ", osAccountObjId));
			} else {
		
				OsAccountRealm realm = null;
				long realmId = rs.getLong("realm_id");

				if (!rs.wasNull()) {
					realm = db.getOsAccountRealmManager().getRealm(realmId, connection);
				}

				return osAccountFromResultSet(rs, realm);
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting OS user account ", ex);
		}
	}
	
	/**
	 * Adds a row to the tsk_os_account_instances table.
	 *
	 * @param osAccount Account.
	 * @param host     Host on which the instance is found.
	 * @param dataSourceObjId Object id of the data source where the instance is found.
	 * @param instanceType Instance type.
	 * @param connection   Database connection to use.
	 *
	 * @throws TskCoreException
	 */
	void addOsAccountInstance(OsAccount osAccount, Host host, long dataSourceObjId, OsAccount.OsAccountInstanceType instanceType, CaseDbConnection connection) throws TskCoreException {

		db.acquireSingleUserCaseWriteLock();
		try {
			String userInsertSQL = "INSERT INTO tsk_os_account_instances(os_account_obj_id, data_source_obj_id, host_id, instance_type)"
					+ " VALUES (?, ?, ?, ?)"; // NON-NLS

			PreparedStatement preparedStatement = connection.getPreparedStatement(userInsertSQL, Statement.RETURN_GENERATED_KEYS);
			preparedStatement.clearParameters();

			preparedStatement.setLong(1, osAccount.getId());
			preparedStatement.setLong(2, dataSourceObjId);
			preparedStatement.setLong(3, host.getId());
			preparedStatement.setInt(4, instanceType.getId());
			
			connection.executeUpdate(preparedStatement);
			
		} catch (SQLException ex) {
			LOGGER.log(Level.SEVERE, null, ex);
			throw new TskCoreException(String.format("Error adding os account instance for account = %s, host name = %s, data source object id = %d", osAccount.getSignature(), host.getName(), dataSourceObjId ), ex);
		} finally {
			db.releaseSingleUserCaseWriteLock();
		}
	}
	
	/**
	 * Get all accounts that had an instance on the specified host.
	 * 
	 * @param host Host for which to look accounts for.
	 * 
	 * @return Set of OsAccounts, may be empty.
	 */
	Set<OsAccount>  getAcccounts(Host host) throws TskCoreException {
	
		String queryString = "SELECT * FROM tsk_os_accounts as accounts "
				+ " JOIN tsk_os_account_instances as instances "
				+ " ON instances.os_account_obj_id = accounts.os_account_obj_id "
				+ " WHERE instances.host_id = " + host.getId();

		try (CaseDbConnection connection = this.db.getConnection();
				Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			Set<OsAccount> accounts = new HashSet<>();
			while (rs.next()) {
				OsAccountRealm realm = null;
				long realmId = rs.getLong("realm_id");
				if (!rs.wasNull()) {
					realm = db.getOsAccountRealmManager().getRealm(realmId, connection);
				}

				accounts.add(osAccountFromResultSet(rs, realm));
			} 
			return accounts;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting OS accounts for host id = %d", host.getId()), ex);
		}
	}
	
	
	/**
	 * Gets or creates an OS account with the given SID.
	 * 
	 * @param sid Account SID.
	 * @param host Host for the realm.
	 * @param transaction Transaction to use.
	 * 
	 * @return OsAccount for the user.
	 * @throws TskCoreException 
	 */
	OsAccount getOrCreateOsAccountByWindowsSID(String sid, Host host, CaseDbTransaction transaction) throws TskCoreException {

		CaseDbConnection connection = transaction.getConnection();

		// first search/create realm 
		OsAccountRealm realm = db.getOsAccountRealmManager().getOrCreateRealmByWindowsSid(sid, host, transaction);
		
		// search by SID
		OsAccount osAccount = getOsAccountByUniqueId(sid, host, connection);
		if (osAccount != null) {
			return osAccount;
		}
		
		// create an account
		osAccount = this.createOsAccount(sid, null, realm, connection);
		
		return osAccount;
	}
	
	/**
	 * Gets or creates an OS account with the given SID. If an account already
	 * exists, then it updates the domain name and/or login name if needed.
	 *
	 * @param sid         Account SID.
	 * @param loginName	  Login name.
	 * @param domainName  Domain name.
	 * @param host        Host for the realm.
	 * @param transaction Transaction to use.
	 *
	 * @return OsAccount for the user.
	 *
	 * @throws TskCoreException
	 */
	OsAccount getUpdateOrCreateOsAccountByWindowsSID(String sid, String loginName, String domainName, Host host, CaseDbTransaction transaction) throws TskCoreException {
		
		CaseDbConnection connection = transaction.getConnection();

		// first search/create realm 
		OsAccountRealm realm = db.getOsAccountRealmManager().getOrCreateRealmByWindowsSid(sid, host, transaction);
		
		// if we have the realm name, and it needs to be updated, update first.
		if (!Strings.isNullOrEmpty(domainName) && Strings.isNullOrEmpty(realm.getName())) {
			realm = db.getOsAccountRealmManager().updateRealmName(realm.getId(), domainName, OsAccountRealm.RealmNameType.EXPRESSED, transaction);
		}
		
		// search by SID
		OsAccount osAccount = getOsAccountByUniqueId(sid, host, connection);
		if (osAccount != null) {
			// if we have a new login name, then update it.
			if (!Strings.isNullOrEmpty(loginName) && !osAccount.getLoginName().isPresent()) {
				osAccount = updateOsAccountLoginName(osAccount.getId(), loginName, transaction);
			}
			return osAccount;
		}

		// create an account
		osAccount = createOsAccount(sid, null, realm, connection);
		return osAccount;	
	}
	
	/**
	 * Gets or creates an OS account with the given given login name and domain
	 * name.
	 *
	 * @param loginName   Account SID.
	 * @param domainName  Domain name.
	 * @param host        Host for the realm.
	 * @param transaction Transaction to use.
	 *
	 * @return OsAccount for the user.
	 *
	 * @throws TskCoreException
	 */
	OsAccount getOrCreateOsAccountLogin(String loginName, String domainName, Host host, CaseDbTransaction transaction) throws TskCoreException {

		CaseDbConnection connection = transaction.getConnection();

		// search/create realm 
		OsAccountRealm realm = db.getOsAccountRealmManager().getOrCreateRealmByName(domainName, host, transaction);

		OsAccount osAccount = this.getOsAccountByLoginName(loginName, realm, connection);
		if (osAccount != null) {
			return osAccount;
		}

		// not found 
		osAccount = this.createOsAccount(null, loginName, realm, connection);

		return osAccount;
	}
	
	/**
	 * Update the account users login name.
	 * 
	 * @param accountId Accoint id of the account to update.
	 * @param loginName Account user login name.
	 * @param transaction Transaction 
	 * 
	 * @return OsAccount.
	 * 
	 * @throws TskCoreException 
	 */
	private OsAccount updateOsAccountLoginName(long accountId, String loginName, CaseDbTransaction transaction) throws TskCoreException {
		
		CaseDbConnection connection = transaction.getConnection();
		
		db.acquireSingleUserCaseWriteLock();
		try {
			String updateSQL = "UPDATE tsk_os_accounts SET login_name = ? WHERE id = ?";
					
			PreparedStatement preparedStatement = connection.getPreparedStatement(updateSQL, Statement.NO_GENERATED_KEYS);
			preparedStatement.clearParameters();

			preparedStatement.setString(1, loginName);
			preparedStatement.setLong(3, accountId);
			
			connection.executeUpdate(preparedStatement);

			return getOsAccount(accountId, connection );
			
		} catch (SQLException ex) {
			LOGGER.log(Level.SEVERE, null, ex);
			throw new TskCoreException(String.format("Error updating account with login name = %s, account id = %d", loginName, accountId), ex);
		} finally {
			db.releaseSingleUserCaseWriteLock();
		}
	}
	
	
	/**
	 * Adds a rows to the tsk_os_account_attributes table for the given set of
	 * attribute.
	 *
	 * @param account	       Account for which the attributes is being added.
	 * @param accountAttribute Attribute to add.
	 *
	 * @throws TskCoreException,
	 */
	void addOsAccountAttributes(OsAccount account, Set<OsAccountAttribute> accountAttributes) throws TskCoreException {
		CaseDbConnection connection = db.getConnection();
		db.acquireSingleUserCaseWriteLock();
	
		try {
			for (OsAccountAttribute accountAttribute : accountAttributes) {

				String attributeInsertSQL = "INSERT INTO tsk_os_account_attributes(os_account_obj_id, host_id, source_obj_id, attribute_type_id, value_type, value_byte, value_text, value_int32, value_int64, value_double)"
						+ " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"; // NON-NLS

				PreparedStatement preparedStatement = connection.getPreparedStatement(attributeInsertSQL, Statement.RETURN_GENERATED_KEYS);
				preparedStatement.clearParameters();

				preparedStatement.setLong(1, account.getId());
				preparedStatement.setLong(2, accountAttribute.getHostId());
				preparedStatement.setLong(3, accountAttribute.getAttributeOwnerId());

				preparedStatement.setLong(4, accountAttribute.getAttributeType().getTypeID());
				preparedStatement.setLong(5, accountAttribute.getAttributeType().getValueType().getType());

				if (accountAttribute.getAttributeType().getValueType() == TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.BYTE) {
					preparedStatement.setBytes(6, accountAttribute.getValueBytes());
				} else {
					preparedStatement.setBytes(6, null);
				}

				if (accountAttribute.getAttributeType().getValueType() == TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING
						|| accountAttribute.getAttributeType().getValueType() == TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.JSON) {
					preparedStatement.setString(7, accountAttribute.getValueString());
				} else {
					preparedStatement.setString(7, null);
				}
				if (accountAttribute.getAttributeType().getValueType() == TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER) {
					preparedStatement.setInt(8, accountAttribute.getValueInt());
				} else {
					preparedStatement.setNull(8, java.sql.Types.INTEGER);
				}

				if (accountAttribute.getAttributeType().getValueType() == TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME
						|| accountAttribute.getAttributeType().getValueType() == TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG) {
					preparedStatement.setLong(9, accountAttribute.getValueLong());
				} else {
					preparedStatement.setNull(9, java.sql.Types.BIGINT);
				}

				if (accountAttribute.getAttributeType().getValueType() == TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE) {
					preparedStatement.setDouble(10, accountAttribute.getValueDouble());
				} else {
					preparedStatement.setNull(10, java.sql.Types.DOUBLE);
				}

				connection.executeUpdate(preparedStatement);
			
			}
		} catch (SQLException ex) {
			LOGGER.log(Level.SEVERE, null, ex);
			throw new TskCoreException(String.format("Error adding OS Account attribute for account id = %d", account.getId()), ex);
		} 
		
		finally {
			db.releaseSingleUserCaseWriteLock();
		}

	}
	
	/**
	 * Takes in a result with a row from tsk_os_accounts table and creates 
	 * an OsAccount.
	 * 
	 * @param rs ResultSet.
	 * @param realm Realm.
	 * @return OsAccount OS Account.
	 * 
	 * @throws SQLException 
	 */
	private OsAccount osAccountFromResultSet(ResultSet rs, OsAccountRealm realm) throws SQLException {
		
		OsAccount osAccount = new OsAccount(db, rs.getLong("os_account_obj_id"), realm, rs.getString("login_name"), rs.getString("unique_id"), rs.getString("signature"));
		
		// set other optional fields
		int status = rs.getInt("status");
		if (!rs.wasNull()) {
			osAccount.setOsAccountStatus(OsAccount.OsAccountStatus.fromID(status));
		}
		
		int admin = rs.getInt("admin");
		osAccount.setIsAdmin(admin != 0);
		
		int type = rs.getInt("type");
		if (!rs.wasNull()) {
			osAccount.setOsAccountType(OsAccount.OsAccountType.fromID(type));
		}
		
		long creationTime = rs.getLong("creation_date_time");
		if (!rs.wasNull()) {
			osAccount.setCreationTime(creationTime);
		}

		return osAccount;
	}
}
