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

import com.google.common.base.Strings;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.util.Collections;
import java.util.ArrayList;
import java.util.List;
import java.util.NavigableSet;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentSkipListSet;
import org.sleuthkit.datamodel.BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbConnection;

/**
 * Responsible for creating/updating/retrieving the OS accounts for files
 * and artifacts.
 *
 */
public final class OsAccountManager {

	private final SleuthkitCase db;

	private final NavigableSet<OsAccountInstanceCacheKey> osAccountInstanceCache = new ConcurrentSkipListSet<>();
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
	 * Creates an OS account with given unique id and given realm id.
	 * If an account already exists with the given id, then the
	 * existing OS account is returned.
	 *
	 * @param uniqueAccountId Account sid/uid.
	 * @param realm           Account realm.
	 * 
	 * @return OsAccount.
	 *
	 * @throws TskCoreException If there is an error in creating the OSAccount.
	 *
	 */
	OsAccount createOsAccount(String uniqueAccountId,  OsAccountRealm realm) throws TskCoreException {

		// ensure unique id is provided
		if (Strings.isNullOrEmpty(uniqueAccountId)) {
			throw new IllegalArgumentException("Cannot create OS account with null uniqueId.");
		}
		
		if (realm == null) {
			throw new IllegalArgumentException("Cannot create OS account without a realm.");
		}
		
		try (CaseDbConnection connection = this.db.getConnection();) {

			// try to create account
			try {
				return createOsAccount(uniqueAccountId, null, realm, OsAccount.OsAccountStatus.UNKNOWN, connection);
			} catch (SQLException ex) {

				// Create may fail if an OsAccount already exists. 
				Optional<OsAccount> osAccount = this.getOsAccountByUniqueId(uniqueAccountId, realm);
				if (osAccount.isPresent()) {
					return osAccount.get();
				}

				// create failed for some other reason, throw an exception
				throw new TskCoreException(String.format("Error creating OsAccount with uniqueAccountId = %s in realm id = %d", uniqueAccountId, realm.getId()), ex);
			}
		} 
	}

	
	/**
	 * Creates an OS account with Windows-specific data. 
	 * If an account already exists with the given id or realm/login, then the
	 * existing OS account is returned.  
	 *
	 * @param sid           Account sid/uid, can be null if loginName is supplied. 
	 * @param loginName     Login name, can be null if sid is supplied. 
	 * @param realmName     Realm within which the accountId or login name is
	 *                      unique. Can be null if sid is supplied. 
	 * @param referringHost Host referring the account.
	 * @param realmScope    Realm scope.
	 *
	 * @return OsAccount.
	 *
	 * @throws TskCoreException If there is an error in creating the OSAccount.
	 *
	 */
	public OsAccount createWindowsAccount(String sid, String loginName, String realmName, Host referringHost, OsAccountRealm.RealmScope realmScope) throws TskCoreException {

		if (realmScope == null) {
			throw new IllegalArgumentException("RealmScope cannot be null. Use UNKNOWN if scope is not known.");
		}
		if (referringHost == null) {
			throw new IllegalArgumentException("A referring host is required to create an account.");
		}
		
		// ensure at least one of the two is supplied - unique id or a login name
		if (Strings.isNullOrEmpty(sid) && Strings.isNullOrEmpty(loginName)) {
			throw new IllegalArgumentException("Cannot create OS account with both uniqueId and loginName as null.");
		}
		// Realm name is required if the sid is null. 
		if (Strings.isNullOrEmpty(sid) && Strings.isNullOrEmpty(realmName)) {
			throw new IllegalArgumentException("Realm name or SID is required to create a Windows account.");
		}

		Optional<OsAccountRealm> realm = Optional.empty();
		try (CaseDbConnection connection = this.db.getConnection();) {

			// get the realm with given name
			realm = db.getOsAccountRealmManager().getWindowsRealm(sid, realmName, referringHost, connection);
			if (!realm.isPresent()) {
				// realm was not found, create it.
				realm = Optional.of(db.getOsAccountRealmManager().createWindowsRealm(sid, realmName, referringHost, realmScope));
			}
		
			// try to create account
			try {
				return createOsAccount(sid, loginName, realm.get(), OsAccount.OsAccountStatus.UNKNOWN, connection);
			} catch (SQLException ex) {

				// Create may fail if an OsAccount already exists. 
				Optional<OsAccount> osAccount;

				// First search for account by uniqueId
				if (!Strings.isNullOrEmpty(sid)) {
					osAccount = getOsAccountByUniqueId(sid, realm.get());
					if (osAccount.isPresent()) {
						return osAccount.get();
					}
				}

				// search by loginName
				if (!Strings.isNullOrEmpty(loginName)) {
					osAccount = getOsAccountByLoginName(loginName, realm.get());
					if (osAccount.isPresent()) {
						return osAccount.get();
					}
				}

				// create failed for some other reason, throw an exception
				throw new TskCoreException(String.format("Error creating OsAccount with sid = %s, loginName = %s, realm = %s, referring host = %d", 
															(sid != null) ? sid : "Null", (loginName != null) ? loginName : "Null", 
															(realmName != null) ? realmName : "Null", referringHost), ex);

			}
		} 
	}

	/**
	 * Creates a OS account with the given uid, name, and realm.
	 *
	 * @param uniqueId     Account sid/uid. May be null.
	 * @param loginName    Login name. May be null only if SID is not null.
	 * @param realm	       Realm.
	 * @param accountStatus Account status.
	 * @param connection   Database connection to use.
	 *
	 * @return OS account.
	 *
	 * @throws TskCoreException
	 */
	private OsAccount createOsAccount(String uniqueId, String loginName, OsAccountRealm realm, OsAccount.OsAccountStatus accountStatus, CaseDbConnection connection) throws TskCoreException, SQLException {

		if (Objects.isNull(realm)) {
			throw new IllegalArgumentException("Cannot create an OS Account, realm is NULL.");
		}
		
		String signature = getAccountSignature(uniqueId, loginName);
		OsAccount account;
		db.acquireSingleUserCaseWriteLock();
		try {
			
			// first create a tsk_object for the OsAccount.
			
			// RAMAN TODO: need to get the correct parent obj id.  
			//            Create an Object Directory parent and used its id.
			long parentObjId = 0;
			
			int objTypeId = TskData.ObjectType.OS_ACCOUNT.getObjectType();
			long osAccountObjId = db.addObject(parentObjId, objTypeId, connection);
			
			String accountInsertSQL = "INSERT INTO tsk_os_accounts(os_account_obj_id, login_name, realm_id, unique_id, signature, status)"
					+ " VALUES (?, ?, ?, ?, ?, ?)"; // NON-NLS

			PreparedStatement preparedStatement = connection.getPreparedStatement(accountInsertSQL, Statement.NO_GENERATED_KEYS);
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
			preparedStatement.setInt(6, accountStatus.getId());	

			connection.executeUpdate(preparedStatement);

			account = new OsAccount(db, osAccountObjId, realm, loginName, uniqueId, signature, accountStatus );
		}  finally {
			db.releaseSingleUserCaseWriteLock();
		}
		fireCreationEvent(account);
		return account;
	}

	/**
	 * Get the OS account with the given unique id.
	 *
	 * @param uniqueId    Account sid/uid.
	 * @param host        Host for account realm, may be null.
	 *
	 * @return Optional with OsAccount, Optional.empty if no matching account is
	 *         found.
	 *
	 * @throws TskCoreException If there is an error getting the account.
	 */
	private Optional<OsAccount> getOsAccount(String uniqueId, Host host) throws TskCoreException {

		try (CaseDbConnection connection = db.getConnection()) {
			return getOsAccountByUniqueId(uniqueId, host, connection);
		}
	}

	/**
	 * Gets the OS account for the given unique id. 
	 *
	 * @param uniqueId   Account SID/uid.
	 * @param host       Host to match the realm, may be null.
	 * @param connection Database connection to use.
	 *
	 * @return Optional with OsAccount, Optional.empty if no account with matching uniqueId is found.
	 *
	 * @throws TskCoreException
	 */
	private Optional<OsAccount> getOsAccountByUniqueId(String uniqueId, Host host, CaseDbConnection connection) throws TskCoreException {

		String whereHostClause = (host == null) 
							? " 1 = 1 " 
							: " ( realms.scope_host_id = " + host.getId() + " OR realms.scope_host_id IS NULL) ";
		
		String queryString = "SELECT accounts.os_account_obj_id as os_account_obj_id, accounts.login_name, accounts.full_name, "
								+ " accounts.realm_id, accounts.unique_id, accounts.signature, "
								+ "	accounts.type, accounts.status, accounts.admin, accounts.created_date, "
								+ " realms.realm_name as realm_name, realms.realm_addr as realm_addr, realms.realm_signature, realms.scope_host_id, realms.scope_confidence "
							+ " FROM tsk_os_accounts as accounts"
							+ "		LEFT JOIN tsk_os_account_realms as realms"
							+ " ON accounts.realm_id = realms.id"
							+ " WHERE " + whereHostClause
							+ "		AND LOWER(accounts.unique_id) = LOWER('" + uniqueId + "')";
		
		db.acquireSingleUserCaseReadLock();
		try (Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			if (!rs.next()) {
				return Optional.empty();	// no match found
			} else {
				OsAccountRealm realm = null;
				long realmId = rs.getLong("realm_id");
				if (!rs.wasNull()) {
					realm = new OsAccountRealm(realmId, rs.getString("realm_name"), rs.getString("realm_addr"), rs.getString("realm_signature"),
									host, OsAccountRealm.ScopeConfidence.fromID(rs.getInt("scope_confidence")));
				}

				return Optional.of(osAccountFromResultSet(rs, realm));
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting OS account for unique id = %s and host = %s", uniqueId, (host != null ? host.getName() : "null")), ex);
		}
		finally {
			db.releaseSingleUserCaseReadLock();
		}
	}

	
	/**
	 * Gets a OS Account by the realm and unique id.
	 *
	 * @param uniqueId   Account unique id.
	 * @param realm      Account realm.
	 *
	 * @return Optional with OsAccount, Optional.empty, if no user is found with
	 *         matching realm and unique id.
	 *
	 * @throws TskCoreException
	 */
	Optional<OsAccount> getOsAccountByUniqueId(String uniqueId, OsAccountRealm realm) throws TskCoreException {

		String queryString = "SELECT * FROM tsk_os_accounts"
				+ " WHERE LOWER(unique_id) = LOWER('" + uniqueId + "')" 
				+ " AND realm_id = " + realm.getId();
		
		db.acquireSingleUserCaseReadLock();
		try (  CaseDbConnection connection = this.db.getConnection();
				Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			if (!rs.next()) {
				return Optional.empty();	// no match found
			} else {
				return Optional.of(osAccountFromResultSet(rs, realm));
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting OS account for realm = %s and uniqueId = %s.", (realm != null) ? realm.getSignature() : "NULL", uniqueId), ex);
		}
		finally {
			db.releaseSingleUserCaseReadLock();
		}
	}
	
	/**
	 * Gets a OS Account by the realm and login name.
	 *
	 * @param loginName Login name.
	 * @param realm     Account realm.
	 *
	 * @return Optional with OsAccount, Optional.empty, if no user is found with
	 *         matching realm and login name.
	 *
	 * @throws TskCoreException
	 */
	Optional<OsAccount> getOsAccountByLoginName(String loginName, OsAccountRealm realm) throws TskCoreException {

		String queryString = "SELECT * FROM tsk_os_accounts"
				+ " WHERE LOWER(login_name) = LOWER('" + loginName + "')" 
				+ " AND realm_id = " + realm.getId();
		
		db.acquireSingleUserCaseReadLock();
		try (	CaseDbConnection connection = this.db.getConnection();
				Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			if (!rs.next()) {
				return Optional.empty();	// no match found
			} else {
				return Optional.of(osAccountFromResultSet(rs, realm));
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting OS account for realm = %s and loginName = %s.", (realm != null) ? realm.getSignature() : "NULL", loginName), ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get the OS Account with the given object id.
	 *
	 * @param osAccountObjId Object id for the account.
	 *
	 * @return OsAccount.
	 *
	 * @throws TskCoreException         If there is an error getting the account.
	 * @throws IllegalArgumentException If no matching object id is found.
	 */
	public OsAccount getOsAccount(long osAccountObjId) throws TskCoreException {

		try (CaseDbConnection connection = this.db.getConnection()) {
			return getOsAccount(osAccountObjId, connection);
		}
	}
	
	/**
	 * Get the OsAccount with the given object id.
	 *
	 * @param osAccountObjId Object id for the account.
	 * @param connection Database connection to use.
	 *
	 * @return OsAccount.
	 *
	 * @throws TskCoreException         If there is an error getting the account.
	 * @throws IllegalArgumentException If no matching object id is found.
	 */
	OsAccount getOsAccount(long osAccountObjId, CaseDbConnection connection) throws TskCoreException {

		String queryString = "SELECT * FROM tsk_os_accounts"
				+ " WHERE os_account_obj_id = " + osAccountObjId;

		db.acquireSingleUserCaseReadLock();
		try (	Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			if (!rs.next()) {
				throw new IllegalArgumentException(String.format("No account found with obj id = %d ", osAccountObjId));
			} else {
		
				OsAccountRealm realm = null;
				long realmId = rs.getLong("realm_id");

				if (!rs.wasNull()) {
					realm = db.getOsAccountRealmManager().getRealm(realmId, connection);
				}

				return osAccountFromResultSet(rs, realm);
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting account with obj id = %d ", osAccountObjId), ex);
		}
		finally {
			db.releaseSingleUserCaseReadLock();
		}
	}
	
	/**
	 * Get the account instance for given account, host and data source id.
	 *
	 * @param osAccount       Account to check for.
	 * @param host            Host Host for the account instance.
	 * @param dataSourceObjId Data source object id.
	 * @param connection      Database connection to use.
	 *
	 * @return Optional with id of the account instance. Optional.empty() if no
	 *         matching instance is found.
	 *
	 * @throws TskCoreException
	 */
	private Optional<Long> getOsAccountInstanceId(OsAccount osAccount, Host host, long dataSourceObjId, CaseDbConnection connection) throws TskCoreException {

		String queryString = "SELECT * FROM tsk_os_account_instances"
				+ " WHERE os_account_obj_id = " + osAccount.getId()
				+ " AND data_source_obj_id = " + dataSourceObjId
				+ " AND host_id = " + host.getId();

		db.acquireSingleUserCaseReadLock();
		try (Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			if (rs.next()) {
				return Optional.ofNullable(rs.getLong("id"));
			}
			return Optional.empty();
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting account instance with account obj id = %d, data source obj id = %d, host  = %s ", osAccount.getId(), dataSourceObjId, host.getName()), ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}
	
	/**
	 * Adds a row to the tsk_os_account_instances table. Does nothing if the
	 * instance already exists in the table.
	 *
	 * @param osAccount    Account for which an instance needs to be added.
	 * @param host         Host on which the instance is found.
	 * @param dataSource   Data source where the instance is found.
	 * @param instanceType Instance type.
	 *
	 * @throws TskCoreException
	 */
	public void createOsAccountInstance(OsAccount osAccount, Host host, Content dataSource, OsAccount.OsAccountInstanceType instanceType) throws TskCoreException {

		if (osAccount == null) {
			throw new IllegalArgumentException("Cannot create account instance with null account.");
		}
		if (host == null) {
			throw new IllegalArgumentException("Cannot create account instance with null host.");
		}
		if (host == null) {
			throw new IllegalArgumentException("Cannot create account instance with null data source.");
		}

		// check cache first
		OsAccountInstanceCacheKey accountInstancekey = new OsAccountInstanceCacheKey(osAccount.getId(), host.getId(), dataSource.getId());
        if (osAccountInstanceCache.contains(accountInstancekey)) {
            return;
        }
			
		// create the instance 
		db.acquireSingleUserCaseWriteLock();
		CaseDbConnection connection = this.db.getConnection(); // not in try-with-resource because it's used in the catch block.
		try {
			String accountInsertSQL = "INSERT INTO tsk_os_account_instances(os_account_obj_id, data_source_obj_id, host_id, instance_type)"
					+ " VALUES (?, ?, ?, ?)"; // NON-NLS

			PreparedStatement preparedStatement = connection.getPreparedStatement(accountInsertSQL, Statement.RETURN_GENERATED_KEYS);
			preparedStatement.clearParameters();

			preparedStatement.setLong(1, osAccount.getId());
			preparedStatement.setLong(2, dataSource.getId());
			preparedStatement.setLong(3, host.getId());
			preparedStatement.setInt(4, instanceType.getId());
			
			connection.executeUpdate(preparedStatement);
			
			// add to the cache.
            osAccountInstanceCache.add(accountInstancekey);
			
		} catch (SQLException ex) {
			// Create may fail if an OsAccount instance already exists. 
			Optional<Long> instanceId = getOsAccountInstanceId(osAccount, host, dataSource.getId(), connection);
			if (instanceId.isPresent()) {
				//add to the cache.
				osAccountInstanceCache.add(accountInstancekey);
				return;
			}

			// create failed due to a real error - throw it up.
			throw new TskCoreException(String.format("Error adding os account instance for account = %s, host name = %s, data source object id = %d", osAccount.getUniqueIdWithinRealm().orElse(osAccount.getLoginName().orElse("UNKNOWN")), host.getName(), dataSource.getId()), ex);
		} finally {
			connection.close();
			db.releaseSingleUserCaseWriteLock();
		}
	}
	
	/**
	 * Get all accounts that had an instance on the specified host.
	 * 
	 * @param host Host for which to look accounts for.
	 * 
	 * @return Set of OsAccounts, may be empty.
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	public List<OsAccount> getAccounts(Host host) throws TskCoreException {
	
		String queryString = "SELECT * FROM tsk_os_accounts as accounts "
				+ " JOIN tsk_os_account_instances as instances "
				+ " ON instances.os_account_obj_id = accounts.os_account_obj_id "
				+ " WHERE instances.host_id = " + host.getId();

		
		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = this.db.getConnection();
				Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			List<OsAccount> accounts = new ArrayList<>();
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
		finally {
			db.releaseSingleUserCaseReadLock();
		}
	}
	
	/**
	 * Get all accounts.
	 * 
	 * @return Set of OsAccounts, may be empty.
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	public List<OsAccount> getAccounts() throws TskCoreException{
		String queryString = "SELECT * FROM tsk_os_accounts";

		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = this.db.getConnection();
				Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			List<OsAccount> accounts = new ArrayList<>();
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
			throw new TskCoreException(String.format("Error getting OS accounts"), ex);
		}
		finally {
			db.releaseSingleUserCaseReadLock();
		}
	}
		
	/**
	 * Gets an OS account using Windows-specific data. 
	 * 
	 * @param sid           Account SID, maybe null if loginName is supplied.
	 * @param loginName     Login name, maybe null if sid is supplied. 
	 * @param realmName     Realm within which the accountId or login name is
	 *                      unique.  Can be null if sid is supplied. 
	 * @param referringHost Host referring the account.
	 *
	 * @return Optional with OsAccount, Optional.empty if no matching OsAccount is found.
	 * 
	 * @throws TskCoreException 
	 */
	public Optional<OsAccount> getWindowsAccount(String sid, String loginName, String realmName, Host referringHost) throws TskCoreException {
		
		if (referringHost == null) {
			throw new IllegalArgumentException("A referring host is required to get an account.");
		}
		
		// ensure at least one of the two is supplied - sid or a login name
		if (Strings.isNullOrEmpty(sid) && Strings.isNullOrEmpty(loginName)) {
			throw new IllegalArgumentException("Cannot get an OS account with both SID and loginName as null.");
		}
		
		// first get the realm for the given sid
		Optional<OsAccountRealm> realm = db.getOsAccountRealmManager().getWindowsRealm(sid, realmName, referringHost);
		if (!realm.isPresent()) {	
			return Optional.empty();
		}
		
		// search by SID
		if (!Strings.isNullOrEmpty(sid)) {
			return this.getOsAccountByUniqueId(sid, realm.get());
		}

		// search by login name
		return this.getOsAccountByLoginName(loginName, realm.get());
	}
	
	/**
	 * Gets an OS account with the given login name and realm name.
	 *
	 * @param loginName   Account SID.
	 * @param realmName   Domain name.
	 * @param host        Host for the realm.
	 *
	 * @return Optional with OsAccount, Optional.empty if no matching OS account
	 *         is found.
	 *
	 * @throws TskCoreException
	 */
	private Optional<OsAccount> getOsAccountByLogin(String loginName, String realmName, Host host) throws TskCoreException {

		try (CaseDbConnection connection = db.getConnection()) {

			// first get the realm 
			Optional<OsAccountRealm> realm = db.getOsAccountRealmManager().getRealmByName(realmName, host, connection);
			if (!realm.isPresent()) {
				throw new TskCoreException(String.format("No realm found with name %s", realmName));
			}

			return getOsAccountByLoginName(loginName, realm.get());
		}
	}
		
	/**
	 * Adds a rows to the tsk_os_account_attributes table for the given set of
	 * attribute.
	 *
	 * @param account	       Account for which the attributes is being added.
	 * @param accountAttribute List of attributes to add.
	 *
	 * @throws TskCoreException,
	 */
	void addOsAccountAttributes(OsAccount account, List<OsAccountAttribute> accountAttributes) throws TskCoreException {
		
		db.acquireSingleUserCaseWriteLock();
	
		try (CaseDbConnection connection = db.getConnection()) {
			for (OsAccountAttribute accountAttribute : accountAttributes) {

				String attributeInsertSQL = "INSERT INTO tsk_os_account_attributes(os_account_obj_id, host_id, source_obj_id, attribute_type_id, value_type, value_byte, value_text, value_int32, value_int64, value_double)"
						+ " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"; // NON-NLS

				PreparedStatement preparedStatement = connection.getPreparedStatement(attributeInsertSQL, Statement.RETURN_GENERATED_KEYS);
				preparedStatement.clearParameters();

				preparedStatement.setLong(1, account.getId());
				if (accountAttribute.getHostId().isPresent()) {
					preparedStatement.setLong(2, accountAttribute.getHostId().get());
				} else {
					preparedStatement.setNull(2, java.sql.Types.NULL);
				}
				if(accountAttribute.getSourceObjectId().isPresent()) {
					preparedStatement.setLong(3, accountAttribute.getSourceObjectId().get());
				}else {
					preparedStatement.setNull(3, java.sql.Types.NULL);
				}

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
					preparedStatement.setNull(8, java.sql.Types.NULL);
				}

				if (accountAttribute.getAttributeType().getValueType() == TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME
						|| accountAttribute.getAttributeType().getValueType() == TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG) {
					preparedStatement.setLong(9, accountAttribute.getValueLong());
				} else {
					preparedStatement.setNull(9, java.sql.Types.NULL);
				}

				if (accountAttribute.getAttributeType().getValueType() == TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE) {
					preparedStatement.setDouble(10, accountAttribute.getValueDouble());
				} else {
					preparedStatement.setNull(10, java.sql.Types.NULL);
				}

				connection.executeUpdate(preparedStatement);
			
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error adding OS Account attribute for account id = %d", account.getId()), ex);
		} 
		
		finally {
			db.releaseSingleUserCaseWriteLock();
		}

		fireChangeEvent(account);
	}
	
	/**
	 * Get the OS account attributes for the given account.
	 * 
	 * @param account Account to get the attributes for.
	 * 
	 * @return List of attributes, may be an empty list.
	 * 
	 * @throws TskCoreException 
	 */
	List<OsAccountAttribute> getOsAccountAttributes(OsAccount account) throws TskCoreException {
		
		String queryString = "SELECT attributes.os_account_obj_id as os_account_obj_id, attributes.host_id as host_id, attributes.source_obj_id as source_obj_id, "
				+ " attributes.attribute_type_id as attribute_type_id,  attributes.value_type as value_type, attributes.value_byte as value_byte, "
				+ " attributes.value_text as value_text, attributes.value_int32 as value_int32, attributes.value_int64 as value_int64, attributes.value_double as value_double, "
				+ " hosts.id, hosts.name as host_name, hosts.status as host_status "
				+ " FROM tsk_os_account_attributes as attributes"
				+ "		LEFT JOIN tsk_hosts as hosts "
				+ " ON attributes.host_id = hosts.id "
				+ " WHERE os_account_obj_id = " + account.getId();

		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = this.db.getConnection();
				Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			List<OsAccountAttribute> attributes = new ArrayList<>();
			while (rs.next()) {
				
				Host host = null;
				long hostId = rs.getLong("host_id");
				if (!rs.wasNull()) {
					host = new Host(hostId, rs.getString("host_name"), Host.HostStatus.fromID(rs.getInt("host_status")));
				}
		
				Content sourceContent = null;
				long sourceObjId = rs.getLong("source_obj_id");
				if (!rs.wasNull()) {
					sourceContent = this.db.getContentById(sourceObjId);
				}
				BlackboardAttribute.Type attributeType = db.getAttributeType(rs.getInt("attribute_type_id"));
				OsAccountAttribute attribute = new OsAccountAttribute(attributeType, rs.getInt("value_int32"), rs.getLong("value_int64"), 
														rs.getDouble("value_double"), rs.getString("value_text"), rs.getBytes("value_byte"),
														db, account, host, sourceContent );
			
				attributes.add(attribute);
			} 
			return attributes;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting OS account attributes for account obj id = %d", account.getId()), ex);
		}
		finally {
			db.releaseSingleUserCaseReadLock();
		}
	}
	
	/**
	 * Updates the database for the given OsAccount.
	 *
	 * @param osAccount   OsAccount that needs to be updated in the database.
	 *
	 * @return OsAccount Updated account.
	 *
	 * @throws TskCoreException
	 */
	public OsAccount updateAccount(OsAccount osAccount) throws TskCoreException {
		
		// do nothing if the account is not dirty.
		if (!osAccount.isDirty()) {
			return osAccount;
		}
		
		db.acquireSingleUserCaseWriteLock();
		try(CaseDbConnection connection = db.getConnection()) {
			String updateSQL = "UPDATE tsk_os_accounts SET "
										+ "		login_name = ?, "	// 1
										+ "		unique_id = ?, "	// 2
										+ "		signature = ?, "	// 3
										+ "		full_name = ?, "	// 4
										+ "		status = ?, "		// 5
										+ "		admin = ?, "		// 6
										+ "		type = ?, "			// 7
										+ "		created_date = ? "	//8
								+ " WHERE os_account_obj_id = ?";	//9
			
			PreparedStatement preparedStatement = connection.getPreparedStatement(updateSQL, Statement.NO_GENERATED_KEYS);
			preparedStatement.clearParameters();

			preparedStatement.setString(1, osAccount.getLoginName().orElse(null));
			preparedStatement.setString(2, osAccount.getUniqueIdWithinRealm().orElse(null));
			
			preparedStatement.setString(3, osAccount.getSignature());
			
			preparedStatement.setString(4, osAccount.getFullName().orElse(null));
			
			preparedStatement.setInt(5, osAccount.getOsAccountStatus().getId());
			if(osAccount.isAdmin().isPresent()) {
				preparedStatement.setInt(6, osAccount.isAdmin().get() ? 1 : 0);
			} else {
				preparedStatement.setNull(6, Types.NULL);
			}
			preparedStatement.setInt(7, osAccount.getOsAccountType().getId());

			Optional<Long> creationTime = osAccount.getCreationTime();
			if(creationTime.isPresent()) {
				preparedStatement.setLong(8, osAccount.getCreationTime().get());
			} else {
				preparedStatement.setNull(8, Types.NULL);
			}
			preparedStatement.setLong(9, osAccount.getId());
			
			connection.executeUpdate(preparedStatement);
			
			osAccount.resetDirty();
		}
		catch (SQLException ex) {
			throw new TskCoreException(String.format("Error updating account with unique id = %s, account id = %d", osAccount.getUniqueIdWithinRealm().orElse("Unknown"), osAccount.getId()), ex);
		}	finally {
			db.releaseSingleUserCaseWriteLock();
		}
		
		fireChangeEvent(osAccount);
		return osAccount;
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
		
		OsAccount osAccount = new OsAccount(db, rs.getLong("os_account_obj_id"), realm, rs.getString("login_name"), rs.getString("unique_id"), rs.getString("signature"), OsAccount.OsAccountStatus.fromID(rs.getInt("status")));
		
		// set other optional fields
		
		String fullName = rs.getString("full_name");
		if (!rs.wasNull()) {
			osAccount.setFullName(fullName);
		}

		int admin = rs.getInt("admin");
		if (!rs.wasNull()) {	
			osAccount.setIsAdmin(admin != 0);
		}
		
		int type = rs.getInt("type");
		if (!rs.wasNull()) {
			osAccount.setOsAccountType(OsAccount.OsAccountType.fromID(type));
		}
		
		long creationTime = rs.getLong("created_date");
		if (!rs.wasNull()) {
			osAccount.setCreationTime(creationTime);
		}

		return osAccount;
	}
	
	/**
	 * Fires an OsAccountAddedEvent for the given OsAccount.
	 * 
	 * @param account Newly created account. 
	 */
	private void fireCreationEvent(OsAccount account) {
		db.fireTSKEvent(new OsAccountsCreationEvent(Collections.singletonList(account)));
	}
	
	/**
	 * Fires an OsAccountChangeEvent for the given OsAccount.
	 * 
	 * @param account Updated account.
	 */
	private void fireChangeEvent(OsAccount account) {
		db.fireTSKEvent(new OsAccountsUpdateEvent(Collections.singletonList(account)));
	}
	
	/**
	 * Created an account signature for an OS Account. This signature is simply
	 * to prevent duplicate accounts from being created. Signature is set to:
	 * uniqueId: if the account has a uniqueId, otherwise
	 * loginName: if the account has a login name.
	 *
	 * @param uniqueId  Unique id.
	 * @param loginName Login name.
	 *
	 * @return Account signature.
	 */
	static String getAccountSignature(String uniqueId,  String loginName) {
		// Create a signature. 
		String signature;
		if (Strings.isNullOrEmpty(uniqueId) == false) {
			signature = uniqueId; 
		} else if (Strings.isNullOrEmpty(loginName) == false)  {
			signature = loginName; 
		} else {
			throw new IllegalArgumentException("OS Account must have either a uniqueID or a login name.");
		}
		return signature;
	}
	
	/**
	 * Key for the OS account instance cache.
	 */
	private final class OsAccountInstanceCacheKey implements Comparable<OsAccountInstanceCacheKey> {

		long accountObjId;
		long hostId;
		long datasourceObjId;

		/**
		 * Create the key into the OS Account instance cache.
		 *
		 * @param accountObjId    Account object id.
		 * @param hostId          Host id.
		 * @param datasourceObjId Data source obj id.
		 */
		OsAccountInstanceCacheKey(long accountObjId, long hostId, long datasourceObjId) {
			this.accountObjId = accountObjId;
			this.hostId = hostId;
			this.datasourceObjId = datasourceObjId;
		}

		@Override
		public int hashCode() {
			int hash = 5;
			hash = 67 * hash + (int) (this.accountObjId ^ (this.accountObjId >>> 32));
			hash = 67 * hash + (int) (this.hostId ^ (this.hostId >>> 32));
			hash = 67 * hash + (int) (this.datasourceObjId ^ (this.datasourceObjId >>> 32));
			return hash;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			final OsAccountInstanceCacheKey other = (OsAccountInstanceCacheKey) obj;
			if (this.accountObjId != other.accountObjId) {
				return false;
			}
			if (this.hostId != other.hostId) {
				return false;
			}
			if (this.datasourceObjId != other.datasourceObjId) {
				return false;
			}
			return true;
		}

		@Override
		public int compareTo(OsAccountInstanceCacheKey other) {
			
			if (this.accountObjId != other.accountObjId) {
				 return Long.compare(this.accountObjId, other.accountObjId);
			}
			if (this.hostId != other.hostId) {
				return Long.compare(this.hostId, other.hostId);
			}
			return Long.compare(this.datasourceObjId, other.datasourceObjId);
		}

	}
	
	/**
	 * Event fired by OsAccountManager to indicate that a new OsAccount was
	 * created.
	 */
	public static final class OsAccountsCreationEvent {
		private final List<OsAccount> accountList;
		
		/**
		 * Constructs a new AddedEvent
		 * 
		 * @param accountList List newly created accounts.
		 */
		OsAccountsCreationEvent(List<OsAccount> accountList) {
			this.accountList = accountList;
		}
		
		/**
		 * Returns a list of the added OsAccounts.
		 * 
		 * @return List of OsAccounts.
		 */
		public List<OsAccount> getOsAcounts() {
			return Collections.unmodifiableList(accountList);
		}
	}
	
	/**
	 * Event fired by OsAccount Manager to indicate that an OsAccount was
	 * updated.
	 */
	public static final class OsAccountsUpdateEvent {
		private final List<OsAccount> accountList;
		
		/**
		 * Constructs a new ChangeEvent
		 * 
		 * @param accountList List newly created accounts.
		 */
		OsAccountsUpdateEvent(List<OsAccount> accountList) {
			this.accountList = accountList;
		}
		
		/**
		 * Returns a list of the updated OsAccounts.
		 * 
		 * @return List of OsAccounts.
		 */
		public List<OsAccount> getOsAcounts() {
			return Collections.unmodifiableList(accountList);
		}
	}
}
