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
import org.apache.commons.lang3.StringUtils;
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
import java.util.UUID;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.stream.Collectors;
import org.sleuthkit.datamodel.BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE;
import org.sleuthkit.datamodel.OsAccount.OsAccountStatus;
import org.sleuthkit.datamodel.OsAccount.OsAccountType;
import org.sleuthkit.datamodel.OsAccount.OsAccountAttribute;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbConnection;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbTransaction;
import org.sleuthkit.datamodel.TskEvent.OsAccountsChangedTskEvent;

/**
 * Responsible for creating/updating/retrieving the OS accounts for files and
 * artifacts.
 *
 */
public final class OsAccountManager {

	private final SleuthkitCase db;

	private final NavigableSet<OsAccountInstance> osAccountInstanceCache = new ConcurrentSkipListSet<>();

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
	 * Creates an OS account with given unique id and given realm id. If an
	 * account already exists with the given id, then the existing OS account is
	 * returned.
	 *
	 * @param uniqueAccountId Account sid/uid.
	 * @param realm           Account realm.
	 *
	 * @return OsAccount.
	 *
	 * @throws TskCoreException If there is an error in creating the OSAccount.
	 *
	 */
	OsAccount newOsAccount(String uniqueAccountId, OsAccountRealm realm) throws TskCoreException {

		// ensure unique id is provided
		if (Strings.isNullOrEmpty(uniqueAccountId)) {
			throw new TskCoreException("Cannot create OS account with null uniqueId.");
		}

		if (realm == null) {
			throw new TskCoreException("Cannot create OS account without a realm.");
		}

		CaseDbTransaction trans = db.beginTransaction();
		try {

			// try to create account
			try {
				OsAccount account = newOsAccount(uniqueAccountId, null, realm, OsAccount.OsAccountStatus.UNKNOWN, trans);
				trans.commit();
				trans = null;
				return account;
			} catch (SQLException ex) {
				// Close the transaction before moving on
				trans.rollback();
				trans = null;

				// Create may fail if an OsAccount already exists. 
				Optional<OsAccount> osAccount = this.getOsAccountByAddr(uniqueAccountId, realm);
				if (osAccount.isPresent()) {
					return osAccount.get();
				}

				// create failed for some other reason, throw an exception
				throw new TskCoreException(String.format("Error creating OsAccount with uniqueAccountId = %s in realm id = %d", uniqueAccountId, realm.getRealmId()), ex);
			}
		} finally {
			if (trans != null) {
				trans.rollback();
			}
		}
	}

	/**
	 * Creates an OS account with Windows-specific data. If an account already
	 * exists with the given id or realm/login, then the existing OS account is
	 * returned.
	 *
	 * If the account realm already exists, but is missing the address or the
	 * realm name, the realm is updated.
	 *
	 * @param sid           Account sid/uid, can be null if loginName is
	 *                      supplied.
	 * @param loginName     Login name, can be null if sid is supplied.
	 * @param realmName     Realm within which the accountId or login name is
	 *                      unique. Can be null if sid is supplied.
	 * @param referringHost Host referring the account.
	 * @param realmScope    Realm scope.
	 *
	 * @return OsAccount.
	 *
	 * @throws TskCoreException                     If there is an error in
	 *                                              creating the OSAccount.
	 * @throws OsAccountManager.NotUserSIDException If the given SID is not a
	 *                                              user SID.
	 *
	 */
	public OsAccount newWindowsOsAccount(String sid, String loginName, String realmName, Host referringHost, OsAccountRealm.RealmScope realmScope) throws TskCoreException, NotUserSIDException {

		if (realmScope == null) {
			throw new TskCoreException("RealmScope cannot be null. Use UNKNOWN if scope is not known.");
		}
		if (referringHost == null) {
			throw new TskCoreException("A referring host is required to create an account.");
		}

		// ensure at least one of the two is supplied - unique id or a login name
		if (StringUtils.isBlank(sid) && StringUtils.isBlank(loginName)) {
			throw new TskCoreException("Cannot create OS account with both uniqueId and loginName as null.");
		}
		// Realm name is required if the sid is null. 
		if (StringUtils.isBlank(sid) && StringUtils.isBlank(realmName)) {
			throw new TskCoreException("Realm name or SID is required to create a Windows account.");
		}

		if (!StringUtils.isBlank(sid) && !WindowsAccountUtils.isWindowsUserSid(sid)) {
			throw new OsAccountManager.NotUserSIDException(String.format("SID = %s is not a user SID.", sid));
		}
		
		// get the realm for the account, and update it if it is missing addr or name.
		Optional<OsAccountRealm> realmOptional;
		try (CaseDbConnection connection = db.getConnection()) {
			realmOptional = db.getOsAccountRealmManager().getAndUpdateWindowsRealm(sid, realmName, referringHost, connection);
		}
		OsAccountRealm realm;
		if (realmOptional.isPresent()) {
			realm = realmOptional.get();
		} else {
			// realm was not found, create it.
			realm = db.getOsAccountRealmManager().newWindowsRealm(sid, realmName, referringHost, realmScope);
		}

		CaseDbTransaction trans = db.beginTransaction();
		try {
			// try to create account
			try {
				OsAccount account = newOsAccount(sid, loginName, realm, OsAccount.OsAccountStatus.UNKNOWN, trans);
				trans.commit();
				trans = null;
				return account;
			} catch (SQLException ex) {
				// Rollback the transaction before proceeding
				trans.rollback();
				trans = null;

				// Create may fail if an OsAccount already exists. 
				Optional<OsAccount> osAccount;

				// First search for account by uniqueId
				if (!Strings.isNullOrEmpty(sid)) {
					osAccount = getOsAccountByAddr(sid, realm);
					if (osAccount.isPresent()) {
						return osAccount.get();
					}
				}

				// search by loginName
				if (!Strings.isNullOrEmpty(loginName)) {
					osAccount = getOsAccountByLoginName(loginName, realm);
					if (osAccount.isPresent()) {
						return osAccount.get();
					}
				}

				// create failed for some other reason, throw an exception
				throw new TskCoreException(String.format("Error creating OsAccount with sid = %s, loginName = %s, realm = %s, referring host = %d",
						(sid != null) ? sid : "Null", (loginName != null) ? loginName : "Null",
						(realmName != null) ? realmName : "Null", referringHost), ex);

			}
		} finally {
			if (trans != null) {
				trans.rollback();
			}
		}
	}

	/**
	 * Creates a OS account with the given uid, name, and realm.
	 *
	 * @param uniqueId      Account sid/uid. May be null.
	 * @param loginName     Login name. May be null only if SID is not null.
	 * @param realm	        Realm.
	 * @param accountStatus Account status.
	 * @param trans         Open transaction to use.
	 *
	 * @return OS account.
	 *
	 * @throws TskCoreException If there is an error creating the account.
	 */
	private OsAccount newOsAccount(String uniqueId, String loginName, OsAccountRealm realm, OsAccount.OsAccountStatus accountStatus, CaseDbTransaction trans) throws TskCoreException, SQLException {

		if (Objects.isNull(realm)) {
			throw new TskCoreException("Cannot create an OS Account, realm is NULL.");
		}

		String signature = getOsAccountSignature(uniqueId, loginName);
		OsAccount account;
		db.acquireSingleUserCaseWriteLock();
		try {
			CaseDbConnection connection = trans.getConnection();

			// first create a tsk_object for the OsAccount.
			// RAMAN TODO: need to get the correct parent obj id.  
			//            Create an Object Directory parent and used its id.
			long parentObjId = 0;

			int objTypeId = TskData.ObjectType.OS_ACCOUNT.getObjectType();
			long osAccountObjId = db.addObject(parentObjId, objTypeId, connection);

			String accountInsertSQL = "INSERT INTO tsk_os_accounts(os_account_obj_id, login_name, realm_id, addr, signature, status)"
					+ " VALUES (?, ?, ?, ?, ?, ?)"; // NON-NLS

			PreparedStatement preparedStatement = connection.getPreparedStatement(accountInsertSQL, Statement.NO_GENERATED_KEYS);
			preparedStatement.clearParameters();

			preparedStatement.setLong(1, osAccountObjId);

			preparedStatement.setString(2, loginName);
			preparedStatement.setLong(3, realm.getRealmId());

			preparedStatement.setString(4, uniqueId);
			preparedStatement.setString(5, signature);
			preparedStatement.setInt(6, accountStatus.getId());

			connection.executeUpdate(preparedStatement);
			
			account = new OsAccount(db, osAccountObjId, realm.getRealmId(), loginName, uniqueId, signature, 
										null, null, null, accountStatus, OsAccount.OsAccountDbStatus.ACTIVE);
		} finally {
			db.releaseSingleUserCaseWriteLock();
		}
		trans.registerAddedOsAccount(account);
		return account;
	}

	/**
	 * Get the OS account with the given unique id.
	 *
	 * @param addr Account sid/uid.
	 * @param host Host for account realm, may be null.
	 *
	 * @return Optional with OsAccount, Optional.empty if no matching account is
	 *         found.
	 *
	 * @throws TskCoreException If there is an error getting the account.
	 */
	private Optional<OsAccount> getOsAccountByAddr(String addr, Host host) throws TskCoreException {

		try (CaseDbConnection connection = db.getConnection()) {
			return getOsAccountByAddr(addr, host, connection);
		}
	}

	/**
	 * Gets the OS account for the given unique id.
	 *
	 * @param uniqueId   Account SID/uid.
	 * @param host       Host to match the realm, may be null.
	 * @param connection Database connection to use.
	 *
	 * @return Optional with OsAccount, Optional.empty if no account with
	 *         matching uniqueId is found.
	 *
	 * @throws TskCoreException
	 */
	private Optional<OsAccount> getOsAccountByAddr(String uniqueId, Host host, CaseDbConnection connection) throws TskCoreException {

		String whereHostClause = (host == null)
				? " 1 = 1 "
				: " ( realms.scope_host_id = " + host.getHostId() + " OR realms.scope_host_id IS NULL) ";

		String queryString = "SELECT accounts.os_account_obj_id as os_account_obj_id, accounts.login_name, accounts.full_name, "
				+ " accounts.realm_id, accounts.addr, accounts.signature, "
				+ "	accounts.type, accounts.status, accounts.admin, accounts.created_date, accounts.db_status, "
				+ " realms.realm_name as realm_name, realms.realm_addr as realm_addr, realms.realm_signature, realms.scope_host_id, realms.scope_confidence, realms.db_status as realm_db_status "
				+ " FROM tsk_os_accounts as accounts"
				+ "		LEFT JOIN tsk_os_account_realms as realms"
				+ " ON accounts.realm_id = realms.id"
				+ " WHERE " + whereHostClause
				+ "     AND accounts.db_status = " + OsAccount.OsAccountDbStatus.ACTIVE.getId()
				+ "		AND LOWER(accounts.addr) = LOWER('" + uniqueId + "')";

		db.acquireSingleUserCaseReadLock();
		try (Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			if (!rs.next()) {
				return Optional.empty();	// no match found
			} else {
				return Optional.of(osAccountFromResultSet(rs));
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting OS account for unique id = %s and host = %s", uniqueId, (host != null ? host.getName() : "null")), ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Gets an active OS Account by the realm and unique id.
	 *
	 * @param uniqueId Account unique id.
	 * @param realm    Account realm.
	 *
	 * @return Optional with OsAccount, Optional.empty, if no user is found with
	 *         matching realm and unique id.
	 *
	 * @throws TskCoreException
	 */
	Optional<OsAccount> getOsAccountByAddr(String uniqueId, OsAccountRealm realm) throws TskCoreException {

		String queryString = "SELECT * FROM tsk_os_accounts"
				+ " WHERE LOWER(addr) = LOWER('" + uniqueId + "')"
				+ " AND db_status = " + OsAccount.OsAccountDbStatus.ACTIVE.getId()
				+ " AND realm_id = " + realm.getRealmId();

		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = this.db.getConnection();
				Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			if (!rs.next()) {
				return Optional.empty();	// no match found
			} else {
				return Optional.of(osAccountFromResultSet(rs));
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting OS account for realm = %s and uniqueId = %s.", (realm != null) ? realm.getSignature() : "NULL", uniqueId), ex);
		} finally {
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
				+ " AND db_status = " + OsAccount.OsAccountDbStatus.ACTIVE.getId()
				+ " AND realm_id = " + realm.getRealmId();

		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = this.db.getConnection();
				Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			if (!rs.next()) {
				return Optional.empty();	// no match found
			} else {
				return Optional.of(osAccountFromResultSet(rs));
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
	 * @throws TskCoreException If there is an error getting the account.
	 */
	public OsAccount getOsAccountByObjectId(long osAccountObjId) throws TskCoreException {

		try (CaseDbConnection connection = this.db.getConnection()) {
			return getOsAccountByObjectId(osAccountObjId, connection);
		}
	}

	/**
	 * Get the OsAccount with the given object id.
	 *
	 * @param osAccountObjId Object id for the account.
	 * @param connection     Database connection to use.
	 *
	 * @return OsAccount.
	 *
	 * @throws TskCoreException If there is an error getting the account.
	 */
	OsAccount getOsAccountByObjectId(long osAccountObjId, CaseDbConnection connection) throws TskCoreException {

		String queryString = "SELECT * FROM tsk_os_accounts"
				+ " WHERE os_account_obj_id = " + osAccountObjId;

		db.acquireSingleUserCaseReadLock();
		try (Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			if (!rs.next()) {
				throw new TskCoreException(String.format("No account found with obj id = %d ", osAccountObjId));
			} else {
				return osAccountFromResultSet(rs);
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting account with obj id = %d ", osAccountObjId), ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get the account instance for given account, host and data source id.
	 *
	 * @param osAccount       Account to check for.
	 * @param dataSourceObjId Data source object id.
	 * @param connection      Database connection to use.
	 *
	 * @return Optional with id of the account instance. Optional.empty() if no
	 *         matching instance is found.
	 *
	 * @throws TskCoreException
	 */
	private Optional<Long> getOsAccountInstanceId(OsAccount osAccount, DataSource dataSource, CaseDbConnection connection) throws TskCoreException {

		String queryString = "SELECT * FROM tsk_os_account_instances"
				+ " WHERE os_account_obj_id = " + osAccount.getId()
				+ " AND data_source_obj_id = " + dataSource.getId();

		db.acquireSingleUserCaseReadLock();
		try (Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			if (rs.next()) {
				return Optional.ofNullable(rs.getLong("id"));
			}
			return Optional.empty();
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting account instance with account obj id = %d, data source obj id = %d ", osAccount.getId(), dataSource.getId()), ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Records that an OsAccount was used or referenced on a given data source.
	 * This data is automatically recorded when a file or DataArtifact is
	 * created.
	 *
	 * Use this method to explicitly record the association when: - Parsing
	 * account information (such as in the registry) because the account may
	 * already exist in the database, but the account did not create any files.
	 * Therefore, no instance for it would be automatically created, even though
	 * you found data about it. - You want to associate more than one OsAccount
	 * with a DataArtifact. Call this for each OsAccount not specified in
	 * 'newDataArtifact()'.
	 *
	 * This method does nothing if the instance is already recorded.
	 *
	 * @param osAccount    Account for which an instance needs to be added.
	 * @param dataSource   Data source where the instance is found.
	 * @param instanceType Instance type.
	 *
	 * @throws TskCoreException If there is an error creating the account
	 *                          instance.
	 */
	public void newOsAccountInstance(OsAccount osAccount, DataSource dataSource, OsAccountInstance.OsAccountInstanceType instanceType) throws TskCoreException {
		if (osAccount == null) {
			throw new TskCoreException("Cannot create account instance with null account.");
		}
		if (dataSource == null) {
			throw new TskCoreException("Cannot create account instance with null data source.");
		}

		// check cache first
		OsAccountInstance accountInstance = new OsAccountInstance(osAccount, dataSource, instanceType);
		if (osAccountInstanceCache.contains(accountInstance)) {
			return;
		}

		try (CaseDbConnection connection = this.db.getConnection()) {
			newOsAccountInstance(osAccount, dataSource, instanceType, connection);
		}
	}

	/**
	 * Adds a row to the tsk_os_account_instances table. Does nothing if the
	 * instance already exists in the table.
	 *
	 * @param osAccount    Account for which an instance needs to be added.
	 * @param dataSource   Data source where the instance is found.
	 * @param instanceType Instance type.
	 * @param connection   The current database connection.
	 *
	 * @throws TskCoreException If there is an error creating the account
	 *                          instance.
	 */
	void newOsAccountInstance(OsAccount osAccount, DataSource dataSource, OsAccountInstance.OsAccountInstanceType instanceType, CaseDbConnection connection) throws TskCoreException {

		if (osAccount == null) {
			throw new TskCoreException("Cannot create account instance with null account.");
		}
		if (dataSource == null) {
			throw new TskCoreException("Cannot create account instance with null data source.");
		}

		newOsAccountInstance(osAccount, dataSource.getId(), instanceType, connection);
	}

	/**
	 * Adds a row to the tsk_os_account_instances table. Does nothing if the
	 * instance already exists in the table.
	 *
	 * @param osAccount       Account for which an instance needs to be added.
	 * @param dataSourceObjId Data source where the instance is found.
	 * @param instanceType    Instance type.
	 * @param connection      The current database connection.
	 *
	 * @throws TskCoreException If there is an error creating the account
	 *                          instance.
	 */
	void newOsAccountInstance(OsAccount osAccount, long dataSourceObjId, OsAccountInstance.OsAccountInstanceType instanceType, CaseDbConnection connection) throws TskCoreException {

		if (osAccount == null) {
			throw new TskCoreException("Cannot create account instance with null account.");
		}

		// check cache first
		OsAccountInstance accountInstance = new OsAccountInstance(osAccount, dataSourceObjId, instanceType);
		if (osAccountInstanceCache.contains(accountInstance)) {
			return;
		}

		// create the instance 
		db.acquireSingleUserCaseWriteLock();
		try {
			String accountInsertSQL = db.getInsertOrIgnoreSQL("INTO tsk_os_account_instances(os_account_obj_id, data_source_obj_id, instance_type)"
					+ " VALUES (?, ?, ?)"); // NON-NLS

			PreparedStatement preparedStatement = connection.getPreparedStatement(accountInsertSQL, Statement.RETURN_GENERATED_KEYS);
			preparedStatement.clearParameters();

			preparedStatement.setLong(1, osAccount.getId());
			preparedStatement.setLong(2, dataSourceObjId);
			preparedStatement.setInt(3, instanceType.getId());

			connection.executeUpdate(preparedStatement);

			// add to the cache.
			osAccountInstanceCache.add(accountInstance);

			// update account instances
			List<OsAccountInstance> currentInstancesList = getOsAccountInstances(osAccount, connection);
			currentInstancesList.add(accountInstance);
			osAccount.setInstancesInternal(currentInstancesList);
			
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error adding os account instance for account = %s, data source object id = %d", osAccount.getAddr().orElse(osAccount.getLoginName().orElse("UNKNOWN")), dataSourceObjId), ex);
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
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	public List<OsAccount> getOsAccounts(Host host) throws TskCoreException {

		String queryString = "SELECT * FROM tsk_os_accounts as accounts "
				+ " JOIN tsk_os_account_instances as instances "
				+ "		ON instances.os_account_obj_id = accounts.os_account_obj_id "
				+ " JOIN data_source_info as datasources "
				+ "		ON datasources.obj_id = instances.data_source_obj_id "
				+ " WHERE datasources.host_id = " + host.getHostId()
				+ " AND accounts.db_status = " + OsAccount.OsAccountDbStatus.ACTIVE.getId();

		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = this.db.getConnection();
				Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			List<OsAccount> accounts = new ArrayList<>();
			while (rs.next()) {
				accounts.add(osAccountFromResultSet(rs));
			}
			return accounts;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting OS accounts for host id = %d", host.getHostId()), ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Merge all OS accounts from sourceRealm into destRealm. After this call: -
	 * sourceRealm's accounts will have been moved or merged - References to
	 * sourceRealm accounts will be updated - sourceRealm will still exist, but
	 * will be empty
	 *
	 * @param sourceRealm The source realm.
	 * @param destRealm   The destination realm.
	 * @param trans       The current transaction.
	 *
	 * @throws TskCoreException
	 */
	void mergeOsAccountsForRealms(OsAccountRealm sourceRealm, OsAccountRealm destRealm, CaseDbTransaction trans) throws TskCoreException {
		List<OsAccount> destinationAccounts = getOsAccounts(destRealm, trans.getConnection());
		List<OsAccount> sourceAccounts = getOsAccounts(sourceRealm, trans.getConnection());

		for (OsAccount sourceAccount : sourceAccounts) {

			// First a check for the case where the source account has both the login name and unique ID set and
			// we have separate matches in the destination account for both. If we find this case, we need to first merge
			// the two accounts in the destination realm. This will ensure that all source accounts match at most one
			// destination account.
			// Note that we only merge accounts based on login name if the unique ID is empty.
			if (sourceAccount.getAddr().isPresent() && sourceAccount.getLoginName().isPresent()) {
				List<OsAccount> duplicateDestAccounts = destinationAccounts.stream()
						.filter(p -> p.getAddr().equals(sourceAccount.getAddr())
						|| (p.getLoginName().equals(sourceAccount.getLoginName()) && (!p.getAddr().isPresent())))
						.collect(Collectors.toList());
				if (duplicateDestAccounts.size() > 1) {
					OsAccount combinedDestAccount = duplicateDestAccounts.get(0);
					duplicateDestAccounts.remove(combinedDestAccount);
					for (OsAccount dupeDestAccount : duplicateDestAccounts) {
						mergeOsAccounts(dupeDestAccount, combinedDestAccount, trans);
					}
				}
			}

			// Look for matching destination account
			OsAccount matchingDestAccount = null;

			// First look for matching unique id
			if (sourceAccount.getAddr().isPresent()) {
				List<OsAccount> matchingDestAccounts = destinationAccounts.stream()
						.filter(p -> p.getAddr().equals(sourceAccount.getAddr()))
						.collect(Collectors.toList());
				if (!matchingDestAccounts.isEmpty()) {
					matchingDestAccount = matchingDestAccounts.get(0);
				}
			}

			// If a match wasn't found yet, look for a matching login name.
			// We will merge only if:
			// - We didn't already find a unique ID match
			// - The source account has no unique ID OR the destination account has no unique ID
			if (matchingDestAccount == null && sourceAccount.getLoginName().isPresent()) {
				List<OsAccount> matchingDestAccounts = destinationAccounts.stream()
						.filter(p -> (p.getLoginName().equals(sourceAccount.getLoginName())
						&& ((!sourceAccount.getAddr().isPresent()) || (!p.getAddr().isPresent()))))
						.collect(Collectors.toList());
				if (!matchingDestAccounts.isEmpty()) {
					matchingDestAccount = matchingDestAccounts.get(0);
				}
			}

			// If we found a match, merge the accounts. Otherwise simply update the realm id
			if (matchingDestAccount != null) {
				mergeOsAccounts(sourceAccount, matchingDestAccount, trans);
			} else {
				String query = "UPDATE tsk_os_accounts SET realm_id = " + destRealm.getRealmId() + " WHERE os_account_obj_id = " + sourceAccount.getId();
				try (Statement s = trans.getConnection().createStatement()) {
					s.executeUpdate(query);
				} catch (SQLException ex) {
					throw new TskCoreException("Error executing SQL update: " + query, ex);
				}
				trans.registerChangedOsAccount(sourceAccount);
			}
		}
	}

	/**
	 * Merges data between two accounts so that only one is active at the end
	 * and all references are to it. Data from the destination account will take
	 * priority. Basic operation: - Update the destination if source has names,
	 * etc. not already in the destination - Update any references to the source
	 * (such as in tsk_files) to point to destination - Mark the source as
	 * "MERGED" and it will not come back in future queries.
	 *
	 * @param sourceAccount The source account.
	 * @param destAccount   The destination account.
	 * @param trans         The current transaction.
	 *
	 * @throws TskCoreException
	 */
	private void mergeOsAccounts(OsAccount sourceAccount, OsAccount destAccount, CaseDbTransaction trans) throws TskCoreException {
	
		String query = "";
		try (Statement s = trans.getConnection().createStatement()) {

			// Update all references
			query = makeOsAccountUpdateQuery("tsk_os_account_attributes", sourceAccount, destAccount);
			s.executeUpdate(query);

			// tsk_os_account_instances has a unique constraint on os_account_obj_id, data_source_obj_id, host_id,
			// so delete any rows that would be duplicates.
			query = "DELETE FROM tsk_os_account_instances "
					+ "WHERE id IN ( "
					+ "SELECT "
					+ "  sourceAccountInstance.id "
					+ "FROM "
					+ "  tsk_os_account_instances destAccountInstance "
					+ "INNER JOIN tsk_os_account_instances sourceAccountInstance ON destAccountInstance.data_source_obj_id = sourceAccountInstance.data_source_obj_id "
					+ "WHERE destAccountInstance.os_account_obj_id = " + destAccount.getId()
					+ " AND sourceAccountInstance.os_account_obj_id = " + sourceAccount.getId() + " )";
			s.executeUpdate(query);

			query = makeOsAccountUpdateQuery("tsk_os_account_instances", sourceAccount, destAccount);
			s.executeUpdate(query);
			osAccountInstanceCache.clear();

			query = makeOsAccountUpdateQuery("tsk_files", sourceAccount, destAccount);
			s.executeUpdate(query);

			query = makeOsAccountUpdateQuery("tsk_data_artifacts", sourceAccount, destAccount);
			s.executeUpdate(query);

			// Update the source account. Make a dummy signature to prevent problems with the unique constraint.
			String mergedSignature = makeMergedOsAccountSignature();
			query = "UPDATE tsk_os_accounts SET merged_into = " + destAccount.getId()
					+ ", db_status = " + OsAccount.OsAccountDbStatus.MERGED.getId()
					+ ", signature = '" + mergedSignature + "' "
					+ " WHERE os_account_obj_id = " + sourceAccount.getId();

			s.executeUpdate(query);	
			trans.registerDeletedOsAccount(sourceAccount.getId());

			// Merge and update the destination account. Note that this must be done after updating
			// the source account to prevent conflicts when merging two accounts in the
			// same realm.
			mergeOsAccountObjectsAndUpdateDestAccount(sourceAccount, destAccount, trans);
		} catch (SQLException ex) {
			throw new TskCoreException("Error executing SQL update: " + query, ex);
		}
	}

	/**
	 * Create a random signature for accounts that have been merged.
	 *
	 * @return The random signature.
	 */
	private String makeMergedOsAccountSignature() {
		return "MERGED " + UUID.randomUUID().toString();
	}

	/**
	 * Create the query to update the os account column to the merged account.
	 *
	 * @param tableName     Name of table to update.
	 * @param sourceAccount The source account.
	 * @param destAccount   The destination account.
	 *
	 * @return The query.
	 */
	private String makeOsAccountUpdateQuery(String tableName, OsAccount sourceAccount, OsAccount destAccount) {
		return "UPDATE " + tableName + " SET os_account_obj_id = " + destAccount.getId() + " WHERE os_account_obj_id = " + sourceAccount.getId();
	}

	/**
	 * Copy all fields from sourceAccount that are not set in
	 * destAccount. 
	 * 
	 * Updates the dest account in the database.
	 *
	 * @param sourceAccount The source account.
	 * @param destAccount   The destination account.
	 * @param trans	Transaction to use for database operations.
	 * 
	 * @return OsAccount Updated account.
	 */
	private OsAccount  mergeOsAccountObjectsAndUpdateDestAccount(OsAccount sourceAccount, OsAccount destAccount, CaseDbTransaction trans) throws TskCoreException {
		
		OsAccount mergedDestAccount = destAccount;
		
		String destLoginName = null;
		String destAddr = null;
		
		
		// Copy any fields that aren't set in the destination to the value from the source account.
		if (!destAccount.getLoginName().isPresent() && sourceAccount.getLoginName().isPresent()) {
			destLoginName = sourceAccount.getLoginName().get();
		}

		if (!destAccount.getAddr().isPresent() && sourceAccount.getAddr().isPresent()) {
			destAddr = sourceAccount.getAddr().get();
		}

		// update the dest account core 
		OsAccountUpdateResult updateStatus = this.updateOsAccountCore(destAccount, destAddr, destLoginName, trans);
		
		if (updateStatus.getUpdateStatusCode() == OsAccountUpdateStatus.UPDATED && updateStatus.getUpdatedAccount().isPresent()) {
			mergedDestAccount = updateStatus.getUpdatedAccount().get();
		}
		
		String destFullName = null;
		Long destCreationTime = null;
		if (!destAccount.getFullName().isPresent() && sourceAccount.getFullName().isPresent()) {
			destFullName = sourceAccount.getFullName().get();
		}

		if (!destAccount.getCreationTime().isPresent() && sourceAccount.getCreationTime().isPresent()) {
			destCreationTime = sourceAccount.getCreationTime().get();
		}
		
		// update the dest account properties 
		updateStatus = this.updateStandardOsAccountAttributes(destAccount, destFullName, null, null, destCreationTime, trans);
		
		if (updateStatus.getUpdateStatusCode() == OsAccountUpdateStatus.UPDATED && updateStatus.getUpdatedAccount().isPresent()) {
			mergedDestAccount = updateStatus.getUpdatedAccount().get();
		}
		
		return mergedDestAccount;
	}

	/**
	 * Get all active accounts associated with the given realm.
	 *
	 * @param realm      Realm for which to look accounts for.
	 * @param connection Current database connection.
	 *
	 * @return Set of OsAccounts, may be empty.
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	private List<OsAccount> getOsAccounts(OsAccountRealm realm, CaseDbConnection connection) throws TskCoreException {
		String queryString = "SELECT * FROM tsk_os_accounts"
				+ " WHERE realm_id = " + realm.getRealmId()
				+ " AND db_status = " + OsAccount.OsAccountDbStatus.ACTIVE.getId()
				+ " ORDER BY os_account_obj_id";

		try (Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			List<OsAccount> accounts = new ArrayList<>();
			while (rs.next()) {
				accounts.add(osAccountFromResultSet(rs));
			}
			return accounts;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting OS accounts for realm id = %d", realm.getRealmId()), ex);
		}
	}

	/**
	 * Get all active accounts.
	 *
	 * @return Set of OsAccounts, may be empty.
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	public List<OsAccount> getOsAccounts() throws TskCoreException {
		String queryString = "SELECT * FROM tsk_os_accounts"
				+ " WHERE db_status = " + OsAccount.OsAccountDbStatus.ACTIVE.getId();

		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = this.db.getConnection();
				Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			List<OsAccount> accounts = new ArrayList<>();
			while (rs.next()) {
				accounts.add(osAccountFromResultSet(rs));
			}
			return accounts;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting OS accounts"), ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Gets an OS account using Windows-specific data.
	 *
	 * @param sid           Account SID, maybe null if loginName is supplied.
	 * @param loginName     Login name, maybe null if sid is supplied.
	 * @param realmName     Realm within which the accountId or login name is
	 *                      unique. Can be null if sid is supplied.
	 * @param referringHost Host referring the account.
	 *
	 * @return Optional with OsAccount, Optional.empty if no matching OsAccount
	 *         is found.
	 *
	 * @throws TskCoreException    If there is an error getting the account.
	 * @throws NotUserSIDException If the given SID is not a user SID.
	 */
	public Optional<OsAccount> getWindowsOsAccount(String sid, String loginName, String realmName, Host referringHost) throws TskCoreException, NotUserSIDException {

		if (referringHost == null) {
			throw new TskCoreException("A referring host is required to get an account.");
		}

		// ensure at least one of the two is supplied - sid or a login name
		if (StringUtils.isBlank(sid) && StringUtils.isBlank(loginName)) {
			throw new TskCoreException("Cannot get an OS account with both SID and loginName as null.");
		}

		// first get the realm for the given sid
		Optional<OsAccountRealm> realm = db.getOsAccountRealmManager().getWindowsRealm(sid, realmName, referringHost);
		if (!realm.isPresent()) {
			return Optional.empty();
		}

		// search by SID
		if (!Strings.isNullOrEmpty(sid)) {
			if (!WindowsAccountUtils.isWindowsUserSid(sid)) {
				throw new OsAccountManager.NotUserSIDException(String.format("SID = %s is not a user SID.", sid));
			}

			return this.getOsAccountByAddr(sid, realm.get());
		}

		// search by login name
		return this.getOsAccountByLoginName(loginName, realm.get());
	}



	/**
	 * Adds a rows to the tsk_os_account_attributes table for the given set of
	 * attribute.
	 *
	 * @param account           Account for which the attributes is being added.
	 * @param accountAttributes List of attributes to add.
	 *
	 * @throws TskCoreException
	 */
	public void addExtendedOsAccountAttributes(OsAccount account, List<OsAccountAttribute> accountAttributes) throws TskCoreException {
	
		synchronized (account) {  // synchronized to prevent multiple threads trying to add osAccount attributes concurrently to the same osAccount.
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
					if (accountAttribute.getSourceObjectId().isPresent()) {
						preparedStatement.setLong(3, accountAttribute.getSourceObjectId().get());
					} else {
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
			} finally {
				db.releaseSingleUserCaseWriteLock();
			}
			// set the atrribute list in account to the most current list from the database
			List<OsAccountAttribute> currentAttribsList = getOsAccountAttributes(account);
			account.setAttributesInternal(currentAttribsList);
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
				+ " hosts.id, hosts.name as host_name, hosts.db_status as host_status "
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
					host = new Host(hostId, rs.getString("host_name"), Host.HostDbStatus.fromID(rs.getInt("host_status")));
				}

				Content sourceContent = null;
				long sourceObjId = rs.getLong("source_obj_id");
				if (!rs.wasNull()) {
					sourceContent = this.db.getContentById(sourceObjId);
				}
				BlackboardAttribute.Type attributeType = db.getAttributeType(rs.getInt("attribute_type_id"));
				OsAccountAttribute attribute = account.new OsAccountAttribute(attributeType, rs.getInt("value_int32"), rs.getLong("value_int64"),
						rs.getDouble("value_double"), rs.getString("value_text"), rs.getBytes("value_byte"),
						db, account, host, sourceContent);

				attributes.add(attribute);
			}
			return attributes;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting OS account attributes for account obj id = %d", account.getId()), ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get a list of OsAccountInstances for the give OsAccount.
	 *
	 * @param account Account to retrieve instance for.
	 *
	 * @return List of OsAccountInstances, the list maybe empty if none were
	 *         found.
	 *
	 * @throws TskCoreException
	 */
	List<OsAccountInstance> getOsAccountInstances(OsAccount account) throws TskCoreException {
		try (CaseDbConnection connection = db.getConnection()) {
			return getOsAccountInstances(account, connection);
		} 
	}
	
	/**
	 * Get a list of OsAccountInstances for the give OsAccount.
	 *
	 * @param account    Account to retrieve instance for.
	 * @param connection Database connection to use.
	 *
	 * @return List of OsAccountInstances, the list maybe empty if none were
	 *         found.
	 *
	 * @throws TskCoreException
	 */
	private List<OsAccountInstance> getOsAccountInstances(OsAccount account, CaseDbConnection connection ) throws TskCoreException {
		List<OsAccountInstance> instanceList = new ArrayList<>();
		String queryString = String.format("SELECT * FROM tsk_os_account_instances WHERE os_account_obj_id = %d", account.getId());

		db.acquireSingleUserCaseReadLock();
		try ( Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			while (rs.next()) {
				long dataSourceId = rs.getLong("data_source_obj_id");
				int instanceType = rs.getInt("instance_type");

				instanceList.add(new OsAccountInstance(db, account, dataSourceId, OsAccountInstance.OsAccountInstanceType.fromID(instanceType)));
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Failed to get OsAccountInstance for OsAccount (%d)", account.getId()), ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}

		return instanceList;
	}
	
	
	/**
	 * Updates the properties of the specified account in the database.
	 *
	 * A column is updated only if a non-null value has been specified.
	 *
	 * @param osAccount     OsAccount that needs to be updated in the database.
	 * @param fullName      Full name, may be null.
	 * @param accountType   Account type, may be null
	 * @param accountStatus Account status, may be null.
	 * @param creationTime  Creation time, may be null.
	 *
	 * @return OsAccountUpdateResult Account update status, and updated account.
	 *
	 * @throws TskCoreException If there is a database error or if the updated
	 *                          information conflicts with an existing account.
	 */
	public OsAccountUpdateResult updateStandardOsAccountAttributes(OsAccount osAccount, String fullName, OsAccountType accountType, OsAccountStatus accountStatus, Long creationTime) throws TskCoreException {

		CaseDbTransaction trans = db.beginTransaction();
		try {
			OsAccountUpdateResult updateStatus = updateStandardOsAccountAttributes(osAccount, fullName, accountType, accountStatus, creationTime, trans);
			
			trans.commit();
			trans = null;
			
			return updateStatus;
		} finally {
			if (trans != null) {
				trans.rollback();
			}
		}
	}

	/**
	 * Updates the properties of the specified account in the
	 * database.
	 *
	 * A column is updated only if a non-null value has been specified.
	 *
	 * @param osAccount     OsAccount that needs to be updated in the database.
	 * @param fullName      Full name, may be null.
	 * @param accountType   Account type, may be null
	 * @param accountStatus Account status, may be null.
	 * @param creationTime  Creation time, may be null.
	 * @param trans         Transaction to use for database operation.
	 *
	 * @return OsAccountUpdateResult Account update status, and updated account.
	 *
	 * @throws TskCoreException If there is a database error or if the updated
	 *                          information conflicts with an existing account.
	 */
	OsAccountUpdateResult updateStandardOsAccountAttributes(OsAccount osAccount, String fullName, OsAccountType accountType, OsAccountStatus accountStatus, Long creationTime, CaseDbTransaction trans) throws TskCoreException {

		OsAccountUpdateStatus updateStatusCode = OsAccountUpdateStatus.NO_CHANGE;

		try {
			CaseDbConnection connection = trans.getConnection();

			if (!StringUtils.isBlank(fullName)) {
				updateAccountColumn(osAccount.getId(), "full_name", fullName, connection);
				updateStatusCode = OsAccountUpdateStatus.UPDATED;
			}

			if (Objects.nonNull(accountType)) {
				updateAccountColumn(osAccount.getId(), "type", accountType, connection);
				updateStatusCode = OsAccountUpdateStatus.UPDATED;
			}

			if (Objects.nonNull(accountStatus)) {
				updateAccountColumn(osAccount.getId(), "status", accountStatus, connection);
				updateStatusCode = OsAccountUpdateStatus.UPDATED;
			}

			if (Objects.nonNull(creationTime)) {
				updateAccountColumn(osAccount.getId(), "created_date", creationTime, connection);
				updateStatusCode = OsAccountUpdateStatus.UPDATED;
			}

			// if nothing has been changed, return
			if (updateStatusCode == OsAccountUpdateStatus.NO_CHANGE) {
				return new OsAccountUpdateResult(updateStatusCode, null);
			}

			// get the updated account from database
			OsAccount updatedAccount = getOsAccountByObjectId(osAccount.getId(), connection);

			// register the updated account with the transaction to fire off an event
			trans.registerChangedOsAccount(updatedAccount);

			return new OsAccountUpdateResult(updateStatusCode, updatedAccount);

		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error updating account with addr = %s, account id = %d", osAccount.getAddr().orElse("Unknown"), osAccount.getId()), ex);
		}
	}

	
	/**
	 * Updates specified column in the tsk_os_accounts table to the specified value.
	 * 
	 * @param <T> Type of value - must be a String, Long or an Integer. 
	 * @param accountObjId Object id of the account to be updated.
	 * @param colName Name of column o be updated.
	 * @param colValue New column value. 
	 * @param connection Database connection to use.
	 * 
	 * @throws SQLException If there is an error updating the database.
	 * @throws TskCoreException  If the value type is not handled.
	 */
	private <T> void updateAccountColumn(long accountObjId, String colName, T colValue, CaseDbConnection connection) throws SQLException, TskCoreException {

		String updateSQL = "UPDATE tsk_os_accounts "
				+ " SET " + colName + " = ? "
				+ " WHERE os_account_obj_id = ?";

		db.acquireSingleUserCaseWriteLock();
		try {
			PreparedStatement preparedStatement = connection.getPreparedStatement(updateSQL, Statement.NO_GENERATED_KEYS);
			preparedStatement.clearParameters();

			if (Objects.isNull(colValue)) {
				preparedStatement.setNull(1, Types.NULL); // handle null value
			} else {
				if (colValue instanceof String) {
					preparedStatement.setString(1, (String) colValue);
				} else if (colValue instanceof Long) {
					preparedStatement.setLong(1, (Long) colValue);
				} else if (colValue instanceof Integer) {
					preparedStatement.setInt(1, (Integer) colValue);
				} else {
					throw new TskCoreException(String.format("Unhandled column data type received while updating the account (%d) ", accountObjId));
				}
			}

			preparedStatement.setLong(2, accountObjId);

			connection.executeUpdate(preparedStatement);
		} finally {
			db.releaseSingleUserCaseWriteLock();
		}
	}
	
	/**
	 * Updates the signature of the specified account, if the db status of the
	 * account is active.
	 *
	 * @param accountObjId Object id of the account to be updated.
	 * @param signature    New signature.
	 * @param connection   Database connection to use.
	 *
	 * @throws SQLException If there is an error updating the database.
	 */
	private void updateAccountSignature(long accountObjId, String signature, CaseDbConnection connection) throws SQLException {

		String updateSQL = "UPDATE tsk_os_accounts SET "
					+ "		signature = "
					+ "       CASE WHEN db_status = " + OsAccount.OsAccountDbStatus.ACTIVE.getId() + " THEN ? ELSE signature END  "
					+ " WHERE os_account_obj_id = ?";	// 8

		PreparedStatement preparedStatement = connection.getPreparedStatement(updateSQL, Statement.NO_GENERATED_KEYS);
		preparedStatement.clearParameters();

		preparedStatement.setString(1, signature);
		preparedStatement.setLong(2, accountObjId);
		
		connection.executeUpdate(preparedStatement);
	}
	
	/**
	 * Update the address and/or login name for the specified account in the
	 * database. Also update the realm addr/name if needed.
	 * 
	 * A column is updated only if its current value is null and a
	 * non-null value has been specified.
	 *
	 *
	 * @param osAccount     OsAccount that needs to be updated in the database.
	 * @param accountSid    Account SID, may be null.
	 * @param loginName     Login name, may be null.
	 * @param realmName     Realm name for the account.
	 * @param referringHost Host.
	 *
	 * @return OsAccountUpdateResult Account update status, and the updated
         account.
	 *
	 * @throws TskCoreException If there is a database error or if the updated
	 *                          information conflicts with an existing account.
	 */
	public OsAccountUpdateResult updateCoreWindowsOsAccountAttributes(OsAccount osAccount, String accountSid, String loginName, String realmName, Host referringHost) throws TskCoreException, NotUserSIDException {
		CaseDbTransaction trans = db.beginTransaction();
		try {
			OsAccountUpdateResult updateStatus = this.updateCoreWindowsOsAccountAttributes(osAccount, accountSid, loginName, realmName, referringHost, trans);

			trans.commit();
			trans = null;
			return updateStatus;
		} finally {
			if (trans != null) {
				trans.rollback();
			}
		}
	}
	
	
	
	/**
	 * Update the address and/or login name for the specified account in the
	 * database. Also update the realm addr/name if needed.
	 *
	 * A column is updated only if it's current value is null and a non-null
	 * value has been specified.
	 *
	 * @param osAccount OsAccount that needs to be updated in the database.
	 * @param accountSid Account SID, may be null.
	 * @param loginName Login name, may be null.
	 * @param realmName Account realm name. May be null if accountSid is not null.
	 *
	 * @return OsAccountUpdateResult Account update status, and the updated
         account.
	 *
	 * @throws TskCoreException If there is a database error or if the updated
	 *                          information conflicts with an existing account.
	 */
	private OsAccountUpdateResult updateCoreWindowsOsAccountAttributes(OsAccount osAccount, String accountSid, String loginName, String realmName, Host referringHost, CaseDbTransaction trans) throws TskCoreException, NotUserSIDException {
						
		// first get and update the realm - if we have the info to find the realm
		if ( !StringUtils.isBlank(accountSid) || !StringUtils.isBlank(realmName) ) {
			db.getOsAccountRealmManager().getAndUpdateWindowsRealm(accountSid, realmName, referringHost, trans.getConnection());
		}
		
		// now update the account core data
		OsAccountUpdateResult updateStatus = this.updateOsAccountCore(osAccount, accountSid, loginName, trans);
		
		return updateStatus;
	}

	
	/**
	 * Update the address and/or login name for the specified account in the
	 * database.
	 *
	 * A column is updated only if its current value is null and a non-null
	 * value has been specified.
	 *
	 *
	 * NOTE: Will not merge accounts if the updated information conflicts with
	 * an existing account (such as adding an ID to an account that has only a
	 * name and there already being an account with that ID).
	 *
	 * @param osAccount OsAccount that needs to be updated in the database.
	 * @param address   Account address, may be null.
	 * @param loginName Login name, may be null.
	 *
	 * @return OsAccountUpdateResult Account update status, and the updated
         account.
	 *
	 * @throws TskCoreException If there is a database error or if the updated
	 *                          information conflicts with an existing account.
	 */
	private OsAccountUpdateResult updateOsAccountCore(OsAccount osAccount, String address, String loginName, CaseDbTransaction trans) throws TskCoreException {

		OsAccountUpdateStatus updateStatusCode = OsAccountUpdateStatus.NO_CHANGE;
		OsAccount updatedAccount;

		try {
			CaseDbConnection connection = trans.getConnection();

			// if a new addr is provided and the account already has an address, and they are not the same, throw an exception
			if (!StringUtils.isBlank(address) && !StringUtils.isBlank(osAccount.getAddr().orElse(null)) && !address.equalsIgnoreCase(osAccount.getAddr().orElse(""))) {
				throw new TskCoreException(String.format("Account (%d) already has an address (%s), address cannot be updated.", osAccount.getId(), osAccount.getAddr().orElse("NULL")));
			}

			// if a new login name is provided and the account already has a loginname and they are not the same, throw an exception
			if (!StringUtils.isBlank(loginName) && !StringUtils.isBlank(osAccount.getLoginName().orElse(null)) && !loginName.equalsIgnoreCase(osAccount.getLoginName().orElse(""))) {
				throw new TskCoreException(String.format("Account (%d) already has a login name (%s), login name cannot be updated.", osAccount.getId(), osAccount.getLoginName().orElse("NULL")));
			}

			if (StringUtils.isBlank(osAccount.getAddr().orElse(null)) && !StringUtils.isBlank(address)) {
				updateAccountColumn(osAccount.getId(), "addr", address, connection);
				updateStatusCode = OsAccountUpdateStatus.UPDATED;
			}

			if (StringUtils.isBlank(osAccount.getLoginName().orElse(null)) && !StringUtils.isBlank(loginName)) {
				updateAccountColumn(osAccount.getId(), "login_name", loginName, connection);
				updateStatusCode = OsAccountUpdateStatus.UPDATED;
			}

			// if nothing is changed, return
			if (updateStatusCode == OsAccountUpdateStatus.NO_CHANGE) {
				return new OsAccountUpdateResult(updateStatusCode, osAccount);
			}

			// update signature if needed, based on the most current addr/loginName
			OsAccount currAccount = getOsAccountByObjectId(osAccount.getId(), connection);
			String newAddress = currAccount.getAddr().orElse(null);
			String newLoginName = currAccount.getLoginName().orElse(null);

			String newSignature = getOsAccountSignature(newAddress, newLoginName);
			updateAccountSignature(osAccount.getId(), newSignature, connection);

			// get the updated account from database
			updatedAccount = getOsAccountByObjectId(osAccount.getId(), connection);

			// register the updated account with the transaction to fire off an event
			trans.registerChangedOsAccount(updatedAccount);

			return new OsAccountUpdateResult(updateStatusCode, updatedAccount);

		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error updating account with unique id = %s, account id = %d", osAccount.getAddr().orElse("Unknown"), osAccount.getId()), ex);
		}
	}

	/**
	 * Returns a list of hosts where the OsAccount has appeared.
	 *
	 * @param account OsAccount
	 *
	 * @return List of Hosts that reference the given OsAccount.
	 *
	 * @throws TskCoreException
	 */
	public List<Host> getHosts(OsAccount account) throws TskCoreException {
		List<Host> hostList = new ArrayList<>();

		String query = "SELECT tsk_hosts.id AS hostId, name, db_status FROM tsk_hosts "
				+ " JOIN data_source_info ON tsk_hosts.id = data_source_info.host_id"
				+ "	JOIN tsk_os_account_instances ON data_source_info.obj_id = tsk_os_account_instances.data_source_obj_id"
				+ " WHERE os_account_obj_id = " + account.getId();

		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = db.getConnection();
				Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, query)) {

			while (rs.next()) {
				hostList.add(new Host(rs.getLong("hostId"), rs.getString("name"), Host.HostDbStatus.fromID(rs.getInt("db_status"))));
			}

		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Failed to get host list for os account %d", account.getId()), ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
		return hostList;
	}

	/**
	 * Takes in a result with a row from tsk_os_accounts table and creates an
	 * OsAccount.
	 *
	 * @param rs      ResultSet.
	 * @param realmId Realm.
	 *
	 * @return OsAccount OS Account.
	 *
	 * @throws SQLException
	 */
	private OsAccount osAccountFromResultSet(ResultSet rs) throws SQLException {
		
		OsAccountType accountType = null;
		int typeId = rs.getInt("type");
		if (!rs.wasNull()) {
			accountType = OsAccount.OsAccountType.fromID(typeId);
		}

		Long creationTime = rs.getLong("created_date"); // getLong returns 0 if value is null
		if (rs.wasNull()) {
			creationTime = null;
		}

		return new OsAccount(db, rs.getLong("os_account_obj_id"), rs.getLong("realm_id"), rs.getString("login_name"), rs.getString("addr"),
						rs.getString("signature"), rs.getString("full_name"), creationTime, accountType, OsAccount.OsAccountStatus.fromID(rs.getInt("status")),
						OsAccount.OsAccountDbStatus.fromID(rs.getInt("db_status")));

	}

	/**
	 * Fires an OsAccountChangeEvent for the given OsAccount. Do not call this
	 * with an open transaction.
	 *
	 * @param account Updated account.
	 */
	private void fireChangeEvent(OsAccount account) {
		db.fireTSKEvent(new OsAccountsChangedTskEvent(Collections.singletonList(account)));
	}

	/**
	 * Created an account signature for an OS Account. This signature is simply
	 * to prevent duplicate accounts from being created. Signature is set to:
	 * uniqueId: if the account has a uniqueId, otherwise loginName: if the
	 * account has a login name.
	 *
	 * @param uniqueId  Unique id.
	 * @param loginName Login name.
	 *
	 * @return Account signature.
	 *
	 * @throws TskCoreException If there is an error creating the account
	 *                          signature.
	 */
	static String getOsAccountSignature(String uniqueId, String loginName) throws TskCoreException {
		// Create a signature. 
		String signature;
		if (Strings.isNullOrEmpty(uniqueId) == false) {
			signature = uniqueId;
		} else if (Strings.isNullOrEmpty(loginName) == false) {
			signature = loginName;
		} else {
			throw new TskCoreException("OS Account must have either a uniqueID or a login name.");
		}
		return signature;
	}

	/**
	 * Exception thrown if a given SID is a valid SID but is a group SID, and
	 * not an individual user SID.
	 */
	public static class NotUserSIDException extends TskException {

		private static final long serialVersionUID = 1L;

		/**
		 * Default constructor when error message is not available
		 */
		public NotUserSIDException() {
			super("No error message available.");
		}

		/**
		 * Create exception containing the error message
		 *
		 * @param msg the message
		 */
		public NotUserSIDException(String msg) {
			super(msg);
		}

		/**
		 * Create exception containing the error message and cause exception
		 *
		 * @param msg the message
		 * @param ex  cause exception
		 */
		public NotUserSIDException(String msg, Exception ex) {
			super(msg, ex);
		}
	}
	
	/**
	 * Status of an account update.
	 */
	public enum OsAccountUpdateStatus {

		NO_CHANGE,	/// no change was made to account.
		UPDATED,	/// account was updated
		MERGED		/// account update triggered a merge
	}
	
	/**
	 * Container that encapsulates the account update status and the updated account.
	 */
	public final static class OsAccountUpdateResult {
		
		private final OsAccountUpdateStatus updateStatus;
		private final OsAccount updatedAccount;
		
		OsAccountUpdateResult(OsAccountUpdateStatus updateStatus, OsAccount updatedAccount) {
			this.updateStatus = updateStatus;
			this.updatedAccount = updatedAccount;
		}

		public OsAccountUpdateStatus getUpdateStatusCode() {
			return updateStatus;
		}

		public Optional<OsAccount> getUpdatedAccount() {
			return Optional.ofNullable(updatedAccount);
		}
	}
}
