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
import java.util.UUID;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.stream.Collectors;
import org.sleuthkit.datamodel.BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbConnection;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbTransaction;

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
	OsAccount createOsAccount(String uniqueAccountId, OsAccountRealm realm) throws TskCoreException {

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
	 * Creates an OS account with Windows-specific data. If an account already
	 * exists with the given id or realm/login, then the existing OS account is
	 * returned.
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
	 * @param uniqueId      Account sid/uid. May be null.
	 * @param loginName     Login name. May be null only if SID is not null.
	 * @param realm	        Realm.
	 * @param accountStatus Account status.
	 * @param connection    Database connection to use.
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

			account = new OsAccount(db, osAccountObjId, realm, loginName, uniqueId, signature, accountStatus, OsAccount.OsAccountDbStatus.ACTIVE);
		}  finally {
			db.releaseSingleUserCaseWriteLock();
		}
		fireCreationEvent(account);
		return account;
	}
	
	/**
	 * Get the OS account with the given unique id.
	 *
	 * @param uniqueId Account sid/uid.
	 * @param host     Host for account realm, may be null.
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
	 * @return Optional with OsAccount, Optional.empty if no account with
	 *         matching uniqueId is found.
	 *
	 * @throws TskCoreException
	 */
	private Optional<OsAccount> getOsAccountByUniqueId(String uniqueId, Host host, CaseDbConnection connection) throws TskCoreException {

		String whereHostClause = (host == null)
				? " 1 = 1 "
				: " ( realms.scope_host_id = " + host.getId() + " OR realms.scope_host_id IS NULL) ";

		String queryString = "SELECT accounts.os_account_obj_id as os_account_obj_id, accounts.login_name, accounts.full_name, "
				+ " accounts.realm_id, accounts.unique_id, accounts.signature, "
				+ "	accounts.type, accounts.status, accounts.admin, accounts.created_date, accounts.db_status, "
				+ " realms.realm_name as realm_name, realms.realm_addr as realm_addr, realms.realm_signature, realms.scope_host_id, realms.scope_confidence, realms.db_status as realm_db_status "
				+ " FROM tsk_os_accounts as accounts"
				+ "		LEFT JOIN tsk_os_account_realms as realms"
				+ " ON accounts.realm_id = realms.id"
				+ " WHERE " + whereHostClause
				+ "     AND accounts.db_status = " + OsAccount.OsAccountDbStatus.ACTIVE.getId()
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
									host, OsAccountRealm.ScopeConfidence.fromID(rs.getInt("scope_confidence")),
									OsAccountRealm.RealmDbStatus.fromID(rs.getInt("realm_db_status")));
				}

				return Optional.of(osAccountFromResultSet(rs, realm));
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
	Optional<OsAccount> getOsAccountByUniqueId(String uniqueId, OsAccountRealm realm) throws TskCoreException {

		String queryString = "SELECT * FROM tsk_os_accounts"
				+ " WHERE LOWER(unique_id) = LOWER('" + uniqueId + "')" 
				+ " AND db_status = " + OsAccount.OsAccountDbStatus.ACTIVE.getId()
				+ " AND realm_id = " + realm.getId();

		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = this.db.getConnection();
				Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			if (!rs.next()) {
				return Optional.empty();	// no match found
			} else {
				return Optional.of(osAccountFromResultSet(rs, realm));
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
				+ " AND realm_id = " + realm.getId();

		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = this.db.getConnection();
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
	 * @throws TskCoreException         If there is an error getting the
	 *                                  account.
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
	 * @param connection     Database connection to use.
	 *
	 * @return OsAccount.
	 *
	 * @throws TskCoreException         If there is an error getting the
	 *                                  account.
	 * @throws IllegalArgumentException If no matching object id is found.
	 */
	OsAccount getOsAccount(long osAccountObjId, CaseDbConnection connection) throws TskCoreException {

		String queryString = "SELECT * FROM tsk_os_accounts"
				+ " WHERE os_account_obj_id = " + osAccountObjId;

		db.acquireSingleUserCaseReadLock();
		try (Statement s = connection.createStatement();
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
         * This data is automatically recorded when a file or DataArtifact is created.
         * 
         * Use this method to explicitly record the association when:
         * - Parsing account information (such as in the registry) because the account
         *   may already exist in the database, but the account did not create any files.
         *   Therefore, no instance for it would be automatically created, even though 
         *   you found data about it. 
         * - You want to associate more than one OsAccount with a DataArtifact.  Call 
         *   this for each OsAccount not specified in 'newDataArtifact()'. 
         * 
         * This method does nothing if the instance is already recorded. 
         *
         * @param osAccount    Account for which an instance needs to be added.
         * @param dataSource   Data source where the instance is found.
         * @param instanceType Instance type.
         *
         * @throws TskCoreException
         */
	public void createOsAccountInstance(OsAccount osAccount, DataSource dataSource, OsAccountInstance.OsAccountInstanceType instanceType) throws TskCoreException {
		if (osAccount == null) {
			throw new IllegalArgumentException("Cannot create account instance with null account.");
		}
		if (dataSource == null) {
			throw new IllegalArgumentException("Cannot create account instance with null data source.");
		}

		// check cache first
		OsAccountInstance accountInstance = new OsAccountInstance(osAccount, dataSource, instanceType);
		if (osAccountInstanceCache.contains(accountInstance)) {
			return;
		}
		
		try(CaseDbConnection connection = this.db.getConnection()) {
			createOsAccountInstance(osAccount, dataSource, instanceType, connection);		
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
	 * @throws TskCoreException
	 */
	void createOsAccountInstance(OsAccount osAccount, DataSource dataSource, OsAccountInstance.OsAccountInstanceType instanceType, CaseDbConnection connection) throws TskCoreException {
	
		
		if (osAccount == null) {
			throw new IllegalArgumentException("Cannot create account instance with null account.");
		}
		if (dataSource == null) {
			throw new IllegalArgumentException("Cannot create account instance with null data source.");
		}

		// check cache first
		OsAccountInstance accountInstance = new OsAccountInstance(osAccount, dataSource, instanceType);
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
			preparedStatement.setLong(2, dataSource.getId());
			preparedStatement.setInt(3, instanceType.getId());

			connection.executeUpdate(preparedStatement);

			// add to the cache.
			osAccountInstanceCache.add(accountInstance);

		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error adding os account instance for account = %s, data source object id = %d", osAccount.getUniqueIdWithinRealm().orElse(osAccount.getLoginName().orElse("UNKNOWN")), dataSource.getId()), ex);
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
	public List<OsAccount> getAccounts(Host host) throws TskCoreException {

		String queryString = "SELECT * FROM tsk_os_accounts as accounts "
				+ " JOIN tsk_os_account_instances as instances "
				+ "		ON instances.os_account_obj_id = accounts.os_account_obj_id "
				+ " JOIN data_source_info as datasources "
				+ "		ON datasources.obj_id = instances.data_source_obj_id "
				+ " WHERE datasources.host_id = " + host.getId()
				+ " AND accounts.db_status = " + OsAccount.OsAccountDbStatus.ACTIVE.getId();
		
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
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Merge all OS accounts from sourceRealm into destRealm. 
	 * After this call:
	 * - sourceRealm's accounts will have been moved or merged
	 * - References to sourceRealm accounts will be updated
	 * - sourceRealm will still exist, but will be empty
	 *
	 * @param sourceRealm The source realm.
	 * @param destRealm   The destination realm.
	 * @param trans  The current transaction.
	 * 
	 * @throws TskCoreException 
	 */
	void mergeAccountsForRealms(OsAccountRealm sourceRealm, OsAccountRealm destRealm, CaseDbTransaction trans) throws TskCoreException {
		List<OsAccount> destinationAccounts = getAccounts(destRealm, trans.getConnection());
		List<OsAccount> sourceAccounts = getAccounts(sourceRealm, trans.getConnection());
		
		for (OsAccount sourceAccount : sourceAccounts) {

			// First a check for the case where the source account has both the login name and unique ID set and
			// we have separate matches in the destination account for both. If we find this case, we need to first merge
			// the two accounts in the destination realm. This will ensure that all source accounts match at most one
			// destination account.
			// Note that we only merge accounts based on login name if the unique ID is empty.
			if (sourceAccount.getUniqueIdWithinRealm().isPresent() && sourceAccount.getLoginName().isPresent()) {
				List<OsAccount> duplicateDestAccounts = destinationAccounts.stream()
						.filter(p -> p.getUniqueIdWithinRealm().equals(sourceAccount.getUniqueIdWithinRealm())
								|| (p.getLoginName().equals(sourceAccount.getLoginName()) && (! p.getUniqueIdWithinRealm().isPresent())))
						.collect(Collectors.toList());
				if (duplicateDestAccounts.size() > 1) {
					OsAccount combinedDestAccount = duplicateDestAccounts.get(0);
					duplicateDestAccounts.remove(combinedDestAccount);
					for (OsAccount dupeDestAccount : duplicateDestAccounts) {
						mergeAccounts(dupeDestAccount, combinedDestAccount, trans);
					}
				}
			}
			
			// Look for matching destination account
			OsAccount matchingDestAccount = null;
			
			// First look for matching unique id
			if (sourceAccount.getUniqueIdWithinRealm().isPresent()) {
				List<OsAccount> matchingDestAccounts = destinationAccounts.stream()
						.filter(p -> p.getUniqueIdWithinRealm().equals(sourceAccount.getUniqueIdWithinRealm()))
						.collect(Collectors.toList());
				if (! matchingDestAccounts.isEmpty()) {
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
							&& ((!sourceAccount.getUniqueIdWithinRealm().isPresent()) || (!p.getUniqueIdWithinRealm().isPresent()))))
						.collect(Collectors.toList());
				if (! matchingDestAccounts.isEmpty()) {
					matchingDestAccount = matchingDestAccounts.get(0);
				}
			}
			
			// If we found a match, merge the accounts. Otherwise simply update the realm id
			if (matchingDestAccount != null) {
				mergeAccounts(sourceAccount, matchingDestAccount, trans);
			} else {
				String query = "UPDATE tsk_os_accounts SET realm_id = " + destRealm.getId() + " WHERE os_account_obj_id = " + sourceAccount.getId();
				try (Statement s = trans.getConnection().createStatement()) {
					s.executeUpdate(query);
				} catch (SQLException ex) {
					throw new TskCoreException("Error executing SQL update: " + query, ex);
				}
			}
		}
	}
	
	/**
	 * Merges data between two accounts so that only one is active at the end and all references are to it. 
	 * Data from the destination account will take priority.
	 * Basic operation:
	 * - Update the destination if source has names, etc. not already in the destination
	 * - Update any references to the source (such as in tsk_files) to point to destination
	 * - Mark the source as "MERGED" and it will not come back in future queries. 
	 * 
	 * @param sourceAccount The source account.
	 * @param destAccount   The destination account.
	 * @param trans The current transaction.
	 * 
	 * @throws TskCoreException 
	 */
	private void mergeAccounts(OsAccount sourceAccount, OsAccount destAccount, CaseDbTransaction trans) throws TskCoreException {
		// Merge data from sourceAccount into matchingDestAccount. Does not update the database.
		mergeOsAccountObjects(sourceAccount, destAccount);

		String query = "";
		try (Statement s = trans.getConnection().createStatement()) {
			
			// Update all references
			query = makeOsAccountUpdateQuery("tsk_os_account_attributes", sourceAccount, destAccount);
			s.executeUpdate(query);
			
			// tsk_os_account_instances has a unique constraint on os_account_obj_id, data_source_obj_id, host_id,
			// so delete any rows that would be duplicates.
			query = "DELETE FROM tsk_os_account_instances " +
				"WHERE id IN ( " +
				"SELECT " +
				"  sourceAccountInstance.id " +
				"FROM " +
				"  tsk_os_account_instances destAccountInstance " +
				"INNER JOIN tsk_os_account_instances sourceAccountInstance ON destAccountInstance.data_source_obj_id = sourceAccountInstance.data_source_obj_id " +
				"WHERE destAccountInstance.os_account_obj_id = " +  destAccount.getId() + 
				" AND sourceAccountInstance.os_account_obj_id = " + sourceAccount.getId() + " )";
			s.executeUpdate(query);
			
			query = makeOsAccountUpdateQuery("tsk_os_account_instances", sourceAccount, destAccount);
			s.executeUpdate(query);
			osAccountInstanceCache.clear();
			
			query = makeOsAccountUpdateQuery("tsk_files", sourceAccount, destAccount);
			s.executeUpdate(query);
			
			query = makeOsAccountUpdateQuery("tsk_data_artifacts", sourceAccount, destAccount);
			s.executeUpdate(query);
			
			// Update the source account. Make a dummy signature to prevent problems with the unique constraint.
			String mergedSignature = makeMergedAccountSignature();
			query = "UPDATE tsk_os_accounts SET merged_into = " + destAccount.getId()
					+ ", db_status = " + OsAccount.OsAccountDbStatus.MERGED.getId()
					+ ", signature = '" + mergedSignature + "' " 
					+ " WHERE os_account_obj_id = " + sourceAccount.getId();
			s.executeUpdate(query);	
			
			// Update the destination account. Note that this must be done after updating
			// the source account to prevent conflicts when merging two accounts in the
			// same realm.
			updateAccount(destAccount, trans.getConnection());
		} catch (SQLException ex) {
			throw new TskCoreException("Error executing SQL update: " + query, ex);
		}
	}
	
	/**
	 * Create a random signature for accounts that have been merged.
	 * 
	 * @return The random signature.
	 */
	private String makeMergedAccountSignature() {
		return "MERGED " +  UUID.randomUUID().toString();
	}
	
	/**
	 * Create the query to update the os account column to the merged account.
	 * 
	 * @param tableName  Name of table to update.
	 * @param sourceAccount  The source account.
	 * @param destAccount    The destination account.
	 * 
	 * @return The query.
	 */
	private String makeOsAccountUpdateQuery(String tableName, OsAccount sourceAccount, OsAccount destAccount) {
		return "UPDATE " + tableName + " SET os_account_obj_id = " + destAccount.getId() + " WHERE os_account_obj_id = " + sourceAccount.getId();
	}
	
	/**
	 * Copy all fields from sourceAccount that are not set in matchingDestAccount.
	 * Does not update the database and does not update associated Person.
	 * 
	 * @param sourceAccount  The source account.
	 * @param destAccount    The destination account.
	 */
	private void mergeOsAccountObjects(OsAccount sourceAccount, OsAccount destAccount) throws TskCoreException {
		// Copy any fields that aren't set in the destination to the value from the source account.
		if (!destAccount.getLoginName().isPresent() && sourceAccount.getLoginName().isPresent()) {
			destAccount.setLoginName(sourceAccount.getLoginName().get());
		}
		
		if (!destAccount.getUniqueIdWithinRealm().isPresent() && sourceAccount.getUniqueIdWithinRealm().isPresent()) {
			destAccount.setUniqueId(sourceAccount.getUniqueIdWithinRealm().get());
		}
		
		if (!destAccount.getFullName().isPresent() && sourceAccount.getFullName().isPresent()) {
			destAccount.setFullName(sourceAccount.getFullName().get());
		}
		
		if (!destAccount.getCreationTime().isPresent() && sourceAccount.getCreationTime().isPresent()) {
			destAccount.setCreationTime(sourceAccount.getCreationTime().get());
		}
	}
	
	/**
	 * Get all active accounts associated with the given realm.
	 * 
	 * @param realm Realm for which to look accounts for.
	 * @param connection Current database connection.
	 * 
	 * @return Set of OsAccounts, may be empty.
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	private List<OsAccount> getAccounts(OsAccountRealm realm, CaseDbConnection connection) throws TskCoreException {
		String queryString = "SELECT * FROM tsk_os_accounts"
				+ " WHERE realm_id = " + realm.getId() 
				+ " AND db_status = " + OsAccount.OsAccountDbStatus.ACTIVE.getId()
				+ " ORDER BY os_account_obj_id";

		try (Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			List<OsAccount> accounts = new ArrayList<>();
			while (rs.next()) {
				accounts.add(osAccountFromResultSet(rs, realm));
			} 
			return accounts;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting OS accounts for realm id = %d", realm.getId()), ex);
		}
	}
	
	/**
	 * Get all active accounts.
	 * 
	 * @return Set of OsAccounts, may be empty.
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	public List<OsAccount> getAccounts() throws TskCoreException{
		String queryString = "SELECT * FROM tsk_os_accounts"
				+ " WHERE db_status = " + OsAccount.OsAccountDbStatus.ACTIVE.getId();

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
	 * @param loginName Account SID.
	 * @param realmName Domain name.
	 * @param host      Host for the realm.
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
	 * @param account	         Account for which the attributes is being added.
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
				OsAccountAttribute attribute = new OsAccountAttribute(attributeType, rs.getInt("value_int32"), rs.getLong("value_int64"),
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
		List<OsAccountInstance> instanceList = new ArrayList<>();
		String queryString = String.format("SELECT * FROM tsk_os_account_instances WHERE os_account_obj_id = %d", account.getId());

		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = db.getConnection();
				Statement s = connection.createStatement();
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
	 * Updates the database for the given OsAccount.
	 *
	 * @param osAccount OsAccount that needs to be updated in the database.
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
		try (CaseDbConnection connection = db.getConnection()) {
			return updateAccount(osAccount, connection);
		} finally {
			db.releaseSingleUserCaseWriteLock();
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
	OsAccount updateAccount(OsAccount osAccount, CaseDbConnection connection) throws TskCoreException {
		
		// do nothing if the account is not dirty.
		if (!osAccount.isDirty()) {
			return osAccount;
		}
		
		try {
			String updateSQL = "UPDATE tsk_os_accounts SET "
										+ "		login_name = ?, "	// 1
										+ "		unique_id = ?, "	// 2
										+ "		signature = "	// 3
										+ "       CASE WHEN db_status = " + OsAccount.OsAccountDbStatus.ACTIVE.getId() + " THEN ? ELSE signature END , "
										+ "		full_name = ?, "	// 4
										+ "		status = ?, "		// 5
										+ "		type = ?, "			// 6
										+ "		created_date = ? "	// 7
								+ " WHERE os_account_obj_id = ?";	// 8
			
			PreparedStatement preparedStatement = connection.getPreparedStatement(updateSQL, Statement.NO_GENERATED_KEYS);
			preparedStatement.clearParameters();

			preparedStatement.setString(1, osAccount.getLoginName().orElse(null));
			preparedStatement.setString(2, osAccount.getUniqueIdWithinRealm().orElse(null));
			
			// If the account is merged or deleted this will not be set.
			preparedStatement.setString(3, osAccount.getSignature());

			preparedStatement.setString(4, osAccount.getFullName().orElse(null));

			preparedStatement.setInt(5, osAccount.getOsAccountStatus().getId());
			preparedStatement.setInt(6, osAccount.getOsAccountType().getId());
			Optional<Long> creationTime = osAccount.getCreationTime();
			if(creationTime.isPresent()) {
				preparedStatement.setLong(7, osAccount.getCreationTime().get());
			} else {
				preparedStatement.setNull(7, Types.NULL);
			}
			preparedStatement.setLong(8, osAccount.getId());
			connection.executeUpdate(preparedStatement);

			osAccount.resetDirty();
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error updating account with unique id = %s, account id = %d", osAccount.getUniqueIdWithinRealm().orElse("Unknown"), osAccount.getId()), ex);
		}

		fireChangeEvent(osAccount);
		return osAccount;
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
	 * @param rs    ResultSet.
	 * @param realm Realm.
	 *
	 * @return OsAccount OS Account.
	 *
	 * @throws SQLException
	 */
	private OsAccount osAccountFromResultSet(ResultSet rs, OsAccountRealm realm) throws SQLException {
		OsAccount osAccount = new OsAccount(db, rs.getLong("os_account_obj_id"), realm, rs.getString("login_name"), rs.getString("unique_id"), 
				rs.getString("signature"), OsAccount.OsAccountStatus.fromID(rs.getInt("status")),
				OsAccount.OsAccountDbStatus.fromID(rs.getInt("db_status")));
		
		// set other optional fields
		String fullName = rs.getString("full_name");
		if (!rs.wasNull()) {
			osAccount.setFullName(fullName);
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
	 * uniqueId: if the account has a uniqueId, otherwise loginName: if the
	 * account has a login name.
	 *
	 * @param uniqueId  Unique id.
	 * @param loginName Login name.
	 *
	 * @return Account signature.
	 */
	static String getAccountSignature(String uniqueId, String loginName) {
		// Create a signature. 
		String signature;
		if (Strings.isNullOrEmpty(uniqueId) == false) {
			signature = uniqueId;
		} else if (Strings.isNullOrEmpty(loginName) == false) {
			signature = loginName;
		} else {
			throw new IllegalArgumentException("OS Account must have either a uniqueID or a login name.");
		}
		return signature;
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
