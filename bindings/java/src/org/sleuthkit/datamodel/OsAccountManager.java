/*
 * Sleuth Kit Data Model
 *
 * Copyright 2020-2022 Basis Technology Corp.
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
import java.util.NavigableMap;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.stream.Collectors;
import org.sleuthkit.datamodel.BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE;
import org.sleuthkit.datamodel.OsAccount.OsAccountStatus;
import org.sleuthkit.datamodel.OsAccount.OsAccountType;
import org.sleuthkit.datamodel.OsAccount.OsAccountAttribute;
import org.sleuthkit.datamodel.OsAccountRealmManager.OsRealmUpdateResult;
import org.sleuthkit.datamodel.OsAccountRealmManager.OsRealmUpdateStatus;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbConnection;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbTransaction;
import org.sleuthkit.datamodel.TskEvent.OsAccountsUpdatedTskEvent;
import static org.sleuthkit.datamodel.WindowsAccountUtils.isWindowsWellKnownSid;
import static org.sleuthkit.datamodel.WindowsAccountUtils.getWindowsWellKnownSidFullName;

/**
 * Responsible for creating/updating/retrieving the OS accounts for files and
 * artifacts.
 */
public final class OsAccountManager {

	private final SleuthkitCase db;
	private final Object osAcctInstancesCacheLock;
	private final NavigableMap<OsAccountInstanceKey, OsAccountInstance> osAccountInstanceCache;

	/**
	 * Construct a OsUserManager for the given SleuthkitCase.
	 *
	 * @param skCase The SleuthkitCase
	 *
	 */
	OsAccountManager(SleuthkitCase skCase) {
		db = skCase;
		osAcctInstancesCacheLock = new Object();
		osAccountInstanceCache = new ConcurrentSkipListMap<>();
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

		// ensure at least one of the two is supplied - a non-null unique id or a login name
		if ((StringUtils.isBlank(sid) || sid.equalsIgnoreCase(WindowsAccountUtils.WINDOWS_NULL_SID)) 
				&& StringUtils.isBlank(loginName)) {
			throw new TskCoreException("Cannot create OS account with both uniqueId and loginName as null.");
		}
		// Realm name is required if the sid is null. 
		if ((StringUtils.isBlank(sid) || sid.equalsIgnoreCase(WindowsAccountUtils.WINDOWS_NULL_SID)) 
				&& StringUtils.isBlank(realmName)) {
			throw new TskCoreException("Realm name or SID is required to create a Windows account.");
		}

		if (!StringUtils.isBlank(sid) && !sid.equalsIgnoreCase(WindowsAccountUtils.WINDOWS_NULL_SID) && !WindowsAccountUtils.isWindowsUserSid(sid)) {
			throw new OsAccountManager.NotUserSIDException(String.format("SID = %s is not a user SID.", sid));
		}

		// If no SID is given and the given realm/login names is a well known account, get and use the well known SID
		if (StringUtils.isBlank(sid) 
			&& !StringUtils.isBlank(loginName) && !StringUtils.isBlank(realmName) 
				&& WindowsAccountUtils.isWindowsWellKnownAccountName(loginName, realmName)) {
			sid = WindowsAccountUtils.getWindowsWellKnownAccountSid(loginName, realmName);
		}
		
		
		OsRealmUpdateResult realmUpdateResult;
		Optional<OsAccountRealm> anotherRealmWithSameName = Optional.empty();
		Optional<OsAccountRealm> anotherRealmWithSameAddr = Optional.empty();
		
		// get the realm for the account, and update it if it is missing addr or name.
		OsAccountRealm realm = null;
		try (CaseDbConnection connection = db.getConnection()) {
			realmUpdateResult = db.getOsAccountRealmManager().getAndUpdateWindowsRealm(sid, realmName, referringHost, connection);
			
			Optional<OsAccountRealm> realmOptional = realmUpdateResult.getUpdatedRealm();
			if (realmOptional.isPresent()) {
				realm = realmOptional.get();
				
				if (realmUpdateResult.getUpdateStatus() == OsRealmUpdateStatus.UPDATED) {

					// Check if update of the realm triggers a merge with any other realm, 
					// say another realm with same name but no SID, or same SID but no name
					
					//1. Check if there is any OTHER realm with the same name, same host but no addr
					anotherRealmWithSameName = db.getOsAccountRealmManager().getAnotherRealmByName(realmOptional.get(), realmName, referringHost, connection);
					
					// 2. Check if there is any OTHER realm with same addr and host, but NO name
					anotherRealmWithSameAddr = db.getOsAccountRealmManager().getAnotherRealmByAddr(realmOptional.get(), realmName, referringHost, connection);
				}
			}
		}
		
		if (null == realm) {
			// realm was not found, create it.
			realm = db.getOsAccountRealmManager().newWindowsRealm(sid, realmName, referringHost, realmScope);
		} else if (realmUpdateResult.getUpdateStatus() == OsRealmUpdateStatus.UPDATED) {
			// if the realm already existed and was updated, and there are other realms with same  name or addr that should now be merged into the updated realm
			if (anotherRealmWithSameName.isPresent() || anotherRealmWithSameAddr.isPresent()) {

				CaseDbTransaction trans = this.db.beginTransaction();
				try {
					if (anotherRealmWithSameName.isPresent()) {
						db.getOsAccountRealmManager().mergeRealms(anotherRealmWithSameName.get(), realm, trans);
					}
					if (anotherRealmWithSameAddr.isPresent()) {
						db.getOsAccountRealmManager().mergeRealms(anotherRealmWithSameAddr.get(), realm, trans);
					}

					trans.commit();
				} catch (TskCoreException ex) {
					trans.rollback();
					throw ex;	// rethrow
				}
			}
		}
		

		return newWindowsOsAccount(sid, loginName, realm);
	}

	/**
	 * Creates an OS account with Windows-specific data. If an account already
	 * exists with the given id or realm/login, then the existing OS account is
	 * returned.
	 *
	 * @param sid       Account sid/uid, can be null if loginName is supplied.
	 * @param loginName Login name, can be null if sid is supplied.
	 * @param realm     The associated realm.
	 *
	 * @return OsAccount.
	 *
	 * @throws TskCoreException                     If there is an error in
	 *                                              creating the OSAccount.
	 * @throws OsAccountManager.NotUserSIDException If the given SID is not a
	 *                                              user SID.
	 *
	 */
	public OsAccount newWindowsOsAccount(String sid, String loginName, OsAccountRealm realm) throws TskCoreException, NotUserSIDException {

		// ensure at least one of the two is supplied - a non-null unique id or a login name
		if ((StringUtils.isBlank(sid) || sid.equalsIgnoreCase(WindowsAccountUtils.WINDOWS_NULL_SID)) 
				&& StringUtils.isBlank(loginName)) {
			throw new TskCoreException("Cannot create OS account with both uniqueId and loginName as null.");
		}

		if (!StringUtils.isBlank(sid) && !sid.equalsIgnoreCase(WindowsAccountUtils.WINDOWS_NULL_SID) && !WindowsAccountUtils.isWindowsUserSid(sid)) {
			throw new OsAccountManager.NotUserSIDException(String.format("SID = %s is not a user SID.", sid));
		}

		// If the login name is well known, we use the well known english name. 
		String resolvedLoginName = WindowsAccountUtils.toWellknownEnglishLoginName(loginName);
		
		CaseDbTransaction trans = db.beginTransaction();
		try {
			// try to create account
			try {
				String uniqueId = (!StringUtils.isBlank(sid) && !sid.equalsIgnoreCase(WindowsAccountUtils.WINDOWS_NULL_SID)) ?  sid : null;
				if (!StringUtils.isBlank(sid) && !sid.equalsIgnoreCase(WindowsAccountUtils.WINDOWS_NULL_SID) && isWindowsWellKnownSid(sid)) {
					// if the SID is a Windows well known SID, then prefer to use the default well known login name
					String wellKnownLoginName = WindowsAccountUtils.getWindowsWellKnownSidLoginName(sid);
					if (!StringUtils.isEmpty(wellKnownLoginName)) {
						resolvedLoginName = wellKnownLoginName;
					}
				}
					
				OsAccount account = newOsAccount(uniqueId, resolvedLoginName, realm, OsAccount.OsAccountStatus.UNKNOWN, trans);

				// If the SID indicates a special windows account, then set its full name. 
				if (!StringUtils.isBlank(sid) && !sid.equalsIgnoreCase(WindowsAccountUtils.WINDOWS_NULL_SID) && isWindowsWellKnownSid(sid)) {
					String fullName = getWindowsWellKnownSidFullName(sid);
					if (StringUtils.isNotBlank(fullName)) {
						OsAccountUpdateResult updateResult = updateStandardOsAccountAttributes(account, fullName, null, null, null, trans);
						if (updateResult.getUpdatedAccount().isPresent()) {
							account = updateResult.getUpdatedAccount().get();
						}
					}
				}
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
				if (!Strings.isNullOrEmpty(resolvedLoginName)) {
					osAccount = getOsAccountByLoginName(resolvedLoginName, realm);
					if (osAccount.isPresent()) {
						return osAccount.get();
					}
				}

				// create failed for some other reason, throw an exception
				throw new TskCoreException(String.format("Error creating OsAccount with sid = %s, loginName = %s, realm = %s, referring host = %s",
						(sid != null) ? sid : "Null",
						(resolvedLoginName != null) ? resolvedLoginName : "Null",
						(!realm.getRealmNames().isEmpty()) ? realm.getRealmNames().get(0) : "Null",
						realm.getScopeHost().isPresent() ? realm.getScopeHost().get().getName() : "Null"), ex);

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
	 * @return OsAccountInstance Existing or newly created account instance.
	 *
	 * @throws TskCoreException If there is an error creating the account
	 *                          instance.
	 */
	public OsAccountInstance newOsAccountInstance(OsAccount osAccount, DataSource dataSource, OsAccountInstance.OsAccountInstanceType instanceType) throws TskCoreException {
		if (osAccount == null) {
			throw new TskCoreException("Cannot create account instance with null account.");
		}
		if (dataSource == null) {
			throw new TskCoreException("Cannot create account instance with null data source.");
		}

		// check the cache first 
		Optional<OsAccountInstance> existingInstance = cachedAccountInstance(osAccount.getId(), dataSource.getId(), instanceType);
		if (existingInstance.isPresent()) {
			return existingInstance.get();
		}

		try (CaseDbConnection connection = this.db.getConnection()) {
			return newOsAccountInstance(osAccount.getId(), dataSource.getId(), instanceType, connection);
		}
	}

	/**
	 * Adds a row to the tsk_os_account_instances table. Does nothing if the
	 * instance already exists in the table.
	 *
	 * @param osAccountId     Account id for which an instance needs to be
	 *                        added.
	 * @param dataSourceObjId Data source id where the instance is found.
	 * @param instanceType    Instance type.
	 * @param connection      The current database connection.
	 *
	 * @return OsAccountInstance Existing or newly created account instance.
	 *
	 * @throws TskCoreException If there is an error creating the account
	 *                          instance.
	 */
	OsAccountInstance newOsAccountInstance(long osAccountId, long dataSourceObjId, OsAccountInstance.OsAccountInstanceType instanceType, CaseDbConnection connection) throws TskCoreException {

		Optional<OsAccountInstance> existingInstance = cachedAccountInstance(osAccountId, dataSourceObjId, instanceType);
		if (existingInstance.isPresent()) {
			return existingInstance.get();
		}

		/*
		 * Create the OS account instance.
		 */
		db.acquireSingleUserCaseWriteLock();
		try {
			String accountInsertSQL = db.getInsertOrIgnoreSQL("INTO tsk_os_account_instances(os_account_obj_id, data_source_obj_id, instance_type)"
					+ " VALUES (?, ?, ?)"); // NON-NLS
			PreparedStatement preparedStatement = connection.getPreparedStatement(accountInsertSQL, Statement.RETURN_GENERATED_KEYS);
			preparedStatement.clearParameters();
			preparedStatement.setLong(1, osAccountId);
			preparedStatement.setLong(2, dataSourceObjId);
			preparedStatement.setInt(3, instanceType.getId());
			connection.executeUpdate(preparedStatement);
			try (ResultSet resultSet = preparedStatement.getGeneratedKeys();) {
				if (resultSet.next()) {
					OsAccountInstance accountInstance = new OsAccountInstance(db, resultSet.getLong(1), osAccountId, dataSourceObjId, instanceType);
					synchronized (osAcctInstancesCacheLock) {
						OsAccountInstanceKey key = new OsAccountInstanceKey(osAccountId, dataSourceObjId);
						// remove from cache any instances less significant (higher ordinal) than this instance
						for (OsAccountInstance.OsAccountInstanceType type : OsAccountInstance.OsAccountInstanceType.values()) {
							if (accountInstance.getInstanceType().compareTo(type) < 0) {
								osAccountInstanceCache.remove(key);
							}
						}
						// add the new most significant instance to the cache
						osAccountInstanceCache.put(key, accountInstance);
					}
					/*
					 * There is a potential issue here. The cache of OS account
					 * instances is an optimization and was not intended to be
					 * used as an authoritative indicator of whether or not a
					 * particular OS account instance was already added to the
					 * case. In fact, the entire cache is flushed during merge
					 * operations. But regardless, there is a check-then-act
					 * race condition for multi-user cases, with or without the
					 * cache. And although the case database schema and the SQL
					 * returned by getInsertOrIgnoreSQL() seamlessly prevents
					 * duplicates in the case database, a valid row ID is
					 * returned here even if the INSERT is not done. So the
					 * bottom line is that a redundant event may be published
					 * from time to time.
					 */
					db.fireTSKEvent(new TskEvent.OsAcctInstancesAddedTskEvent(Collections.singletonList(accountInstance)));

					return accountInstance;
				} else {
					// there is the possibility that another thread may be adding the same os account instance at the same time
					// the database may be updated prior to the cache being updated so this provides an extra opportunity to check
					// the cache before throwing the exception
					Optional<OsAccountInstance> existingInstanceRetry = cachedAccountInstance(osAccountId, dataSourceObjId, instanceType);
					if (existingInstanceRetry.isPresent()) {
						return existingInstanceRetry.get();
					} else {
						throw new TskCoreException(String.format("Could not get autogen key after row insert for OS account instance. OS account object id = %d, data source object id = %d", osAccountId, dataSourceObjId));	
					}
				}
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error adding OS account instance for OS account object id = %d, data source object id = %d", osAccountId, dataSourceObjId), ex);
		} finally {
			db.releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Check if an account instance for exists in the cache for given account
	 * id, data source and instance type.
	 *
	 * Instance type does not need to be an exact match - an existing instance
	 * with an instance type more significant than the specified type is
	 * considered a match.
	 *
	 * @param osAccountId     Account id.
	 * @param dataSourceObjId Data source object id.
	 * @param instanceType    Account instance type.
	 *
	 * @return Optional with OsAccountInstance, Optional.empty if there is no
	 *         matching instance in cache.
	 *
	 */
	private Optional<OsAccountInstance> cachedAccountInstance(long osAccountId, long dataSourceObjId, OsAccountInstance.OsAccountInstanceType instanceType) {

		/*
		 * Check the cache of OS account instances for an existing instance for
		 * this OS account and data source. Note that the account instance
		 * created here has a bogus instance ID. This is possible since the
		 * instance ID is not considered in the equals() and hashCode() methods
		 * of this class.
		 */
		synchronized (osAcctInstancesCacheLock) {
			OsAccountInstanceKey key = new OsAccountInstanceKey(osAccountId, dataSourceObjId);
			OsAccountInstance instance = osAccountInstanceCache.get(key);
			if (instance != null) {
				// if the new instance type same or less significant than the existing instance (i.e. same or higher ordinal value) it's a match. 
				if (instanceType.compareTo(instance.getInstanceType()) >= 0) {
					return Optional.of(instance);
				}
			}
			return Optional.empty();
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
		String queryString = "SELECT * FROM tsk_os_accounts accounts "
				+ "WHERE accounts.os_account_obj_id IN "
				+ "(SELECT instances.os_account_obj_id "
				+ "FROM tsk_os_account_instances instances "
				+ "INNER JOIN data_source_info datasources ON datasources.obj_id = instances.data_source_obj_id "
				+ "WHERE datasources.host_id = " + host.getHostId() + ") "
				+ "AND accounts.db_status = " + OsAccount.OsAccountDbStatus.ACTIVE.getId();

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
	 * Get all accounts that had an instance on the specified data source.
	 *
	 * @param dataSourceId Data source id for which to look accounts for.
	 *
	 * @return Set of OsAccounts, may be empty.
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	public List<OsAccount> getOsAccountsByDataSourceObjId(long dataSourceId) throws TskCoreException {
		String queryString = "SELECT * FROM tsk_os_accounts acc "
				+ "WHERE acc.os_account_obj_id IN "
				+ "(SELECT instance.os_account_obj_id "
				+ "FROM tsk_os_account_instances instance "
				+ "WHERE instance.data_source_obj_id = " + dataSourceId + ") "
				+ "AND acc.db_status = " + OsAccount.OsAccountDbStatus.ACTIVE.getId();

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
			throw new TskCoreException(String.format("Error getting OS accounts for data source id = %d", dataSourceId), ex);
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
			// - destination account has a login name and matches the source account login name
			if (matchingDestAccount == null && sourceAccount.getLoginName().isPresent()) {
				List<OsAccount> matchingDestAccounts = destinationAccounts.stream()
						.filter(p -> p.getLoginName().isPresent())
						.filter(p -> (p.getLoginName().get().equalsIgnoreCase(sourceAccount.getLoginName().get())
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

			// tsk_os_account_instances has a unique constraint on os_account_obj_id, data_source_obj_id, and instance_type,
			// so delete any rows that would be duplicates.
			query = "DELETE FROM tsk_os_account_instances "
					+ "WHERE id IN ( "
					+ "SELECT "
					+ "  sourceAccountInstance.id "
					+ "FROM "
					+ "  tsk_os_account_instances destAccountInstance "
					+ "INNER JOIN tsk_os_account_instances sourceAccountInstance ON destAccountInstance.data_source_obj_id = sourceAccountInstance.data_source_obj_id "
					+ "WHERE destAccountInstance.os_account_obj_id = " + destAccount.getId()
					+ " AND sourceAccountInstance.os_account_obj_id = " + sourceAccount.getId()
					+ " AND sourceAccountInstance.instance_type = destAccountInstance.instance_type" + ")";

			s.executeUpdate(query);

			query = makeOsAccountUpdateQuery("tsk_os_account_instances", sourceAccount, destAccount);
			s.executeUpdate(query);
			synchronized (osAcctInstancesCacheLock) {
				osAccountInstanceCache.clear();
			}

			query = makeOsAccountUpdateQuery("tsk_files", sourceAccount, destAccount);
			s.executeUpdate(query);

			query = makeOsAccountUpdateQuery("tsk_data_artifacts", sourceAccount, destAccount);
			s.executeUpdate(query);

			
			// TBD: We need to emit another event which tells CT that two accounts are being merged so it can updates other dedicated tables 
			
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
	 * Copy all fields from sourceAccount that are not set in destAccount.
	 *
	 * Updates the dest account in the database.
	 *
	 * @param sourceAccount The source account.
	 * @param destAccount   The destination account.
	 * @param trans	        Transaction to use for database operations.
	 *
	 * @return OsAccount Updated account.
	 */
	private OsAccount mergeOsAccountObjectsAndUpdateDestAccount(OsAccount sourceAccount, OsAccount destAccount, CaseDbTransaction trans) throws TskCoreException {

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

		// ensure at least one of the two is supplied - a non-null sid or a login name
		if ((StringUtils.isBlank(sid) || (sid.equalsIgnoreCase(WindowsAccountUtils.WINDOWS_NULL_SID)) ) && StringUtils.isBlank(loginName)) {
			throw new TskCoreException("Cannot get an OS account with both SID and loginName as null.");
		}

		// If no SID is given and the given realm/login names is a well known account, get and use the well known SID
		if (StringUtils.isBlank(sid) 
			&& !StringUtils.isBlank(loginName) && !StringUtils.isBlank(realmName) 
				&& WindowsAccountUtils.isWindowsWellKnownAccountName(loginName, realmName)) {
			sid = WindowsAccountUtils.getWindowsWellKnownAccountSid(loginName, realmName);
			
		}
			
		// first get the realm for the given sid
		Optional<OsAccountRealm> realm = db.getOsAccountRealmManager().getWindowsRealm(sid, realmName, referringHost);
		if (!realm.isPresent()) {
			return Optional.empty();
		}

		// search by SID
		if (!Strings.isNullOrEmpty(sid) && !(sid.equalsIgnoreCase(WindowsAccountUtils.WINDOWS_NULL_SID))) {
			if (!WindowsAccountUtils.isWindowsUserSid(sid)) {
				throw new OsAccountManager.NotUserSIDException(String.format("SID = %s is not a user SID.", sid));
			}

			Optional<OsAccount> account = this.getOsAccountByAddr(sid, realm.get());
			if (account.isPresent()) {
				return account;
			}
		}

		// search by login name
		if (!Strings.isNullOrEmpty(loginName)) {
			String resolvedLoginName = WindowsAccountUtils.toWellknownEnglishLoginName(loginName);
			return this.getOsAccountByLoginName(resolvedLoginName, realm.get());
		} else {
			return Optional.empty();
		}
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
				BlackboardAttribute.Type attributeType = db.getBlackboard().getAttributeType(rs.getInt("attribute_type_id"));
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
	 * Gets the OS account instances for a given OS account.
	 *
	 * @param account The OS account.
	 *
	 * @return The OS account instances, may be an empty list.
	 *
	 * @throws TskCoreException
	 */
	public List<OsAccountInstance> getOsAccountInstances(OsAccount account) throws TskCoreException {
		String whereClause = "tsk_os_account_instances.os_account_obj_id = " + account.getId();
		return getOsAccountInstances(whereClause);
	}

	/**
	 * Gets the OS account instances with the given instance IDs.
	 *
	 * @param instanceIDs The instance IDs.
	 *
	 * @return The OS account instances.
	 *
	 * @throws TskCoreException Thrown if there is an error querying the case
	 *                          database.
	 */
	public List<OsAccountInstance> getOsAccountInstances(List<Long> instanceIDs) throws TskCoreException {
		String instanceIds = instanceIDs.stream().map(id -> id.toString()).collect(Collectors.joining(","));

		List<OsAccountInstance> osAcctInstances = new ArrayList<>();

		String querySQL = "SELECT * FROM tsk_os_account_instances "
				+ "	WHERE tsk_os_account_instances.id IN (" + instanceIds + ")";

		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = db.getConnection();
				PreparedStatement preparedStatement = connection.getPreparedStatement(querySQL, Statement.NO_GENERATED_KEYS);
				ResultSet results = connection.executeQuery(preparedStatement)) {

			osAcctInstances = getOsAccountInstancesFromResultSet(results);

		} catch (SQLException ex) {
			throw new TskCoreException("Failed to get OsAccountInstances (SQL = " + querySQL + ")", ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
		return osAcctInstances;
	}

	/**
	 * Gets the OS account instances that satisfy the given SQL WHERE clause.
	 *
	 * Note: this query returns only the most significant instance type (least
	 * ordinal) for each instance, that matches the specified WHERE clause.
	 *
	 * @param whereClause The SQL WHERE clause.
	 *
	 * @return The OS account instances.
	 *
	 * @throws TskCoreException Thrown if there is an error querying the case
	 *                          database.
	 */
	private List<OsAccountInstance> getOsAccountInstances(String whereClause) throws TskCoreException {
		List<OsAccountInstance> osAcctInstances = new ArrayList<>();

		String querySQL
				= "SELECT tsk_os_account_instances.* "
				+ " FROM tsk_os_account_instances "
				+ " INNER JOIN ( SELECT os_account_obj_id,  data_source_obj_id, MIN(instance_type) AS min_instance_type "
				+ "					FROM tsk_os_account_instances"
				+ "					GROUP BY os_account_obj_id, data_source_obj_id ) grouped_instances "
				+ " ON tsk_os_account_instances.os_account_obj_id = grouped_instances.os_account_obj_id "
				+ " AND tsk_os_account_instances.instance_type = grouped_instances.min_instance_type "
				+ " WHERE " + whereClause;

		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = db.getConnection();
				PreparedStatement preparedStatement = connection.getPreparedStatement(querySQL, Statement.NO_GENERATED_KEYS);
				ResultSet results = connection.executeQuery(preparedStatement)) {

			osAcctInstances = getOsAccountInstancesFromResultSet(results);

		} catch (SQLException ex) {
			throw new TskCoreException("Failed to get OsAccountInstances (SQL = " + querySQL + ")", ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
		return osAcctInstances;
	}

	/**
	 * Returns list of OS account instances from the given result set.
	 *
	 * @param results Result set from a SELECT tsk_os_account_instances.* query.
	 *
	 * @return List of OS account instances.
	 *
	 * @throws SQLException
	 */
	private List<OsAccountInstance> getOsAccountInstancesFromResultSet(ResultSet results) throws SQLException {

		List<OsAccountInstance> osAcctInstances = new ArrayList<>();
		while (results.next()) {
			long instanceId = results.getLong("id");
			long osAccountObjID = results.getLong("os_account_obj_id");
			long dataSourceObjId = results.getLong("data_source_obj_id");
			int instanceType = results.getInt("instance_type");
			osAcctInstances.add(new OsAccountInstance(db, instanceId, osAccountObjID, dataSourceObjId, OsAccountInstance.OsAccountInstanceType.fromID(instanceType)));
		}

		return osAcctInstances;
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
	 * Updates the properties of the specified account in the database.
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
	 * Updates specified column in the tsk_os_accounts table to the specified
	 * value.
	 *
	 * @param <T>          Type of value - must be a String, Long or an Integer.
	 * @param accountObjId Object id of the account to be updated.
	 * @param colName      Name of column o be updated.
	 * @param colValue     New column value.
	 * @param connection   Database connection to use.
	 *
	 * @throws SQLException     If there is an error updating the database.
	 * @throws TskCoreException If the value type is not handled.
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
	 * A column is updated only if its current value is null and a non-null
	 * value has been specified.
	 *
	 *
	 * @param osAccount     OsAccount that needs to be updated in the database.
	 * @param accountSid    Account SID, may be null.
	 * @param loginName     Login name, may be null.
	 * @param realmName     Realm name for the account.
	 * @param referringHost Host.
	 *
	 * @return OsAccountUpdateResult Account update status, and the updated
	 *         account.
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
	 * @param osAccount  OsAccount that needs to be updated in the database.
	 * @param accountSid Account SID, may be null.
	 * @param loginName  Login name, may be null.
	 * @param realmName  Account realm name. May be null if accountSid is not
	 *                   null.
	 *
	 * @return OsAccountUpdateResult Account update status, and the updated
	 *         account.
	 *
	 * @throws TskCoreException If there is a database error or if the updated
	 *                          information conflicts with an existing account.
	 */
	private OsAccountUpdateResult updateCoreWindowsOsAccountAttributes(OsAccount osAccount, String accountSid, String loginName, String realmName, Host referringHost, CaseDbTransaction trans) throws TskCoreException, NotUserSIDException {

		// first get and update the realm - if we have the info to find the realm
		
		if ((!StringUtils.isBlank(accountSid) && !accountSid.equalsIgnoreCase(WindowsAccountUtils.WINDOWS_NULL_SID)) || !StringUtils.isBlank(realmName)) {
			// If the SID is a well known SID, ensure we use the well known english name
			String resolvedRealmName = WindowsAccountUtils.toWellknownEnglishRealmName(realmName);
			
			
			OsRealmUpdateResult realmUpdateResult = db.getOsAccountRealmManager().getAndUpdateWindowsRealm(accountSid, resolvedRealmName, referringHost, trans.getConnection());
			
			
			Optional<OsAccountRealm> realmOptional = realmUpdateResult.getUpdatedRealm();

			if (realmOptional.isPresent()) {
				
				if (realmUpdateResult.getUpdateStatus() == OsRealmUpdateStatus.UPDATED) {

					// Check if update of the realm triggers a merge with any other realm, 
					// say another realm with same name but no SID, or same SID but no name
					//1. Check if there is any OTHER realm with the same name, same host but no addr
					Optional<OsAccountRealm> anotherRealmWithSameName = db.getOsAccountRealmManager().getAnotherRealmByName(realmOptional.get(), realmName, referringHost, trans.getConnection());

					// 2. Check if there is any OTHER realm with same addr and host, but NO name
					Optional<OsAccountRealm> anotherRealmWithSameAddr = db.getOsAccountRealmManager().getAnotherRealmByAddr(realmOptional.get(), realmName, referringHost, trans.getConnection());

					if (anotherRealmWithSameName.isPresent()) {
						db.getOsAccountRealmManager().mergeRealms(anotherRealmWithSameName.get(), realmOptional.get(), trans);
					}
					if (anotherRealmWithSameAddr.isPresent()) {
						db.getOsAccountRealmManager().mergeRealms(anotherRealmWithSameAddr.get(), realmOptional.get(), trans);
					}
				}
			}
		}

		// now update the account core data
		String resolvedLoginName = WindowsAccountUtils.toWellknownEnglishLoginName(loginName);
		OsAccountUpdateResult updateStatus = this.updateOsAccountCore(osAccount, accountSid, resolvedLoginName, trans);

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
	 *         account.
	 *
	 * @throws TskCoreException If there is a database error or if the updated
	 *                          information conflicts with an existing account.
	 */
	private OsAccountUpdateResult updateOsAccountCore(OsAccount osAccount, String address, String loginName, CaseDbTransaction trans) throws TskCoreException {

		OsAccountUpdateStatus updateStatusCode = OsAccountUpdateStatus.NO_CHANGE;
		OsAccount updatedAccount;

		try {
			CaseDbConnection connection = trans.getConnection();

			// if a new non-null addr is provided and the account already has an address, and they are not the same, throw an exception
			if (!StringUtils.isBlank(address) && !address.equalsIgnoreCase(WindowsAccountUtils.WINDOWS_NULL_SID) && !StringUtils.isBlank(osAccount.getAddr().orElse(null)) && !address.equalsIgnoreCase(osAccount.getAddr().orElse(""))) {
				throw new TskCoreException(String.format("Account (%d) already has an address (%s), address cannot be updated.", osAccount.getId(), osAccount.getAddr().orElse("NULL")));
			}

			if (StringUtils.isBlank(osAccount.getAddr().orElse(null)) && !StringUtils.isBlank(address) && !address.equalsIgnoreCase(WindowsAccountUtils.WINDOWS_NULL_SID)) {
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
		db.fireTSKEvent(new OsAccountsUpdatedTskEvent(Collections.singletonList(account)));
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

		NO_CHANGE, /// no change was made to account.
		UPDATED, /// account was updated
		MERGED		/// account update triggered a merge
	}

	/**
	 * Container that encapsulates the account update status and the updated
	 * account.
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

	/**
	 * Represents the osAccountId\dataSourceId pair for use with the cache of
	 * OsAccountInstances.
	 */
	private class OsAccountInstanceKey implements Comparable<OsAccountInstanceKey>{

		private final long osAccountId;
		private final long dataSourceId;

		OsAccountInstanceKey(long osAccountId, long dataSourceId) {
			this.osAccountId = osAccountId;
			this.dataSourceId = dataSourceId;
		}

		@Override
		public boolean equals(Object other) {
			if (this == other) {
				return true;
			}
			if (other == null) {
				return false;
			}
			if (getClass() != other.getClass()) {
				return false;
			}

			final OsAccountInstanceKey otherKey = (OsAccountInstanceKey) other;

			if (osAccountId != otherKey.osAccountId) {
				return false;
			}

			return dataSourceId == otherKey.dataSourceId;
		}

		@Override
		public int hashCode() {
			int hash = 5;
			hash = 53 * hash + (int) (this.osAccountId ^ (this.osAccountId >>> 32));
			hash = 53 * hash + (int) (this.dataSourceId ^ (this.dataSourceId >>> 32));
			return hash;
		}

		@Override
		public int compareTo(OsAccountInstanceKey other) {
			if(this.equals(other)) {
				return 0;
			}
			
			if (dataSourceId != other.dataSourceId) {
				return Long.compare(dataSourceId, other.dataSourceId);
			}

			return Long.compare(osAccountId, other.osAccountId);
		}
	}
}
