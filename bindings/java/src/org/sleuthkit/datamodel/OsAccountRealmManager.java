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
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.logging.Logger;
import org.sleuthkit.datamodel.OsAccountRealm.ScopeConfidence;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbConnection;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbTransaction;


/**
 * Create/Retrieve/Update OS account realms. Realms represent either an individual
 * host with local accounts or a domain. 
 */
public final class OsAccountRealmManager {

	private static final Logger LOGGER = Logger.getLogger(OsAccountRealmManager.class.getName());

	private final SleuthkitCase db;

	/**
	 * Construct a OsAccountRealmManager for the given SleuthkitCase.
	 *
	 * @param skCase The SleuthkitCase
	 *
	 */
	OsAccountRealmManager(SleuthkitCase skCase) {
		this.db = skCase;
	}
		
	/**
	 * Create realm based on Windows information. The input SID is a user/group
	 * SID.The domain SID is extracted from this incoming SID.
	 *
	 * @param accountSid    User/group SID. May be null only if name is not
	 *                      null.
	 * @param realmName     Realm name. May be null only if SID is not null.
	 * @param referringHost Host where realm reference is found.
	 * @param realmScope    Scope of realm. Use UNKNOWN if you are not sure and
	 *                      the method will try to detect the correct scope.
	 *
	 * @return OsAccountRealm.
	 *
	 * @throws TskCoreException                     If there is an error
	 *                                              creating the realm.
	 * @throws OsAccountManager.NotUserSIDException If the SID is not a user
	 *                                              SID.
	 */
	public OsAccountRealm newWindowsRealm(String accountSid, String realmName, Host referringHost, OsAccountRealm.RealmScope realmScope) throws TskCoreException, OsAccountManager.NotUserSIDException {

		if (realmScope == null) {
			throw new TskCoreException("RealmScope cannot be null. Use UNKNOWN if scope is not known.");
		}
		if (referringHost == null) {
			throw new TskCoreException("A referring host is required to create a realm.");
		}
		if (StringUtils.isBlank(accountSid) && StringUtils.isBlank(realmName)) {
			throw new TskCoreException("Either an address or a name is required to create a realm.");
		}
		
		Host scopeHost;
		OsAccountRealm.ScopeConfidence scopeConfidence;
		
		switch (realmScope) {
			case DOMAIN:
				scopeHost = null;
				scopeConfidence = OsAccountRealm.ScopeConfidence.KNOWN;
				break;
			case LOCAL:
				scopeHost = referringHost;
				scopeConfidence = OsAccountRealm.ScopeConfidence.KNOWN;
				break;

			case UNKNOWN:
			default:
				// check if the referring host already has a realm
				boolean isHostRealmKnown = isHostRealmKnown(referringHost);
				if (isHostRealmKnown) {
					scopeHost = null;	// the realm does not scope to the referring host since it already has one.
					scopeConfidence = OsAccountRealm.ScopeConfidence.KNOWN;
				} else {
					scopeHost = referringHost;
					scopeConfidence = OsAccountRealm.ScopeConfidence.INFERRED;
				}
				break;

		}
		
		// get windows realm address from sid
		String realmAddr = null;
		if (!Strings.isNullOrEmpty(accountSid)) {
			
			if (!WindowsAccountUtils.isWindowsUserSid(accountSid)) {
				throw new OsAccountManager.NotUserSIDException(String.format("SID = %s is not a user SID.", accountSid ));
			}
			
			realmAddr = WindowsAccountUtils.getWindowsRealmAddress(accountSid);
			
			// if the account is special windows account, create a local realm for it.
			if (realmAddr.equals(WindowsAccountUtils.SPECIAL_WINDOWS_REALM_ADDR)) {
				scopeHost = referringHost;
				scopeConfidence = OsAccountRealm.ScopeConfidence.KNOWN;
			}
		}
		
		String signature = makeRealmSignature(realmAddr, realmName, scopeHost);
		
		// create a realm
		return newRealm(realmName, realmAddr, signature, scopeHost, scopeConfidence);
	}
	
	/**
	 * Get a windows realm by the account SID, or the domain name. The input SID
	 * is an user/group account SID. The domain SID is extracted from this
	 * incoming SID.
	 *
	 * @param accountSid    Account SID, may be null.
	 * @param realmName     Realm name, may be null only if accountSid is not
	 *                      null.
	 * @param referringHost Referring Host.
	 *
	 * @return Optional with OsAccountRealm, Optional.empty if no matching realm
	 *         is found.
	 *
	 * @throws TskCoreException
	 * @throws OsAccountManager.NotUserSIDException If the SID is not a user
	 *                                              SID.
	 */
	public Optional<OsAccountRealm> getWindowsRealm(String accountSid, String realmName, Host referringHost) throws TskCoreException, OsAccountManager.NotUserSIDException {
		
		if (referringHost == null) {
			throw new TskCoreException("A referring host is required get a realm.");
		}
		
		// need at least one of the two, the addr or name to look up
		if (Strings.isNullOrEmpty(accountSid) && Strings.isNullOrEmpty(realmName)) {
			throw new TskCoreException("Realm address or name is required get a realm.");
		}
		
		try (CaseDbConnection connection = this.db.getConnection()) {
			return getWindowsRealm(accountSid, realmName, referringHost, connection);
		}
	}
	
	
	/**
	 * Get a windows realm by the account SID, or the domain name.
	 * The input SID is an user/group account SID. The domain SID is extracted from this incoming SID.
	 * 
	 * @param accountSid    Account SID, may be null.
	 * @param realmName     Realm name, may be null only if accountSid is not
	 *                      null.
	 * @param referringHost Referring Host.
	 * @param connection    Database connection to use.
	 * 
	 * @return Optional with OsAccountRealm, Optional.empty if no matching realm is found.
	 * 
	 * @throws TskCoreException
	 */
	Optional<OsAccountRealm> getWindowsRealm(String accountSid, String realmName, Host referringHost, CaseDbConnection connection) throws TskCoreException, OsAccountManager.NotUserSIDException {
		
		if (referringHost == null) {
			throw new TskCoreException("A referring host is required get a realm.");
		}
		
		// need at least one of the two, the addr or name to look up
		if (StringUtils.isBlank(accountSid) && StringUtils.isBlank(realmName)) {
			throw new TskCoreException("Realm address or name is required get a realm.");
		}
		
		// If an accountSID is provided search for realm by addr.
		if (!Strings.isNullOrEmpty(accountSid)) {
			
			if (!WindowsAccountUtils.isWindowsUserSid(accountSid)) {
				throw new OsAccountManager.NotUserSIDException(String.format("SID = %s is not a user SID.", accountSid ));
			}
			// get realm addr from the account SID.
			String realmAddr = WindowsAccountUtils.getWindowsRealmAddress(accountSid);
			Optional<OsAccountRealm> realm = getRealmByAddr(realmAddr, referringHost, connection);
			if (realm.isPresent()) {
				return realm;
			}
		}

		// No realm addr so search by name.
		Optional<OsAccountRealm> realm = getRealmByName(realmName, referringHost, connection);
		if (realm.isPresent() && !Strings.isNullOrEmpty(accountSid)) {
			// If we were given an accountSID, make sure there isn't one set on the matching realm.
			// We know it won't match because the previous search by SID failed.
			if (realm.get().getRealmAddr().isPresent()) {
				return Optional.empty();
			}
		}
		return realm;
	}
	
	
	/**
	 * Get a windows realm by the account SID, or the domain name. The input SID
	 * is an user/group account SID. The domain SID is extracted from this
	 * incoming SID.
	 *
	 * If a realm is found but is missing either the SID or the realmName, then
	 * the realm is updated.
	 *
	 * @param accountSid    Account SID, may be null.
	 * @param realmName     Realm name, may be null only if accountSid is not
	 *                      null.
	 * @param referringHost Referring Host.
	 * @param connection    Database connection to use.
	 *
	 * @return Optional with OsAccountRealm, Optional.empty if no matching realm
	 *         is found.
	 *
	 * @throws TskCoreException
	 */
	Optional<OsAccountRealm> getAndUpdateWindowsRealm(String accountSid, String realmName, Host referringHost, CaseDbConnection connection) throws TskCoreException, OsAccountManager.NotUserSIDException {
		
		// get realm
		Optional<OsAccountRealm> realmOptional =  getWindowsRealm(accountSid, realmName, referringHost, connection );
		
		// if found, update it if needed
		if (realmOptional.isPresent()) {
			String realmAddr = StringUtils.isNotBlank(accountSid) ? WindowsAccountUtils.getWindowsRealmAddress(accountSid) : null;
			OsRealmUpdateResult realmUpdateResult = updateRealm(realmOptional.get(), realmAddr, realmName, connection);
			
			// if realm was updated, return the updated realm
			if (realmUpdateResult.getUpdateStatus() == OsRealmUpdateStatus.UPDATED) {
				return realmUpdateResult.getUpdatedRealm();
			} 
		} 
		
		return realmOptional; // return the found realm as is, if any
	}
	
	
	/**
	 * Updates the realm address and/or name, if a non blank address/name is
	 * specified and the current address/name is blank.
	 * 
	 * NOTE: This will not merge two realms if the updated information exists
     * for another realm (i.e. such as adding an address to a realm that has
     * only a name and there is already a realm with that address). 
	 * 
	 *
	 * @param realm      Realm to update.
	 * @param realmAddr  Realm address, may be null if the address doesn't need
	 *                   to be updated.
	 * @param realmName  Realm name, may be null if the name doesn't need to be
	 *                   updated.
	 * 
	 * @return OsRealmUpdateResult Update status and updated realm.
	 * 
	 * @throws TskCoreException If there is a database error or if a realm
     * already exists with that information. 
	 */
	public OsRealmUpdateResult updateRealm(OsAccountRealm realm, String realmAddr, String realmName) throws TskCoreException {
		
		try (CaseDbConnection connection = db.getConnection())  {
			return updateRealm(realm, realmAddr, realmName, connection);
		}
	}
		
	/**
	 * Updates the realm address and/or name, if a non blank address/name is
	 * specified and the current address/name is blank.
	 *
	 * @param realm      Realm to update.
	 * @param realmAddr  Realm address, may be null if the address doesn't need
	 *                   to be updated.
	 * @param realmName  Realm name, may be null if the name doesn't need to be
	 *                   updated.
	 * @param connection Current database connection.
	 *
	 * @return OsRealmUpdateResult Update status and updated realm.
	 *
	 * @throws TskCoreException If there is a database error or if a realm
	 *                          already exists with that information.
	 */
	private OsRealmUpdateResult updateRealm(OsAccountRealm realm, String realmAddr, String realmName, CaseDbConnection connection) throws TskCoreException {

		// need at least one of the two
		if (StringUtils.isBlank(realmAddr) && StringUtils.isBlank(realmName)) {
			throw new TskCoreException("Realm address or name is required to update realm.");
		}

		OsRealmUpdateStatus updateStatusCode = OsRealmUpdateStatus.NO_CHANGE;
		OsAccountRealm updatedRealm = null;

		db.acquireSingleUserCaseWriteLock();
		try {
			List<String> realmNames = realm.getRealmNames();
			String currRealmName = realmNames.isEmpty() ? null : realmNames.get(0);	// currently there is only one name.
			String currRealmAddr = realm.getRealmAddr().orElse(null);

			// set name and address to new values only if the current value is blank and the new value isn't.		
			if ((StringUtils.isBlank(currRealmAddr) && StringUtils.isNotBlank(realmAddr))) {
				updateRealmColumn(realm.getRealmId(), "realm_addr", realmAddr, connection);
				updateStatusCode = OsRealmUpdateStatus.UPDATED;
			}

			if (StringUtils.isBlank(currRealmName) && StringUtils.isNotBlank(realmName)) {
				updateRealmColumn(realm.getRealmId(), "realm_name", realmName, connection);
				updateStatusCode = OsRealmUpdateStatus.UPDATED;
			}

			// if nothing is to be changed, return
			if (updateStatusCode == OsRealmUpdateStatus.NO_CHANGE) {
				return new OsRealmUpdateResult(updateStatusCode, realm);
			}

			// update realm signature - based on the most current address and name
			OsAccountRealm currRealm = getRealmByRealmId(realm.getRealmId(), connection);
			String newRealmAddr = currRealm.getRealmAddr().orElse(null);
			String newRealmName = (currRealm.getRealmNames().isEmpty() == false) ? currRealm.getRealmNames().get(0) : null;

			// make new signature
			String newSignature = makeRealmSignature(newRealmAddr, newRealmName, realm.getScopeHost().orElse(null));

			// Use a random string as the signature if the realm is not active.
			String updateSQL = "UPDATE tsk_os_account_realms SET  "
					+ " realm_signature = "
					+ "   CASE WHEN db_status = " + OsAccountRealm.RealmDbStatus.ACTIVE.getId() + " THEN ? ELSE realm_signature END "
					+ " WHERE id = ?";
			PreparedStatement preparedStatement = connection.getPreparedStatement(updateSQL, Statement.NO_GENERATED_KEYS);
			preparedStatement.clearParameters();

			preparedStatement.setString(1, newSignature); // Is only set for active accounts
			preparedStatement.setLong(2, realm.getRealmId());
			connection.executeUpdate(preparedStatement);

			// read the updated realm
			updatedRealm = this.getRealmByRealmId(realm.getRealmId(), connection);

			return new OsRealmUpdateResult(updateStatusCode, updatedRealm);
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error updating realm with id = %d, name = %s, addr = %s", realm.getRealmId(), realmName != null ? realmName : "Null", realm.getRealmAddr().orElse("Null")), ex);
		} finally {
			db.releaseSingleUserCaseWriteLock();
		}

	}

	/**
	 * Updates specified column in the tsk_os_account_realms table to the specified value.
	 * 
	 * @param <T> Type of value - must be a String, Long or an Integer. 
	 * @param realmId Id of the realm to be updated.
	 * @param colName Name of column o be updated.
	 * @param colValue New column value. 
	 * @param connection Database connection to use.
	 * 
	 * @throws SQLException If there is an error updating the database.
	 * @throws TskCoreException  If the value type is not handled.
	 */
	private <T> void updateRealmColumn(long realmId, String colName, T colValue, CaseDbConnection connection) throws SQLException, TskCoreException {

		String updateSQL = "UPDATE tsk_os_account_realms "
				+ " SET " + colName + " = ? "
				+ " WHERE id = ?";

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
					throw new TskCoreException(String.format("Unhandled column data type received while updating the realm (id = %d) ", realmId));
				}
			}

			preparedStatement.setLong(2, realmId);

			connection.executeUpdate(preparedStatement);
		} finally {
			db.releaseSingleUserCaseWriteLock();
		}
	}
	
	private final static String REALM_QUERY_STRING = "SELECT realms.id as realm_id, realms.realm_name as realm_name,"
			+ " realms.realm_addr as realm_addr, realms.realm_signature as realm_signature, realms.scope_host_id, realms.scope_confidence, realms.db_status,"
			+ " hosts.id, hosts.name as host_name "
			+ " FROM tsk_os_account_realms as realms"
			+ "		LEFT JOIN tsk_hosts as hosts"
			+ " ON realms.scope_host_id = hosts.id";
	
    /**
	 * Get the realm from the given row id. 
	 * 
	 * @param id Realm row id.
	 * 
	 * @return Realm. 
	 * @throws TskCoreException on error 
	 */

	public OsAccountRealm getRealmByRealmId(long id) throws TskCoreException {
		try (CaseDbConnection connection = this.db.getConnection()) {
			return getRealmByRealmId(id, connection);
		}
	}
	
	/**
	 * Get the realm from the given row id. 
	 * 
	 * @param id Realm row id.
	 * @param connection Database connection to use.
	 * 
	 * @return Realm. 
	 * @throws TskCoreException 
	 */
	OsAccountRealm getRealmByRealmId(long id, CaseDbConnection connection) throws TskCoreException {
		
		String queryString = REALM_QUERY_STRING
					+ " WHERE realms.id = " + id;
		
		db.acquireSingleUserCaseReadLock();
		try (	Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {
			OsAccountRealm accountRealm = null;
			if (rs.next()) { 
				accountRealm = resultSetToAccountRealm(rs);
			} else {
				throw new TskCoreException(String.format("No realm found with id = %d", id));
			}

			return accountRealm;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error running the realms query = %s", queryString), ex);
		}
		finally {
			db.releaseSingleUserCaseReadLock();
		}
	}
	
	/**
	 * Get the realm with the given realm address.
	 * 
	 * @param realmAddr Realm address.
	 * @param host Host for realm, may be null.
	 * @param connection Database connection to use.
	 * 
	 * @return Optional with OsAccountRealm, Optional.empty if no realm found with matching real address.
	 * 
	 * @throws TskCoreException.
	 */
	Optional<OsAccountRealm> getRealmByAddr(String realmAddr, Host host, CaseDbConnection connection) throws TskCoreException {
		
		// If a host is specified, we want to match the realm with matching addr and specified host, or a realm with matching addr and no host.
		// If no host is specified, then we return the first realm with matching addr.
		String whereHostClause = (host == null) 
							? " 1 = 1 " 
							: " ( realms.scope_host_id = " + host.getHostId() + " OR realms.scope_host_id IS NULL) ";
		String queryString = REALM_QUERY_STRING
						+ " WHERE LOWER(realms.realm_addr) = LOWER('"+ realmAddr + "') "
						+ " AND " + whereHostClause
				        + " AND realms.db_status = " + OsAccountRealm.RealmDbStatus.ACTIVE.getId()
						+ " ORDER BY realms.scope_host_id IS NOT NULL, realms.scope_host_id";	// ensure that non null host_id is at the front
				    
		db.acquireSingleUserCaseReadLock();
		try (	Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			OsAccountRealm accountRealm = null;
			if (rs.next()) {
				Host realmHost = null;
				long hostId = rs.getLong("scope_host_id");
				if (!rs.wasNull()) {
					if (host != null ) {
						realmHost = host; // exact match on given host
					} else {
						realmHost = new Host(hostId, rs.getString("host_name"));
					}
				}
				
				accountRealm = new OsAccountRealm(rs.getLong("realm_id"), rs.getString("realm_name"), 
												rs.getString("realm_addr"), rs.getString("realm_signature"), 
												realmHost, ScopeConfidence.fromID(rs.getInt("scope_confidence")),
												OsAccountRealm.RealmDbStatus.fromID(rs.getInt("db_status")));
			} 
			return Optional.ofNullable(accountRealm);
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error running the realms query = %s with realmaddr = %s and host name = %s",
					queryString, realmAddr, (host != null ? host.getName() : "Null")), ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}
	
	/**
	 * Get the realm with the given name and specified host.
	 * 
	 * @param realmName Realm name.
	 * @param host Host for realm, may be null.
	 * @param connection Database connection to use.
	 * 
	 * @return Optional with OsAccountRealm, Optional.empty if no matching realm is found.
	 * @throws TskCoreException.
	 */
	Optional<OsAccountRealm> getRealmByName(String realmName, Host host, CaseDbConnection connection) throws TskCoreException {
		
		// If a host is specified, we want to match the realm with matching name and specified host, or a realm with matching name and no host.
		// If no host is specified, then we return the first realm with matching name.
		String whereHostClause = (host == null)
				? " 1 = 1 "
				: " ( realms.scope_host_id = " + host.getHostId() + " OR realms.scope_host_id IS NULL ) ";
		String queryString = REALM_QUERY_STRING
				+ " WHERE LOWER(realms.realm_name) = LOWER('" + realmName + "')"
				+ " AND " + whereHostClause
				+ " AND realms.db_status = " + OsAccountRealm.RealmDbStatus.ACTIVE.getId()
				+ " ORDER BY realms.scope_host_id IS NOT NULL, realms.scope_host_id";	// ensure that non null host_id are at the front

		db.acquireSingleUserCaseReadLock();
		try (Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {
			
			OsAccountRealm accountRealm = null;
			if (rs.next()) {
				Host realmHost = null;
				long hostId = rs.getLong("scope_host_id");
				if (!rs.wasNull()) {
					if (host != null ) {
						realmHost = host;
					} else {
						realmHost = new Host(hostId, rs.getString("host_name"));
					}
				}
				
				accountRealm = new OsAccountRealm(rs.getLong("realm_id"), rs.getString("realm_name"), 
												rs.getString("realm_addr"), rs.getString("realm_signature"), 
												realmHost, ScopeConfidence.fromID(rs.getInt("scope_confidence")),
												OsAccountRealm.RealmDbStatus.fromID(rs.getInt("db_status")));
				
			} 
			return Optional.ofNullable(accountRealm);
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting account realm for with name = %s", realmName), ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}
	
	/**
	 * Check is there is any realm with a host-scope and KNOWN confidence for the given host.  
	 * If we can assume that a host will have only a single host-scoped realm, then you can 
	 * assume a new realm is domain-scoped when this method returns true.  I.e. once we know
	 * the host-scoped realm, then everything else is domain-scoped. 
	 * 
	 * @param host Host for which to look for a realm.
	 * 
	 * @return True if there exists a a realm with the host scope matching the host. False otherwise
	 */
	private boolean isHostRealmKnown(Host host) throws TskCoreException {
	
		// check if this host has a local known realm aleady, other than the special windows realm.
		String queryString = REALM_QUERY_STRING
				+ " WHERE realms.scope_host_id = " + host.getHostId()
				+ " AND realms.scope_confidence = " + OsAccountRealm.ScopeConfidence.KNOWN.getId()
				+ " AND realms.db_status = " + OsAccountRealm.RealmDbStatus.ACTIVE.getId()
				+ " AND LOWER(realms.realm_addr) <> LOWER('"+ WindowsAccountUtils.SPECIAL_WINDOWS_REALM_ADDR + "') ";

		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = this.db.getConnection();
				Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {
			
			// return true if there is any match.
			return rs.next();
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting account realm for with host = %s", host.getName()), ex);
		}
		finally {
			db.releaseSingleUserCaseReadLock();
		}

	}

	/**
	 * Creates a OsAccountRealm from the resultset of a REALM_QUERY_STRING query.
	 * 
	 * @param rs ResultSet
	 * @return
	 * @throws SQLException 
	 */
	private OsAccountRealm resultSetToAccountRealm(ResultSet rs) throws SQLException {
		
		long hostId = rs.getLong("scope_host_id");
		Host realmHost = null;
		if (!rs.wasNull()) {
			realmHost = new Host(hostId, rs.getString("host_name"));
		}

		return new OsAccountRealm(rs.getLong("realm_id"), rs.getString("realm_name"), 
												rs.getString("realm_addr"), rs.getString("realm_signature"), 
												realmHost, ScopeConfidence.fromID(rs.getInt("scope_confidence")),
												OsAccountRealm.RealmDbStatus.fromID(rs.getInt("db_status")));
	}
	
//	/**
//	 * Get all realms.
//	 * 
//	 * @return Collection of OsAccountRealm
//	 */
//	Collection<OsAccountRealm> getRealms() throws TskCoreException {
//		String queryString = "SELECT realms.id as realm_id, realms.realm_name as realm_name, realms.realm_addr as realm_addr, realms.scope_host_id, realms.scope_confidence, "
//				+ " hosts.id, hosts.name as host_name "
//				+ " FROM tsk_os_account_realms as realms"
//				+ "		LEFT JOIN tsk_hosts as hosts"
//				+ " ON realms.scope_host_id = hosts.id";
//
//		db.acquireSingleUserCaseReadLock();
//		try (CaseDbConnection connection = this.db.getConnection();
//				Statement s = connection.createStatement();
//				ResultSet rs = connection.executeQuery(s, queryString)) {
//
//			ArrayList<OsAccountRealm> accountRealms = new ArrayList<>();
//			while (rs.next()) {
//				long hostId = rs.getLong("scope_host_id");
//				Host host = null;
//				if (!rs.wasNull()) {
//					host = new Host(hostId, rs.getString("host_name"));
//				}
//
//				accountRealms.add(new OsAccountRealm(rs.getLong("realm_id"), rs.getString("realm_name"),
//						ScopeConfidence.fromID(rs.getInt("scope_confidence")),
//						rs.getString("realm_addr"), host));
//			}
//
//			return accountRealms;
//		} catch (SQLException ex) {
//			throw new TskCoreException(String.format("Error running the realms query = %s", queryString), ex);
//		}
//		finally {
//			db.releaseSingleUserCaseReadLock();
//		}
//	}
	
	
	/**
	 * Adds a row to the realms table.
	 * 
	 * If the add fails, it tries to get the realm, in case the realm already exists.
	 *
	 * @param realmName       Realm name, may be null.
	 * @param realmAddr       SID or some other identifier. May be null if name
	 *                        is not null.
	 * @param signature       Signature, either the address or the name.
	 * @param host            Host, if the realm is host scoped. Can be null
	 *                        realm is domain scoped.
	 * @param scopeConfidence Confidence in realm scope.
	 *
	 * @return OsAccountRealm Realm just created.
	 *
	 * @throws TskCoreException If there is an internal error.
	 */
	private OsAccountRealm newRealm(String realmName, String realmAddr, String signature, Host host, OsAccountRealm.ScopeConfidence scopeConfidence) throws TskCoreException {

		db.acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = this.db.getConnection()) {
			String realmInsertSQL = "INSERT INTO tsk_os_account_realms(realm_name, realm_addr, realm_signature, scope_host_id, scope_confidence)"
					+ " VALUES (?, ?, ?, ?, ?)"; // NON-NLS

			PreparedStatement preparedStatement = connection.getPreparedStatement(realmInsertSQL, Statement.RETURN_GENERATED_KEYS);
			preparedStatement.clearParameters();

			preparedStatement.setString(1, realmName);
			preparedStatement.setString(2, realmAddr);
			preparedStatement.setString(3, signature);
			if (host != null) {
				preparedStatement.setLong(4, host.getHostId());
			} else {
				preparedStatement.setNull(4, java.sql.Types.BIGINT);
			}
			preparedStatement.setInt(5, scopeConfidence.getId());

			connection.executeUpdate(preparedStatement);

			// Read back the row id
			try (ResultSet resultSet = preparedStatement.getGeneratedKeys();) {
				long rowId = resultSet.getLong(1); // last_insert_rowid()
				return new OsAccountRealm(rowId, realmName, realmAddr, signature, host, scopeConfidence, OsAccountRealm.RealmDbStatus.ACTIVE);
			}

		} catch (SQLException ex) {
			// Create may have failed if the realm already exists. Try and get the matching realm 
			try (CaseDbConnection connection = this.db.getConnection()) {
				if (!Strings.isNullOrEmpty(realmAddr)) {
					Optional<OsAccountRealm> accountRealm = this.getRealmByAddr(realmAddr, host, connection);
					if (accountRealm.isPresent()) {
						return accountRealm.get();
					}
				} else if (!Strings.isNullOrEmpty(realmName)) {
					Optional<OsAccountRealm> accountRealm = this.getRealmByName(realmName, host, connection);
					if (accountRealm.isPresent()) {
						return accountRealm.get();
					}
				}

				// some other failure - throw an exception
				throw new TskCoreException(String.format("Error creating realm with address = %s and name = %s, with host = %s",
						realmAddr != null ? realmAddr : "", realmName != null ? realmName : "", host != null ? host.getName() : ""), ex);
			}
		} finally {
			db.releaseSingleUserCaseWriteLock();
		}
	}
	

	/**
	 * Makes a realm signature based on given realm address, name scope host.
	 *
	 * The signature is  primarily to provide uniqueness in the database.
	 * 
	 * Signature is built as:
	 *  (addr|name)_(hostId|"DOMAIN")
	 *
	 * @param realmAddr Realm address, may be null.
	 * @param realmName Realm name, may be null only if address is not null.
	 * @param scopeHost Realm scope host. May be null.
	 * 
	 * @return Realm Signature.
	 * 
	 * @throws TskCoreException If there is an error making the signature.
	 */
	static String makeRealmSignature(String realmAddr, String realmName, Host scopeHost) throws TskCoreException {

		// need at least one of the two, the addr or name to look up
		if (Strings.isNullOrEmpty(realmAddr) && Strings.isNullOrEmpty(realmName)) {
			throw new TskCoreException("Realm address and name can't both be null.");
		}
		
		String signature = String.format("%s_%s", !Strings.isNullOrEmpty(realmAddr) ?  realmAddr : realmName,
												scopeHost != null ? scopeHost.getHostId() : "DOMAIN");
		return signature;
	}
	
	/**
	 * Create a random signature for realms that have been merged.
	 * 
	 * @return The random signature.
	 */
	private String makeMergedRealmSignature() {
		return "MERGED " +  UUID.randomUUID().toString();
	}
	
	
	/**
	 * Move source realm into the destination host or merge with an existing realm.
	 * 
	 * @param sourceRealm
	 * @param destHost
	 * @param trans
	 * @throws TskCoreException 
	 */
	void moveOrMergeRealm(OsAccountRealm sourceRealm, Host destHost, CaseDbTransaction trans) throws TskCoreException {
		// Look for a matching realm by address
		Optional<OsAccountRealm> optDestRealmAddr = Optional.empty();
		if (sourceRealm.getRealmAddr().isPresent()) {
			optDestRealmAddr = db.getOsAccountRealmManager().getRealmByAddr(sourceRealm.getRealmAddr().get(), destHost, trans.getConnection());
		}
		
		// Look for a matching realm by name
		Optional<OsAccountRealm> optDestRealmName = Optional.empty();
		if (!sourceRealm.getRealmNames().isEmpty()) {
			optDestRealmName = db.getOsAccountRealmManager().getRealmByName(sourceRealm.getRealmNames().get(0), destHost, trans.getConnection());
		}
		
		// Decide how to proceed:
		// - If we only got one match:
		// -- If the address matched, set destRealm to the matching address realm
		// -- If the name matched but the original and the matching realm have different addresses, leave destRealm null (it'll be a move)
		// -- If the name matched and at least one of the address fields was null, set destRealm to the matching name realm
		// - If we got no matches, leave destRealm null (we'll do a move not a merge)
		// - If we got two of the same matches, set destRealm to that realm
		// - If we got two different matches:
		// -- If the name match has no address set, merge the matching name realm into the matching address realm, then
		//        set destRealm to the matching address realm
		// -- Otherwise we're in the case where the addresses are different. We will consider the address the 
		//        stronger match and set destRealm to the matching address realm and leave the matching name realm as-is.		
		OsAccountRealm destRealm = null;
		if (optDestRealmAddr.isPresent() && optDestRealmName.isPresent()) {
			if (optDestRealmAddr.get().getRealmId() == optDestRealmName.get().getRealmId()) {
				// The two matches are the same
				destRealm = optDestRealmAddr.get();
			} else {
				if (optDestRealmName.get().getRealmAddr().isPresent()) {
					// The addresses are different, so use the one with the matching address
					destRealm = optDestRealmAddr.get();
				} else {
					// Merge the realm with the matching name into the realm with the matching address.
					// Reload from database afterward to make sure everything is up-to-date.
					mergeRealms(optDestRealmName.get(), optDestRealmAddr.get(), trans);
					destRealm = getRealmByRealmId(optDestRealmAddr.get().getRealmId(), trans.getConnection());
				}
			}
		} else if (optDestRealmAddr.isPresent()) {
			// Only address matched - use it
			destRealm = optDestRealmAddr.get();
		} else if (optDestRealmName.isPresent()) {
			// Only name matched - check whether both have addresses set.
			// Due to earlier checks we know the address fields can't be the same, so
			// don't do anything if both have addresses - we consider the address to be a stronger identifier than the name
			if (! (optDestRealmName.get().getRealmAddr().isPresent() && sourceRealm.getRealmAddr().isPresent())) {
				destRealm = optDestRealmName.get();
			}
		}
		
		// Move or merge the source realm
		if (destRealm == null) {
			moveRealm(sourceRealm, destHost, trans);
		} else {
			mergeRealms(sourceRealm, destRealm, trans);
		}
	}
	
	/**
	 * Move a realm to a different host.
	 * A check should be done to make sure there are no matching realms in
	 * the destination host before calling this method.
	 * 
	 * @param sourceRealm The source realm.
	 * @param destHost    The destination host.
	 * @param trans       The open transaction.
	 * 
	 * @throws TskCoreException 
	 */
	private void moveRealm(OsAccountRealm sourceRealm, Host destHost, CaseDbTransaction trans) throws TskCoreException {
		try(Statement s = trans.getConnection().createStatement()) {
			String query = "UPDATE tsk_os_account_realms SET scope_host_id = " + destHost.getHostId() + " WHERE id = " + sourceRealm.getRealmId();
			s.executeUpdate(query);
		} catch (SQLException ex) {
			throw new TskCoreException("Error moving realm with id: " + sourceRealm.getRealmId() + " to host with id: " + destHost.getHostId(), ex);
		}
	}
	
	
	/**
	 * Merge one realm into another, moving or combining all associated OsAccounts.
	 * 
	 * @param sourceRealm The sourceRealm realm.
	 * @param destRealm   The destination realm.
	 * @param trans  The open transaction.
	 * 
	 * @throws TskCoreException 
	 */
	void mergeRealms(OsAccountRealm sourceRealm, OsAccountRealm destRealm, CaseDbTransaction trans) throws TskCoreException {

		// Update accounts
		db.getOsAccountManager().mergeOsAccountsForRealms(sourceRealm, destRealm, trans);

		// Update the sourceRealm realm
		CaseDbConnection connection = trans.getConnection();
		try (Statement statement = connection.createStatement()) {
			String updateStr = "UPDATE tsk_os_account_realms SET db_status = " + OsAccountRealm.RealmDbStatus.MERGED.getId() 
					+ ", merged_into = " + destRealm.getRealmId()
					+ ", realm_signature = '" + makeMergedRealmSignature() + "' "
					+ " WHERE id = " + sourceRealm.getRealmId();
			connection.executeUpdate(statement, updateStr);
		} catch (SQLException ex) {
			throw new TskCoreException ("Error updating status of realm with id: " + sourceRealm.getRealmId(), ex);
		}
		
		// Update the destination realm if it doesn't have the name or addr set and the source realm does
		if (!destRealm.getRealmAddr().isPresent() && sourceRealm.getRealmAddr().isPresent()) {
			updateRealm(destRealm, sourceRealm.getRealmAddr().get(), null, trans.getConnection());
		} else if (destRealm.getRealmNames().isEmpty() && !sourceRealm.getRealmNames().isEmpty()) {
			updateRealm(destRealm, null, sourceRealm.getRealmNames().get(0), trans.getConnection());
		}
	}
	
	/**
	 * Get all realms associated with the given host.
	 * 
	 * @param host       The host.
	 * @param connection The current database connection.
	 * 
	 * @return List of realms for the given host.
	 * 
	 * @throws TskCoreException 
	 */
	List<OsAccountRealm> getRealmsByHost(Host host, CaseDbConnection connection) throws TskCoreException {
		List<OsAccountRealm> results = new ArrayList<>();
		String queryString = REALM_QUERY_STRING
			+ " WHERE realms.scope_host_id = " + host.getHostId();
		
		db.acquireSingleUserCaseReadLock();
		try (	Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {
			while (rs.next()) { 
				results.add(resultSetToAccountRealm(rs));
			} 
			return results;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error gettings realms for host with id = " + host.getHostId()), ex);
		}
		finally {
			db.releaseSingleUserCaseReadLock();
		}
	}
	
	/**
	 * Status of a realm update.
	 */
	public enum OsRealmUpdateStatus {

		NO_CHANGE,	/// no change was made to account.
		UPDATED,	/// account was updated
		MERGED		/// account update triggered a merge
	}
	
	/**
	 * Container to encapsulate the status returned by the realm update api, and
	 * the updated realm.
	 */
	public final static class OsRealmUpdateResult {
		
		private final OsRealmUpdateStatus updateStatus;
		private final OsAccountRealm updatedRealm;
		
		OsRealmUpdateResult(OsRealmUpdateStatus updateStatus, OsAccountRealm updatedRealm) {
			this.updateStatus = updateStatus;
			this.updatedRealm = updatedRealm;
		}

		public OsRealmUpdateStatus getUpdateStatus() {
			return updateStatus;
		}

		public Optional<OsAccountRealm> getUpdatedRealm() {
			return Optional.ofNullable(updatedRealm);
		}
	}
}
