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
import com.google.common.collect.ImmutableSet;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Logger;
import org.sleuthkit.datamodel.OsAccountRealm.ScopeConfidence;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbConnection;


/**
 * Create/Retrieve/Update OS account realms. Realms represent either an individual
 * host with local accounts or a domain. 
 */
public final class OsAccountRealmManager {
	
	// Some windows SID indicate special account.
	// These should be handled differently from regular user accounts.
	private static final Set<String> SPECIAL_SIDS = ImmutableSet.of(
			"S-1-5-18",	// LOCAL_SYSTEM_ACCOUNT
			"S-1-5-19", // LOCAL_SERVICE_ACCOUNT
			"S-1-5-20" // NETWORK_SERVICE_ACCOUNT
	);
	private static final Set<String> SPECIAL_SID_PREFIXES = ImmutableSet.of(
			"S-1-5-80",	// Virtual Service accounts
			"S-1-5-82", // AppPoolIdentity Virtual accounts. 
			"S-1-5-83", // Virtual Machine  Virtual Accounts.
			"S-1-5-90", // Windows Manager Virtual Accounts. 
			"S-1-5-96" // Font Drive Host Virtual Accounts.
			);
	
	// Special Windows Accounts with short SIDS are given a special realm "address".
	private final static String SPECIAL_WINDOWS_REALM_ADDR = "SPECIAL_WINDOWS_ACCOUNTS";
	
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
	 * Create realm based on Windows information. The input SID is a user/group SID. The
	 * domain SID is extracted from this incoming SID.
	 *
	 * @param accountSid    User/group SID. May be null only if name is not null.
	 * @param realmName     Realm name. May be null only if SID is not null.
	 * @param referringHost Host where realm reference is found.
	 * @param realmScope    Scope of realm. Use UNKNOWN if you are not sure and the 
	 *                      method will try to detect the correct scope. 
	 *
	 * @return OsAccountRealm.
	 * 
	 * @throws TskCoreException If there is an error creating the realm.
	 */
	public OsAccountRealm createWindowsRealm(String accountSid, String realmName, Host referringHost, OsAccountRealm.RealmScope realmScope) throws TskCoreException {

		if (realmScope == null) {
			throw new IllegalArgumentException("RealmScope cannot be null. Use UNKNOWN if scope is not known.");
		}
		if (referringHost == null) {
			throw new IllegalArgumentException("A referring host is required to create a realm.");
		}
		if (Strings.isNullOrEmpty(accountSid) && Strings.isNullOrEmpty(realmName)) {
			throw new IllegalArgumentException("Either an address or a name is required to create a realm.");
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
			realmAddr = getWindowsRealmAddress(accountSid);
			
			// if the account is special windows account, create a local realm for it.
			if (realmAddr.equals(SPECIAL_WINDOWS_REALM_ADDR)) {
				scopeHost = referringHost;
				scopeConfidence = OsAccountRealm.ScopeConfidence.KNOWN;
			}
		}
		
		String signature = makeRealmSignature(realmAddr, realmName, scopeHost);
		
		// create a realm
		return createRealm(realmName, realmAddr, signature, scopeHost, scopeConfidence);
	}
	
	/**
	 * Get a windows realm by the account SID, or the domain name.
	 * The input SID is an user/group account SID. The domain SID is extracted from this incoming SID.
	 * 
	 * @param accountSid  Account SID, may be null.
	 * @param realmName   Realm name, may be null only if accountSid is not
	 *                    null.
	 * @param referringHost Referring Host.
	 * 
	 * @return Optional with OsAccountRealm, Optional.empty if no matching realm is found.
	 * 
	 * @throws TskCoreException
	 */
	public Optional<OsAccountRealm> getWindowsRealm(String accountSid, String realmName, Host referringHost) throws TskCoreException {
		
		if (referringHost == null) {
			throw new IllegalArgumentException("A referring host is required get a realm.");
		}
		
		// need at least one of the two, the addr or name to look up
		if (Strings.isNullOrEmpty(accountSid) && Strings.isNullOrEmpty(realmName)) {
			throw new IllegalArgumentException("Realm address or name is required get a realm.");
		}
		
		try (CaseDbConnection connection = this.db.getConnection()) {
			return getWindowsRealm(accountSid, realmName, referringHost, connection);
		}
	}
	
	
	/**
	 * Get a windows realm by the account SID, or the domain name.
	 * The input SID is an user/group account SID. The domain SID is extracted from this incoming SID.
	 * 
	 * @param accountSid  Account SID, may be null.
	 * @param realmName   Realm name, may be null only if accountSid is not
	 *                    null.
	 * @param referringHost Referring Host.
	 * 
	 * @return Optional with OsAccountRealm, Optional.empty if no matching realm is found.
	 * 
	 * @throws TskCoreException
	 */
	Optional<OsAccountRealm> getWindowsRealm(String accountSid, String realmName, Host referringHost, CaseDbConnection connection) throws TskCoreException {
		
		if (referringHost == null) {
			throw new IllegalArgumentException("A referring host is required get a realm.");
		}
		
		// need at least one of the two, the addr or name to look up
		if (Strings.isNullOrEmpty(accountSid) && Strings.isNullOrEmpty(realmName)) {
			throw new IllegalArgumentException("Realm address or name is required get a realm.");
		}
		
		// If an accountSID is provided search for realm by addr.
		if (!Strings.isNullOrEmpty(accountSid)) {
			// get realm addr from the account SID.
			String realmAddr = getWindowsRealmAddress(accountSid);
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
	 * Updates the specified realm in the database.
	 * 
	 * @param realm Realm to update.
	 * 
	 * @return OsAccountRealm Updated realm.
	 * 
	 * @throws TskCoreException 
	 */
	OsAccountRealm updateRealm(OsAccountRealm realm) throws TskCoreException {
		
		// do nothing if the realm is not dirty.
		if (!realm.isDirty()) {
			return realm;
		}
		
		db.acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = db.getConnection())  {
			// We only alow realm addr, name and signature to be updated at this time. 
			String updateSQL = "UPDATE tsk_os_account_realms SET realm_name = ?,  realm_addr = ?, realm_signature = ? WHERE id = ?";
			PreparedStatement preparedStatement = connection.getPreparedStatement(updateSQL, Statement.NO_GENERATED_KEYS);
			preparedStatement.clearParameters();

			preparedStatement.setString(1, realm.getRealmName().orElse(null));
			preparedStatement.setString(2, realm.getRealmAddr().orElse(null));
			preparedStatement.setString(3, realm.getSignature());
			
			preparedStatement.setLong(4, realm.getId());
			
			connection.executeUpdate(preparedStatement);
			
			realm.resetDirty();
			return realm;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error updating realm with id = %d, name = %s, addr = %s", realm.getId(), realm.getRealmName().orElse("Null"), realm.getRealmAddr().orElse("Null") ), ex);
		} finally {
			db.releaseSingleUserCaseWriteLock();
		}
	}
	
	private final static String REALM_QUERY_STRING = "SELECT realms.id as realm_id, realms.realm_name as realm_name,"
			+ " realms.realm_addr as realm_addr, realms.realm_signature as realm_signature, realms.scope_host_id, realms.scope_confidence, "
			+ " hosts.id, hosts.name as host_name "
			+ " FROM tsk_os_account_realms as realms"
			+ "		LEFT JOIN tsk_hosts as hosts"
			+ " ON realms.scope_host_id = hosts.id";
	
	/**
	 * Get the realm from the given row id. 
	 * 
	 * @param id Realm row id.
	 * @param connection Database connection to use.
	 * 
	 * @return Realm. 
	 * @throws TskCoreException 
	 */
	OsAccountRealm getRealm(long id, CaseDbConnection connection) throws TskCoreException {
		
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
							: " ( realms.scope_host_id = " + host.getId() + " OR realms.scope_host_id IS NULL) ";
		String queryString = REALM_QUERY_STRING
						+ " WHERE LOWER(realms.realm_addr) = LOWER('"+ realmAddr + "') "
						+ " AND " + whereHostClause
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
												realmHost, ScopeConfidence.fromID(rs.getInt("scope_confidence")));
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
				: " ( realms.scope_host_id = " + host.getId() + " OR realms.scope_host_id IS NULL ) ";
		String queryString = REALM_QUERY_STRING
				+ " WHERE LOWER(realms.realm_name) = LOWER('" + realmName + "')"
				+ " AND " + whereHostClause
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
												realmHost, ScopeConfidence.fromID(rs.getInt("scope_confidence")));
				
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
				+ " WHERE realms.scope_host_id = " + host.getId()
				+ " AND realms.scope_confidence = " + OsAccountRealm.ScopeConfidence.KNOWN.getId()
				+ " AND LOWER(realms.realm_addr) <> LOWER('"+ SPECIAL_WINDOWS_REALM_ADDR + "') ";

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
												realmHost, ScopeConfidence.fromID(rs.getInt("scope_confidence")));
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
	private OsAccountRealm createRealm(String realmName, String realmAddr, String signature, Host host, OsAccountRealm.ScopeConfidence scopeConfidence) throws TskCoreException {

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
				preparedStatement.setLong(4, host.getId());
			} else {
				preparedStatement.setNull(4, java.sql.Types.BIGINT);
			}
			preparedStatement.setInt(5, scopeConfidence.getId());

			connection.executeUpdate(preparedStatement);

			// Read back the row id
			try (ResultSet resultSet = preparedStatement.getGeneratedKeys();) {
				long rowId = resultSet.getLong(1); // last_insert_rowid()
				return new OsAccountRealm(rowId, realmName, realmAddr, signature, host, scopeConfidence);
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
	 * Get the windows realm address from the given SID.
	 * 
	 * For all regular account SIDs, the realm address is the sub-authority SID.
	 * For special Windows account the realm address is a special address.
	 * 
	 * @param sid SID
	 * 
	 * @return Realm address for the SID.
	 */
	private String getWindowsRealmAddress(String sid) {
		
		String realmAddr;
		
		if (isWindowsSpecialSid(sid)) {
			realmAddr = SPECIAL_WINDOWS_REALM_ADDR;
		} else {
			// regular SIDs should have at least 5 components: S-1-x-y-z
			if (org.apache.commons.lang3.StringUtils.countMatches(sid, "-") < 4) {
				throw new IllegalArgumentException(String.format("Invalid SID %s for a host/domain", sid));
			}
			// get the sub authority SID
			realmAddr = sid.substring(0, sid.lastIndexOf('-'));
		}

		return realmAddr;
	}
	
	/**
	 * Checks if the given SID is a special Windows SID.
	 * 
	 * @param sid SID to check.
	 * 
	 * @return True if the SID is a Windows special SID, false otherwise 
	 */
	private boolean isWindowsSpecialSid(String sid) {
		if (SPECIAL_SIDS.contains(sid)) {
			return true;
		}
		for (String specialPrefix: SPECIAL_SID_PREFIXES) {
			if (sid.startsWith(specialPrefix)) {
				return true;
			}
		}
		return false;
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
	 */
	static String makeRealmSignature(String realmAddr, String realmName, Host scopeHost) {

		// need at least one of the two, the addr or name to look up
		if (Strings.isNullOrEmpty(realmAddr) && Strings.isNullOrEmpty(realmName)) {
			throw new IllegalArgumentException("Realm address and name can't both be null.");
		}
		
		String signature = String.format("%s_%s", !Strings.isNullOrEmpty(realmAddr) ?  realmAddr : realmName,
												scopeHost != null ? scopeHost.getId() : "DOMAIN");
		return signature;
	}
}
