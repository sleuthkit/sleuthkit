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
import java.util.Optional;
import java.util.logging.Logger;
import org.sleuthkit.datamodel.OsAccountRealm.ScopeConfidence;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbConnection;


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
	 * Create realm for the Windows. The input SID is a user/group SID. The
	 * domain SID is extracted from this incoming SID.
	 *
	 * @param accountSid    User/group SID. May be null only if name is not null.
	 * @param realmName     Realm name. May be null only if SID is not null.
	 * @param referringHost Host where realm reference is found.
	 * @param realmScope    Scope of realm.
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
				boolean isHostRealmKnown = this.isHostRealmKnown(referringHost);
				if (isHostRealmKnown) {
					scopeHost = null;	// the realm does not scope to the referring host since it already has one.
					scopeConfidence = OsAccountRealm.ScopeConfidence.KNOWN;
				} else {
					scopeHost = referringHost;
					scopeConfidence = OsAccountRealm.ScopeConfidence.INFERRED;
				}
				break;

		}
		
		// RAMAN TBD: can the SID be parsed in some way to determine local vs domain ??
		
		// get subAuthority sid
		String realmAddr = null;
		if (!Strings.isNullOrEmpty(accountSid)) {
			realmAddr = getSubAuthorityId(accountSid);
		}
		
		String signature = getRealmSignature(realmAddr, realmName);
		
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
		
		// If a accountSID is provided , search for realm by addr.
		if (!Strings.isNullOrEmpty(accountSid)) {
			// get realm addr from the account SID.
			String subAuthorityId = getSubAuthorityId(accountSid);
			return this.getRealmByAddr(subAuthorityId, referringHost, connection);
		}

		// No realm addr, Search  by name	
		return this.getRealmByName(realmName, referringHost, connection);
	}
	
	/**
	 * Updates the realm name and name type for the the specified realm id.
	 * 
	 * @param realmId Row id of realm to update.
	 * @param realmName Realm name.
	 * @param nameType Name type.
	 * 
	 * @return OsAccountRealm
	 * @throws TskCoreException 
	 */
	OsAccountRealm updateRealmName(long realmId, String realmName, OsAccountRealm.ScopeConfidence nameType) throws TskCoreException {
		
		db.acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = db.getConnection())  {
			String updateSQL = "UPDATE tsk_os_account_realms SET realm_name = ?, scope_confidence = ? WHERE id = ?";
			PreparedStatement preparedStatement = connection.getPreparedStatement(updateSQL, Statement.NO_GENERATED_KEYS);
			preparedStatement.clearParameters();

			preparedStatement.setString(1, realmName);
			preparedStatement.setInt(2, nameType.getId());
			preparedStatement.setLong(3, realmId);
			
			connection.executeUpdate(preparedStatement);

			return getRealm(realmId, connection );
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error updating realm with name = %s, id = %d", realmName, realmId), ex);
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
														queryString, realmAddr, (host != null ? host.getName() : "Null")  ), ex);
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
		}
	}
	
	/**
	 * Check is there is any realm with a known host scope matching the given host.  
	 * 
	 * @param host Host for which to look for a realm.
	 * 
	 * @return True if there exists a a realm with the host scope matching the host. False otherwise
	 */
	private boolean isHostRealmKnown(Host host) throws TskCoreException {
	
		String queryString = REALM_QUERY_STRING
				+ " WHERE realms.scope_host_id = " + host.getId()
				+ " AND realms.scope_confidence = " + OsAccountRealm.ScopeConfidence.KNOWN.getId();

		try (CaseDbConnection connection = this.db.getConnection();
				Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {
			
			// return true if there is any match.
			return rs.next();
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting account realm for with host = %s", host.getName()), ex);
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
	 * Gets the sub authority id from the given SID.
	 * 
	 * @param sid SID
	 * 
	 * @return Sub-authority id string.
	 */
	private String getSubAuthorityId(String sid) {
		
		// RAMAN TBD: this fails for short WellKnown SIDs
		if (org.apache.commons.lang3.StringUtils.countMatches(sid, "-") < 5 ) {
			throw new IllegalArgumentException(String.format("Invalid SID %s for a host/domain", sid));
		}
		String subAuthorityId = sid.substring(0, sid.lastIndexOf('-'));
		
		return subAuthorityId;
	}
	
	/**
	 * Determines the realm signature based on given realm address and name.
	 *
	 * If the address known, it is used for unique signature, otherwise the name
	 * is used.
	 *
	 * @param realmAddr Realm address.
	 * @param realmName Realm name.
	 * 
	 * @return Realm Signature.
	 */
	static String getRealmSignature(String realmAddr, String realmName) {
		
		if (!Strings.isNullOrEmpty(realmAddr)) {
			return realmAddr;
		} else if (!Strings.isNullOrEmpty(realmName)) {
			return realmName;
		} else {
			throw new IllegalArgumentException(String.format("Realm address and name can't both be null."));
		}
	}
}
