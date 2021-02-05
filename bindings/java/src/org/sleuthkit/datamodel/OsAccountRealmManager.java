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
import java.util.logging.Level;
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
	 * Create the realm with the given name and scope for the given host. If a
	 * realm with same name already exists, then the existing realm is returned.
	 *
	 * @param realmName Realm name.
	 * @param host      Host that realm reference was found on. May be null if
	 *                  the realm is a domain and not host-specific.
	 *
	 * @return OsAccountRealm Realm.
	 *
	 * @throws TskCoreException If there is an error creating the realm.
	 */
	public OsAccountRealm createRealmByName(String realmName, Host host) throws TskCoreException {
		
		if (Strings.isNullOrEmpty(realmName)) {
			throw new IllegalArgumentException("A realm name is required.");
		}
		
		try (CaseDbConnection connection = this.db.getConnection()) {
			return createRealm(realmName, null, realmName, host, ScopeConfidence.KNOWN, connection);
		} catch (SQLException ex) {
			// Create may have failed if the realm already exists. try to get the realm by name.
			try (CaseDbConnection connection = this.db.getConnection()) {
				Optional<OsAccountRealm >accountRealm = this.getRealmByName(realmName, host, connection);
				if (accountRealm.isPresent()) {
					return accountRealm.get();
				} else {
					throw new TskCoreException(String.format("Error creating realm with name = %s and host name = %s", realmName, (host != null ? host.getName() : "null")), ex);
				}
			}
		}
	}

	/**
	 * Get the realm with the given name and specified host.
	 * 
	 * @param realmName Realm name.
	 * @param host Host for realm, may be null.
	 * @param transaction Transaction to use for database connection.
	 * 
	 * @return OsAccountRealm, Optional.empty  if no matching realm is found.
	 *
	 * @throws TskCoreException If there is an error creating the realm.
	 */
	public Optional<OsAccountRealm> getRealmByName(String realmName, Host host, CaseDbTransaction transaction) throws TskCoreException {
		
		return this.getRealmByName(realmName, host, transaction.getConnection());
	}
	
	
	/**
	 * Create realm for the given Windows SID. The input SID is a user/group
	 * SID. The domain SID is extracted from this incoming SID. If a realm
	 * already exists for the given user/group SID, the existing realm is
	 * returned.
	 * 
	 * @param sid  User/group SID.
	 * @param host Host for realm, may be null.
	 * 
	 * @return OsAccountRealm.
	 * 
	 * @throws TskCoreException If there is an error creating the realm.
	 */
	public OsAccountRealm createRealmByWindowsSid(String sid, Host host) throws TskCoreException {

		if (Strings.isNullOrEmpty(sid)) {
			throw new IllegalArgumentException("A SID is required.");
		}
		
		// get subAuthority sid
		String subAuthorityId = getSubAuthorityId(sid);
		
		// RAMAN TBD: can the SID be parsed in some way to determine local vs domain ??
			
		try (CaseDbConnection connection = this.db.getConnection()) {
			return createRealm(null, subAuthorityId, subAuthorityId, host, OsAccountRealm.ScopeConfidence.INFERRED, connection);
		} catch (SQLException ex) {
			// Create may have failed if the realm already exists. try to get the realm by addr.
			try (CaseDbConnection connection = this.db.getConnection()) {
				Optional<OsAccountRealm >accountRealm = this.getRealmByAddr(subAuthorityId, host, connection);
				if (accountRealm.isPresent()) {
					return accountRealm.get();
				} else {
					throw new TskCoreException(String.format("Error creating realm with address = %s", subAuthorityId), ex);
				}
			}
		}
		
	}
	
	/**
	 * Get the realm for the given user/group SID. The input SID is a user/group
	 * SID. The domain SID is extracted from this incoming SID.
	 * 
	 * @param sid         User SID.
	 * @param host        Host for realm, may be null.
	 * @param transaction Transaction to use for database connection.
	 * 
	 * @return Optional with OsAccountRealm, Optional.empty if no realm found with matching real address.
	 * 
	 * @throws TskCoreException
	 */
	public Optional<OsAccountRealm> getRealmByWindowsSid(String sid, Host host, CaseDbTransaction transaction) throws TskCoreException {
		
		// get subAuthority sid
		String subAuthorityId = getSubAuthorityId(sid);
		
		CaseDbConnection connection = transaction.getConnection();
		return this.getRealmByAddr(subAuthorityId, host, connection);
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
		
		// If a host is specified, we want to match the realm with matching name and specified host, or a realm with matching name and no host.
		// If no host is specified, then we return the first realm with matching name.
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
	 * @param realmName       Realm name, may be null.
	 * @param realmAddr       SID or some other identifier. May be null if name
	 *                        is not null.
	 * @param signature       Signature, either the address or the name.
	 * @param host            Host, if the realm is host scoped. Can be null
	 *                        realm is domain scoped.
	 * @param scopeConfidence Confidence in realm scope.
	 *
	 *
	 * @param connection      DB connection to use.
	 *
	 * @return OsAccountRealm Realm just created.
	 *
	 * @throws SQLException     If there is an SQL error in creating realm.
	 * @throws TskCoreException If there is an internal error.
	 */
	private OsAccountRealm createRealm(String realmName, String realmAddr, String signature, Host host, OsAccountRealm.ScopeConfidence scopeConfidence,  CaseDbConnection connection) throws TskCoreException, SQLException {
		
		db.acquireSingleUserCaseWriteLock();
		try {
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
				return  new OsAccountRealm(rowId, realmName, realmAddr, signature, host, scopeConfidence);
			}
		}  finally {
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
			if (org.apache.commons.lang3.StringUtils.countMatches(sid, "-") < 5 ) {
			throw new IllegalArgumentException(String.format("Invalid SID %s for a host/domain", sid));
		}
		String subAuthorityId = sid.substring(0, sid.lastIndexOf('-'));
		
		return subAuthorityId;
	}
}
