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
import java.util.logging.Level;
import java.util.logging.Logger;
import org.sleuthkit.datamodel.OsAccountRealm.RealmNameType;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbConnection;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbTransaction;


/**
 * Create/Retrieve/Update OS account realms.
 * 
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
	 * 
	 * @param realmName Realm Name.
	 * @param nameType Realm name type.
	 * @param uniqueId Unique sid/id for realm. May be null.
	 * @param host Host, if this realm comprises of a single host. May be null.
	 * @param transaction Transaction to use for database operation.
	 * 
	 * @return OsAccountRealm
	 */
//	OsAccountRealm addRealm(String realmName, OsAccountRealm.RealmNameType nameType, String uniqueId,  Host host, CaseDbTransaction transaction) throws TskCoreException {
//		
//		CaseDbConnection connection = transaction.getConnection();
//		return createRealm(realmName, nameType,  uniqueId, host, connection );
//	}
	
	
	/**
	 * Get the realm with the given name and the given host.
	 * Creates one if one does not exist.
	 * 
	 * @param realmName Realm name.
	 * @param host Host for realm, may be null.
	 * @param transaction Transaction to use for connection.
	 * 
	 * @return OsAccountRealm Realm.
	 * 
	 * @throws TskCoreException 
	 */
	OsAccountRealm getOrCreateRealmByName(String realmName, Host host, CaseDbTransaction transaction) throws TskCoreException {
		
		if (Strings.isNullOrEmpty(realmName)) {
			throw new IllegalArgumentException("A realm name is required.");
		}
		
		CaseDbConnection connection = transaction.getConnection();
		
		OsAccountRealm accountRealm = getRealmByName(realmName, host, connection );
		if (accountRealm != null) {
			return accountRealm;
		}
		
		// couldn't find a matching realm, create one.
		return createRealm(realmName, RealmNameType.EXPRESSED, null, host, connection); 
	}

	
	/**
	 * Get or create with the given Windows SID. 
	 * 
	 * @param sid	SID.
	 * @param host	Host, if the realm is restricted to a single host. May be null.
	 * @param transaction Transaction.
	 * 
	 * @return Realm.
	 * @throws TskCoreException .
	 */
	OsAccountRealm getOrCreateRealmByWindowsSid(String sid, Host host, CaseDbTransaction transaction) throws TskCoreException {

		// get subAuthority sid
		if (org.apache.commons.lang3.StringUtils.countMatches(sid, "-") < 5 ) {
			throw new IllegalArgumentException(String.format("Invalid SID %s for a host/domain", sid));
		}
		String subAuthorityId = sid.substring(0, sid.lastIndexOf('-'));
		
		CaseDbConnection connection = transaction.getConnection();
			
		// RAMAN TBD: can the SID be parsed in some way to determine local vs domain ??
		
		// check if realm exists with this unique id
		OsAccountRealm realm = getRealmByAddr(subAuthorityId, host, connection);
		if (realm != null) {	
			return realm;
		}
		
		// don't have an existing realm with this ID, create one.
		return createRealm("Unknown Domain Name", OsAccountRealm.RealmNameType.INFERRED, subAuthorityId, host, connection);
	}
	
	
	/**
	 * Updates the realm name and name type for the the specified realm id.
	 * 
	 * @param realmId Row id of realm to update.
	 * @param realmName Realm name.
	 * @param nameType Name type.
	 * @param transaction Transaction to use. 
	 * 
	 * @return OsAccountRealm
	 * @throws TskCoreException 
	 */
	OsAccountRealm updateRealmName(long realmId, String realmName, OsAccountRealm.RealmNameType nameType, CaseDbTransaction transaction) throws TskCoreException {
		
		CaseDbConnection connection = transaction.getConnection();
		
		db.acquireSingleUserCaseWriteLock();
		try {
			String updateSQL = "UPDATE tsk_os_account_realms SET name = ?, name_type = ? WHERE id = ?";
			PreparedStatement preparedStatement = connection.getPreparedStatement(updateSQL, Statement.NO_GENERATED_KEYS);
			preparedStatement.clearParameters();

			preparedStatement.setString(1, realmName);
			preparedStatement.setInt(2, nameType.getId());
			preparedStatement.setLong(3, realmId);
			
			connection.executeUpdate(preparedStatement);

			return getRealm(realmId, connection );
		} catch (SQLException ex) {
			LOGGER.log(Level.SEVERE, null, ex);
			throw new TskCoreException(String.format("Error updating realm with name = %s, id = %d", realmName, realmId), ex);
		} finally {
			db.releaseSingleUserCaseWriteLock();
		}
	}
	
	private final String REALM_QUERY_STRING = "SELECT realms.id as realm_id, realms.name as realm_name,"
			+ " realms.realm_addr as realm_addr, realms.host_id, realms.name_type, "
			+ " hosts.id, hosts.name as host_name "
			+ " FROM tsk_os_account_realms as realms"
			+ "		LEFT JOIN tsk_hosts as hosts"
			+ " ON realms.host_id = hosts.id";
	
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
			}

			return accountRealm;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error running the realms query = %s", queryString), ex);
		}
	}
	
	/**
	 * Get the realm with the given realm addr.
	 * 
	 * @param uniqueId Realm uniqueId/SID.
	 * @param host Host for realm, may be null.
	 * @param connection Database connection to use.
	 * 
	 * @return OsAccountRealm.
	 * @throws TskCoreException.
	 */
	private OsAccountRealm getRealmByAddr(String realmAddr, Host host, CaseDbConnection connection) throws TskCoreException {
		
		String whereHostClause = (host == null) 
							? " 1 = 1 " 
							: " ( realms.host_id = " + host.getId() + " OR realms.host_id IS NULL) ";
		String queryString = REALM_QUERY_STRING
						+ " WHERE LOWER(realms.realm_addr) = LOWER('"+ realmAddr + "') "
						+ " AND " + whereHostClause
						+ " ORDER BY realms.host_id IS NOT NULL, realms.host_id";	// ensure that non null host_id is at the front
				    
		try (	Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			OsAccountRealm accountRealm = null;
			if (rs.next()) {
				Host realmHost = null;
				long hostId = rs.getLong("host_id");
				if (!rs.wasNull()) {
					if (host != null ) {
						realmHost = host; // exact match on given host
					} else {
						realmHost = new Host(hostId, rs.getString("host_name"));
					}
				}
				
				accountRealm = new OsAccountRealm(rs.getLong("realm_id"), rs.getString("realm_name"),
												RealmNameType.fromID(rs.getInt("name_type")),
												rs.getString("realm_addr"), realmHost);
			} 
			return accountRealm;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error running the realms query = %s", queryString), ex);
		}
	}
	
	/**
	 * Get the realm with the given name and specified host.
	 * 
	 * @param realmName Realm name.
	 * @param host Host for realm, may be null.
	 * @param connection Database connection to use.
	 * 
	 * @return OsAccountRealm, Null if no matching realm is found.
	 * @throws TskCoreException.
	 */
	private OsAccountRealm getRealmByName(String realmName, Host host, CaseDbConnection connection) throws TskCoreException {
		
		String whereHostClause = (host == null) 
							? " 1 = 1 " 
							: " ( realms.host_id = " + host.getId() + " OR realms.host_id IS NULL ) ";
		String queryString = REALM_QUERY_STRING
				+ " WHERE LOWER(realms.name) = LOWER('" + realmName + "')"
				+ " AND " + whereHostClause 
				+ " ORDER BY realms.host_id IS NOT NULL, realms.host_id";	// ensure that non null host_id are at the front
				
		try (Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {
			
			OsAccountRealm accountRealm = null;
			if (rs.next()) {
				Host realmHost = null;
				long hostId = rs.getLong("host_id");
				if (!rs.wasNull()) {
					if (host != null ) {
						realmHost = host;
					} else {
						realmHost = new Host(hostId, rs.getString("host_name"));
					}
				}
				
				accountRealm = new OsAccountRealm(rs.getLong("realm_id"), rs.getString("realm_name"),
												RealmNameType.fromID(rs.getInt("name_type")),
												rs.getString("realm_addr"), realmHost);
				
			} 
			return accountRealm;
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
		
		long hostId = rs.getLong("host_id");
		Host realmhost = null;
		if (!rs.wasNull()) {
			realmhost = new Host(hostId, rs.getString("host_name"));
		}

		return new OsAccountRealm(rs.getLong("realm_id"), rs.getString("realm_name"),
				RealmNameType.fromID(rs.getInt("name_type")),
				rs.getString("realm_addr"), realmhost);
	}
	
	/**
	 * Get all realms.
	 * 
	 * @return Collection of OsAccountRealm
	 */
//	Collection<OsAccountRealm> getRealms() throws TskCoreException {
//		String queryString = "SELECT realms.id as realm_id, realms.name as realm_name, realms.realm_addr as realm_addr, realms.host_id, realms.name_type, "
//				+ " hosts.id, hosts.name as host_name "
//				+ " FROM tsk_os_account_realms as realms"
//				+ "		LEFT JOIN tsk_hosts as hosts"
//				+ " ON realms.host_id = hosts.id";
//
//		try (CaseDbConnection connection = this.db.getConnection();
//				Statement s = connection.createStatement();
//				ResultSet rs = connection.executeQuery(s, queryString)) {
//
//			ArrayList<OsAccountRealm> accountRealms = new ArrayList<>();
//			while (rs.next()) {
//				long hostId = rs.getLong("host_id");
//				Host host = null;
//				if (!rs.wasNull()) {
//					host = new Host(hostId, rs.getString("host_name"));
//				}
//
//				accountRealms.add(new OsAccountRealm(rs.getLong("realm_id"), rs.getString("realm_name"),
//						RealmNameType.fromID(rs.getInt("name_type")),
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
	 * @param realmName  Realm name.
	 * @param nameType   Name type.
	 * @param realmAddr  SID or some other identifier. May be null.
	 * @param host       Host, if this realm encompasses a single host. May be
	 *                   null.
	 * @param connection DB connection to use.
	 *
	 * @return OsAccountRealm Realm just created.
	 *
	 * @throws TskCoreException
	 */
	private OsAccountRealm createRealm(String realmName, OsAccountRealm.RealmNameType nameType, String realmAddr,  Host host, CaseDbConnection connection) throws TskCoreException {
		
		db.acquireSingleUserCaseWriteLock();
		try {
			String realmInsertSQL = "INSERT INTO tsk_os_account_realms(name, realm_addr, host_id, name_type)"
					+ " VALUES (?, ?, ?, ?)"; // NON-NLS

			PreparedStatement preparedStatement = connection.getPreparedStatement(realmInsertSQL, Statement.RETURN_GENERATED_KEYS);
			preparedStatement.clearParameters();

			preparedStatement.setString(1, realmName);
			preparedStatement.setString(2, realmAddr);
			if (host != null) {
				preparedStatement.setLong(3, host.getId());
			} else {
				preparedStatement.setNull(3, java.sql.Types.BIGINT);
			}
			preparedStatement.setInt(4, nameType.getId());
			
			connection.executeUpdate(preparedStatement);

			// Read back the row id
			try (ResultSet resultSet = preparedStatement.getGeneratedKeys();) {
				if (resultSet.next()) {
					long rowId = resultSet.getLong(1); ;//last_insert_rowid()
					return  new OsAccountRealm(rowId, realmName, nameType, realmAddr, host);
				} else {
					throw new SQLException("Error executing  " + realmInsertSQL);
				}
			}
		} catch (SQLException ex) {
			LOGGER.log(Level.SEVERE, null, ex);
			throw new TskCoreException(String.format("Error adding realm with name = %s", realmName), ex);
		} finally {
			db.releaseSingleUserCaseWriteLock();
		}
	}
}