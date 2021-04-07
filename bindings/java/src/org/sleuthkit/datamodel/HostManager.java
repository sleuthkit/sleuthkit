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
import java.sql.Savepoint;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.sleuthkit.datamodel.Host.HostDbStatus;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbConnection;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbTransaction;
import org.sleuthkit.datamodel.TskEvent.HostsChangedTskEvent;
import org.sleuthkit.datamodel.TskEvent.HostsDeletedTskEvent;

/**
 * Responsible for creating/updating/retrieving Hosts.
 *
 */
public final class HostManager {

	private final SleuthkitCase db;

	/**
	 * Construct a HostManager for the given SleuthkitCase.
	 *
	 * @param skCase The SleuthkitCase
	 *
	 */
	HostManager(SleuthkitCase skCase) {
		this.db = skCase;
	}

	/**
	 * Create a host with specified name. If a host already exists with the
	 * given name, it returns the existing host.
	 *
	 * @param name	Host name.
	 *
	 * @return Host with the specified name.
	 *
	 * @throws TskCoreException
	 */
	public Host newHost(String name) throws TskCoreException {
		CaseDbTransaction transaction = db.beginTransaction();
		try {
			Host host = newHost(name, transaction);
			transaction.commit();
			transaction = null;
			return host;
		} finally {
			if (transaction != null) {
				transaction.rollback();
			}
		}
	}

	/**
	 * Create a host with given name. If the host already exists, the existing
	 * host will be returned.
	 *
	 * NOTE: Whenever possible, create hosts as part of a single step
	 * transaction so that it can quickly determine a host of the same name
	 * already exists. If you call this as part of a multi-step
	 * CaseDbTransaction, then this method may think it can insert the host
	 * name, but then when it comes time to call CaseDbTransaction.commit(),
	 * there could be a uniqueness constraint violation and other inserts in the
	 * same transaction could have problems.
	 *
	 * This method should never be made public and exists only because we need
	 * to support APIs that do not take in a host and we must make one. Ensure
	 * that if you call this method that the host name you give will be unique.
	 *
	 * @param name  Host name that must be unique if this is called as part of a
	 *              multi-step transaction
	 * @param trans Database transaction to use.
	 *
	 * @return Newly created host.
	 *
	 * @throws TskCoreException
	 */
	Host newHost(String name, CaseDbTransaction trans) throws TskCoreException {
		// must have a name
		if (Strings.isNullOrEmpty(name)) {
			throw new TskCoreException("Illegal argument passed to createHost: Host name is required.");
		}

		CaseDbConnection connection = trans.getConnection();
		Savepoint savepoint = null;

		try {
			savepoint = connection.getConnection().setSavepoint();
			String hostInsertSQL = "INSERT INTO tsk_hosts(name) VALUES (?)"; // NON-NLS
			PreparedStatement preparedStatement = connection.getPreparedStatement(hostInsertSQL, Statement.RETURN_GENERATED_KEYS);

			preparedStatement.clearParameters();
			preparedStatement.setString(1, name);

			connection.executeUpdate(preparedStatement);

			// Read back the row id
			Host host = null;
			try (ResultSet resultSet = preparedStatement.getGeneratedKeys();) {
				if (resultSet.next()) {
					host = new Host(resultSet.getLong(1), name); //last_insert_rowid()
				} else {
					throw new SQLException("Error executing  " + hostInsertSQL);
				}
			}

			if (host != null) {
				trans.registerAddedHost(host);
			}
			return host;
		} catch (SQLException ex) {
			if (savepoint != null) {
				try {
					connection.getConnection().rollback(savepoint);
				} catch (SQLException ex2) {
					throw new TskCoreException(String.format("Error adding host with name = %s and unable to rollback", name), ex);
				}
			}

			// It may be the case that the host already exists, so try to get it.
			Optional<Host> optHost = getHostByName(name, connection);
			if (optHost.isPresent()) {
				return optHost.get();
			}
			throw new TskCoreException(String.format("Error adding host with name = %s", name), ex);
		}
	}

	/**
	 * Updates the name of the provided host.
	 *
	 * @param host The host to be updated.
	 * @param newName The new name of the host.
	 *
	 * @return The updated host.
	 *
	 * @throws TskCoreException
	 */
	public Host updateHostName(Host host, String newName) throws TskCoreException {
		if (host == null) {
			throw new TskCoreException("Illegal argument passed to updateHost: No host argument provided.");
		} else if (newName == null) {
			throw new TskCoreException(String.format("Illegal argument passed to updateHost: Host with id %d has no name", host.getHostId()));
		}

		long hostId = host.getHostId();
		Host updatedHost = null;
		db.acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = db.getConnection()) {
			// Don't update the name for non-active hosts
			String hostInsertSQL = "UPDATE tsk_hosts "
					+ "SET name = "
					+ "   CASE WHEN db_status = " + Host.HostDbStatus.ACTIVE.getId() + " THEN ? ELSE name END "
					+ "WHERE id = ?";

			PreparedStatement preparedStatement = connection.getPreparedStatement(hostInsertSQL, Statement.RETURN_GENERATED_KEYS);

			preparedStatement.clearParameters();
			preparedStatement.setString(1, newName);
			preparedStatement.setLong(2, hostId);

			connection.executeUpdate(preparedStatement);

			updatedHost = getHostById(hostId, connection).orElseThrow(()
					-> new TskCoreException((String.format("Error while fetching newly updated host with id: %d, "))));

		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error updating host with name = %s", newName), ex);
		} finally {
			db.releaseSingleUserCaseWriteLock();
		}

		if (updatedHost != null) {
			fireChangeEvent(updatedHost);
		}
		return updatedHost;
	}

	/**
	 * Delete a host. Name comparison is case-insensitive.
	 *
	 * @param name Name of the host to delete.
	 *
	 * @return The id of the deleted host or null if no host was deleted.
	 *
	 * @throws TskCoreException
	 */
	public Long deleteHost(String name) throws TskCoreException {
		if (name == null) {
			throw new TskCoreException("Illegal argument passed to deleteHost: Name provided must be non-null");
		}

		// query to check if there are any dependencies on this host.  If so, don't delete.
		String queryString = "SELECT COUNT(*) AS count FROM\n"
				+ "(SELECT obj_id AS id, host_id FROM data_source_info\n"
				+ "UNION\n"
				+ "SELECT id, scope_host_id AS host_id FROM tsk_os_account_realms\n"
				+ "UNION\n"
				+ "SELECT id, host_id FROM tsk_os_account_attributes\n"
				+ "UNION\n"
				+ "SELECT id, host_id FROM tsk_host_address_map) children\n"
				+ "INNER JOIN tsk_hosts h ON children.host_id = h.id WHERE LOWER(h.name)=LOWER(?)";

		String deleteString = "DELETE FROM tsk_hosts WHERE LOWER(name) = LOWER(?)";

		CaseDbTransaction trans = this.db.beginTransaction();
		try {
			// check if host has any child data sources.  if so, don't delete and throw exception.
			PreparedStatement query = trans.getConnection().getPreparedStatement(queryString, Statement.NO_GENERATED_KEYS);
			query.clearParameters();
			query.setString(1, name);
			try (ResultSet queryResults = query.executeQuery()) {
				if (queryResults.next() && queryResults.getLong("count") > 0) {
					throw new TskCoreException(String.format("Host with name '%s' has child data and cannot be deleted.", name));
				}
			}

			// otherwise, delete the host
			PreparedStatement update = trans.getConnection().getPreparedStatement(deleteString, Statement.RETURN_GENERATED_KEYS);
			update.clearParameters();
			update.setString(1, name);
			int numUpdated = update.executeUpdate();

			// get ids for deleted.
			Long hostId = null;

			if (numUpdated > 0) {
				try (ResultSet updateResult = update.getGeneratedKeys()) {
					if (updateResult.next()) {
						hostId = updateResult.getLong(1);
					}
				}
			}

			trans.commit();
			trans = null;

			fireDeletedEvent(new Host(hostId, name));
			return hostId;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error deleting host with name %s", name), ex);
		} finally {
			if (trans != null) {
				trans.rollback();
			}
		}
	}

	/**
	 * Get all data sources associated with a given host.
	 *
	 * @param host The host.
	 *
	 * @return The list of data sources corresponding to the host.
	 *
	 * @throws TskCoreException
	 */
	public List<DataSource> getDataSourcesForHost(Host host) throws TskCoreException {
		String queryString = "SELECT * FROM data_source_info WHERE host_id = " + host.getHostId();

		List<DataSource> dataSources = new ArrayList<>();
		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = this.db.getConnection();
				Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			while (rs.next()) {
				dataSources.add(db.getDataSource(rs.getLong("obj_id")));
			}

			return dataSources;
		} catch (SQLException | TskDataException ex) {
			throw new TskCoreException(String.format("Error getting data sources for host " + host.getName()), ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get active host with given name.
	 *
	 * @param name Host name to look for.
	 *
	 * @return Optional with host. Optional.empty if no matching host is found.
	 *
	 * @throws TskCoreException
	 */
	public Optional<Host> getHostByName(String name) throws TskCoreException {
		try (CaseDbConnection connection = db.getConnection()) {
			return getHostByName(name, connection);
		}
	}

	/**
	 * Get active host with given name.
	 *
	 * @param name       Host name to look for.
	 * @param connection Database connection to use.
	 *
	 * @return Optional with host. Optional.empty if no matching host is found.
	 *
	 * @throws TskCoreException
	 */
	private Optional<Host> getHostByName(String name, CaseDbConnection connection) throws TskCoreException {

		String queryString = "SELECT * FROM tsk_hosts"
				+ " WHERE LOWER(name) = LOWER(?)" 
				+ " AND db_status = " + Host.HostDbStatus.ACTIVE.getId();

		db.acquireSingleUserCaseReadLock();
		try {
			PreparedStatement s = connection.getPreparedStatement(queryString, Statement.RETURN_GENERATED_KEYS);
			s.clearParameters();
			s.setString(1, name);

			try (ResultSet rs = s.executeQuery()) {
				if (!rs.next()) {
					return Optional.empty();	// no match found
				} else {
					return Optional.of(new Host(rs.getLong("id"), rs.getString("name"), Host.HostDbStatus.fromID(rs.getInt("db_status"))));
				}
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting host with name = %s", name), ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get host with the given id.
	 *
	 * @param id The id of the host.
	 *
	 * @return Optional with host. Optional.empty if no matching host is found.
	 *
	 * @throws TskCoreException
	 */
	public Optional<Host> getHostById(long id) throws TskCoreException {
		try (CaseDbConnection connection = db.getConnection()) {
			return getHostById(id, connection);
		}
	}

	/**
	 * Get host with given id.
	 *
	 * @param id	        The id of the host.
	 * @param connection Database connection to use.
	 *
	 * @return Optional with host. Optional.empty if no matching host is found.
	 *
	 * @throws TskCoreException
	 */
	private Optional<Host> getHostById(long id, CaseDbConnection connection) throws TskCoreException {

		String queryString = "SELECT * FROM tsk_hosts WHERE id = " + id;

		db.acquireSingleUserCaseReadLock();
		try (Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			if (rs.next()) {
				return Optional.of(new Host(rs.getLong("id"), rs.getString("name"), Host.HostDbStatus.fromID(rs.getInt("db_status"))));
			} else {
				return Optional.empty();
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting host with id: " + id), ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get all hosts that have a status of ACTIVE.
	 *
	 * @return Collection of hosts that have ACTIVE status.
	 *
	 * @throws TskCoreException
	 */
	public List<Host> getAllHosts() throws TskCoreException {
		String queryString = "SELECT * FROM tsk_hosts WHERE db_status = " + HostDbStatus.ACTIVE.getId();

		List<Host> hosts = new ArrayList<>();
		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = this.db.getConnection();
				Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			while (rs.next()) {
				hosts.add(new Host(rs.getLong("id"), rs.getString("name"), Host.HostDbStatus.fromID(rs.getInt("db_status"))));
			}

			return hosts;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting hosts"), ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get host for the given data source.
	 *
	 * @param dataSource The data source to look up the host for.
	 *
	 * @return The host for this data source (will not be null).
	 *
	 * @throws TskCoreException if no host is found or an error occurs.
	 */
	public Host getHostByDataSource(DataSource dataSource) throws TskCoreException {

		String queryString = "SELECT tsk_hosts.id AS hostId, tsk_hosts.name AS name, tsk_hosts.db_status AS db_status FROM \n"
				+ "tsk_hosts INNER JOIN data_source_info \n"
				+ "ON tsk_hosts.id = data_source_info.host_id \n"
				+ "WHERE data_source_info.obj_id = " + dataSource.getId();

		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = this.db.getConnection();
				Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			if (!rs.next()) {
				throw new TskCoreException(String.format("Host not found for data source with ID = %d", dataSource.getId()));
			} else {
				return new Host(rs.getLong("hostId"), rs.getString("name"), Host.HostDbStatus.fromID(rs.getInt("db_status")));
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting host for data source with ID = %d", dataSource.getId()), ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}
	
	/**
	 * Merge source host into destination host.
	 * When complete:
	 * - All realms will have been moved into the destination host or merged with existing realms in the destination host.
	 * - All references to the source host will be updated to reference the destination host.
	 * - The source host will be updated so that it will no longer be returned by any methods
	 *    apart from get by host id.
	 * 
	 * @param sourceHost The source host.
	 * @param destHost   The destination host.
	 * 
	 * @throws TskCoreException 
	 */
	public void mergeHosts(Host sourceHost, Host destHost) throws TskCoreException {
		String query = "";
		CaseDbTransaction trans = null;
		try {
			trans = db.beginTransaction();
			
			// Merge or move any realms associated with the source host
			List<OsAccountRealm> realms = db.getOsAccountRealmManager().getRealmsByHost(sourceHost, trans.getConnection());
			for (OsAccountRealm realm : realms) {
				db.getOsAccountRealmManager().moveOrMergeRealm(realm, destHost, trans);
			}
			
			try (Statement s = trans.getConnection().createStatement()) {
				// Update references to the source host
				
				// tsk_host_address_map has a unique constraint on host_id, addr_obj_id, time,
				// so delete any rows that would be duplicates.
				query = "DELETE FROM tsk_host_address_map " +
					"WHERE id IN ( " +
					"SELECT " +
					"  sourceMapRow.id " +
					"FROM " +
					"  tsk_host_address_map destMapRow " +
					"INNER JOIN tsk_host_address_map sourceMapRow ON destMapRow.addr_obj_id = sourceMapRow.addr_obj_id AND destMapRow.time = sourceMapRow.time " +
					"WHERE destMapRow.host_id = " +  destHost.getHostId() + 
					" AND sourceMapRow.host_id = " + sourceHost.getHostId() + " )";
				s.executeUpdate(query);
				query = makeOsAccountUpdateQuery("tsk_host_address_map", "host_id", sourceHost, destHost);
				s.executeUpdate(query);
				
				query = makeOsAccountUpdateQuery("tsk_os_account_attributes", "host_id", sourceHost, destHost);
				s.executeUpdate(query);
				
				query = makeOsAccountUpdateQuery("data_source_info", "host_id", sourceHost, destHost);
				s.executeUpdate(query);
			
				// Mark the source host as merged and change the name to a random string.
				String mergedName = makeMergedHostName();
				query = "UPDATE tsk_hosts SET merged_into = " + destHost.getHostId()
						+ ", db_status = " + Host.HostDbStatus.MERGED.getId()
						+ ", name = '" + mergedName + "' " 
						+ " WHERE id = " + sourceHost.getHostId();
				s.executeUpdate(query);	
			}
			
			trans.commit();
			trans = null;
			
			// Fire events for updated and deleted hosts
			fireChangeEvent(sourceHost);
			fireDeletedEvent(destHost);
		} catch (SQLException ex) {
			throw new TskCoreException("Error executing query: " + query, ex);
		} finally {
			if (trans != null) {
				trans.rollback();
			}
		}
	}
	
	/**
	 * Create the query to update the host id column to the merged host.
	 * 
	 * @param tableName  Name of table to update.
	 * @param columnName Name of the column containing the host id.
	 * @param sourceHost  The source host.
	 * @param destHost    The destination host.
	 * 
	 * @return The query.
	 */
	private String makeOsAccountUpdateQuery(String tableName, String columnName, Host sourceHost, Host destHost) {
		return "UPDATE " + tableName + " SET " + columnName + " = " + destHost.getHostId() + " WHERE " + columnName + " = " + sourceHost.getHostId();
	}
	
	/**
	 * Create a random name for hosts that have been merged.
	 * 
	 * @return The random signature.
	 */
	private String makeMergedHostName() {
		return "MERGED " +  UUID.randomUUID().toString();
	}

	/**
	 * Fires an event that a host has changed.
	 * Do not call this with an open transaction.
	 *
	 * @param newValue The new value for the host.
	 */
	private void fireChangeEvent(Host newValue) {
		db.fireTSKEvent(new HostsChangedTskEvent(Collections.singletonList(newValue)));
	}

	/**
	 * Fires an event that a host has been deleted.
	 * Do not call this with an open transaction.
	 *
	 * @param deleted The deleted host.
	 */
	private void fireDeletedEvent(Host deleted) {
		db.fireTSKEvent(new HostsDeletedTskEvent(Collections.singletonList(deleted)));
	}
}
