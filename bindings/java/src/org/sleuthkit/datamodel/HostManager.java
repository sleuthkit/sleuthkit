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
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.sleuthkit.datamodel.Host.HostStatus;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbConnection;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbTransaction;

/**
 * Responsible for creating/updating/retrieving Hosts.
 *
 */
public final class HostManager {

	private static final Logger LOGGER = Logger.getLogger(HostManager.class.getName());

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
	 * Get or create host with specified name.
	 *
	 * @param name	Host name.
	 *
	 * @return Host with the specified name.
	 *
	 * @throws TskCoreException
	 */
	public Host getOrCreateHost(String name) throws TskCoreException {
		CaseDbTransaction trans = db.beginTransaction();
		try {
			Host host = getOrCreateHost(name, trans);
			trans.commit();
			return host;
		} catch (TskCoreException ex) {
			trans.rollback();
			throw ex;
		}
	}

	/**
	 * Get or create host with specified name.
	 *
	 * @param name	       Host name.
	 * @param transaction Database transaction to use.
	 *
	 * @return Host with the specified name.
	 *
	 * @throws TskCoreException
	 *
	 * @deprecated This method has been deprecated. Callers should use getHost()
	 * followed by createHost if needed.
	 */
	// RAMAN TBD: this method need to be deleted when the client code in Sleuthkit 
	//   is refactroed to use the get/create methods instead of getOrCreate
	@Deprecated
	Host getOrCreateHost(String name, CaseDbTransaction transaction) throws TskCoreException {

		// must have a name
		if (Strings.isNullOrEmpty(name)) {
			throw new IllegalArgumentException("Host name is required.");
		}

		CaseDbConnection connection = transaction.getConnection();

		// First search for host by name
		Optional<Host> host = getHost(name, connection);
		if (host.isPresent()) {
			return host.get();
		}

		// couldn't find it, create a new host
		return createHost(name, connection);
	}

	/**
	 * Create a host with given name.
	 *
	 * @param name       Host name.
	 * @param connection Database connection to use.
	 *
	 * @return Newly created host.
	 *
	 * @throws TskCoreException
	 */
	// RAMAN TBD: this method needs to be deleted when getOrCreateHost is deleted.
	private Host createHost(String name, CaseDbConnection connection) throws TskCoreException {
		db.acquireSingleUserCaseWriteLock();
		try {
			String hostInsertSQL = "INSERT INTO tsk_hosts(name) VALUES (?)"; // NON-NLS
			PreparedStatement preparedStatement = connection.getPreparedStatement(hostInsertSQL, Statement.RETURN_GENERATED_KEYS);

			preparedStatement.clearParameters();
			preparedStatement.setString(1, name);

			connection.executeUpdate(preparedStatement);

			// Read back the row id
			try (ResultSet resultSet = preparedStatement.getGeneratedKeys();) {
				if (resultSet.next()) {
					return new Host(resultSet.getLong(1), name); //last_insert_rowid()
				} else {
					throw new SQLException("Error executing  " + hostInsertSQL);
				}
			}
		} catch (SQLException ex) {
			LOGGER.log(Level.SEVERE, null, ex);
			throw new TskCoreException(String.format("Error adding host with name = %s", name), ex);
		} finally {
			db.releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Updates host in database based on the host object provided.
	 *
	 * @param newHost The host to be updated.
	 *
	 * @return The newly returned host.
	 *
	 * @throws TskCoreException
	 * @throws IllegalArgumentException
	 */
	public Host updateHost(Host newHost) throws TskCoreException, IllegalArgumentException {
		if (newHost == null) {
			throw new IllegalArgumentException("No host argument provided.");
		} else if (newHost.getName() == null) {
			throw new IllegalArgumentException(String.format("Host with id %d has no name", newHost.getId()));
		}

		CaseDbConnection connection = this.db.getConnection();
		db.acquireSingleUserCaseWriteLock();
		try {
			String hostInsertSQL = "UPDATE tsk_hosts \n"
					+ "SET name = ? \n"
					+ "WHERE id = ?";

			PreparedStatement preparedStatement = connection.getPreparedStatement(hostInsertSQL, Statement.RETURN_GENERATED_KEYS);

			preparedStatement.clearParameters();
			preparedStatement.setString(1, newHost.getName());
			preparedStatement.setLong(2, newHost.getId());

			connection.executeUpdate(preparedStatement);

			return getHost(newHost.getId(), connection).orElseThrow(()
					-> new TskCoreException((String.format("Error while fetching newly updated host with id: %d, "))));

		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error updating host with name = %s", newHost.getName()), ex);
		} finally {
			db.releaseSingleUserCaseWriteLock();
		}
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
		if (name != null) {
			throw new IllegalArgumentException("Name provided must be non-null");
		}

		String queryString = "SELECT d.obj_id FROM data_source_info d INNER JOIN tsk_hosts h WHERE LOWER(h.name)=LOWER(?)";
		String deleteString = "DELETE FROM tsk_hosts WHERE LOWER(name) = LOWER(?)";

		CaseDbTransaction trans = this.db.beginTransaction();
		try {
			// check if host has any child data sources.  if so, don't delete and throw exception.
			PreparedStatement query = trans.getConnection().getPreparedStatement(queryString, Statement.NO_GENERATED_KEYS);
			query.clearParameters();
			query.setString(1, name);
			try (ResultSet queryResults = query.executeQuery()) {
				if (queryResults.next()) {
					throw new TskCoreException(String.format("Host with name '%s' has child data sources and cannot be deleted."));
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
			return hostId;
			
		} catch (TskCoreException ex) {
			trans.rollback();
			throw ex;
		} catch (SQLException ex) {
			trans.rollback();
			throw new TskCoreException(String.format("Error deleting host with name %s", name), ex);
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
	public Set<DataSource> getDataSourcesForHost(Host host) throws TskCoreException {
		String queryString = "SELECT * FROM data_source_info WHERE host_id = " + host.getId();

		Set<DataSource> dataSources = new HashSet<>();
		try (CaseDbConnection connection = this.db.getConnection();
				Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			while (rs.next()) {
				dataSources.add(db.getDataSource(rs.getLong("obj_id")));
			}

			return dataSources;
		} catch (SQLException | TskDataException ex) {
			throw new TskCoreException(String.format("Error getting data sources for host " + host.getName()), ex);
		}
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
	public Host createHost(String name) throws TskCoreException {

		// must have a name
		if (Strings.isNullOrEmpty(name)) {
			throw new IllegalArgumentException("Host name is required.");
		}

		CaseDbConnection connection = this.db.getConnection();
		db.acquireSingleUserCaseWriteLock();
		try {
			String hostInsertSQL = "INSERT INTO tsk_hosts(name) VALUES (?)"; // NON-NLS
			PreparedStatement preparedStatement = connection.getPreparedStatement(hostInsertSQL, Statement.RETURN_GENERATED_KEYS);

			preparedStatement.clearParameters();
			preparedStatement.setString(1, name);

			connection.executeUpdate(preparedStatement);

			// Read back the row id
			try (ResultSet resultSet = preparedStatement.getGeneratedKeys();) {
				if (resultSet.next()) {
					return new Host(resultSet.getLong(1), name); //last_insert_rowid()
				} else {
					throw new SQLException("Error executing  " + hostInsertSQL);
				}
			}
		} catch (SQLException ex) {
			// may have failed because it already exists. So try getting the host.
			Optional<Host> host = this.getHost(name, connection);
			if (host.isPresent()) {
				return host.get();
			} else {
				throw new TskCoreException(String.format("Error adding host with name = %s", name), ex);
			}
		} finally {
			db.releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Get host with given name.
	 *
	 * @param name Host name to look for.
	 *
	 * @return Optional with host. Optional.empty if no matching host is found.
	 *
	 * @throws TskCoreException
	 */
	public Optional<Host> getHost(String name) throws TskCoreException {
		try (CaseDbConnection connection = db.getConnection()) {
			return getHost(name, connection);
		}
	}

	/**
	 * Get host with given name.
	 *
	 * @param name       Host name to look for.
	 * @param connection Database connection to use.
	 *
	 * @return Optional with host. Optional.empty if no matching host is found.
	 *
	 * @throws TskCoreException
	 */
	private Optional<Host> getHost(String name, CaseDbConnection connection) throws TskCoreException {

		String queryString = "SELECT * FROM tsk_hosts"
				+ " WHERE LOWER(name) = LOWER(?)";
		try {
			PreparedStatement s = connection.getPreparedStatement(queryString, Statement.RETURN_GENERATED_KEYS);
			s.clearParameters();
			s.setString(1, name);

			try (ResultSet rs = s.executeQuery()) {
				if (!rs.next()) {
					return Optional.empty();	// no match found
				} else {
					return Optional.of(new Host(rs.getLong("id"), rs.getString("name"), Host.HostStatus.fromID(rs.getInt("status"))));
				}
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting host with name = %s", name), ex);
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
	private Optional<Host> getHost(long id, CaseDbConnection connection) throws TskCoreException {

		String queryString = "SELECT * FROM tsk_hosts WHERE id = " + id;
		try (Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			if (rs.next()) {
				return Optional.of(new Host(rs.getLong("id"), rs.getString("name"), Host.HostStatus.fromID(rs.getInt("status"))));
			} else {
				return Optional.empty();
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting host with id: " + id), ex);
		}
	}

	/**
	 * Get all hosts that have a status of ACTIVE.
	 *
	 * @return Collection of hosts that have ACTIVE status.
	 *
	 * @throws TskCoreException
	 */
	public List<Host> getHosts() throws TskCoreException {
		String queryString = "SELECT * FROM tsk_hosts WHERE status = " + HostStatus.ACTIVE.getId();

		List<Host> hosts = new ArrayList<>();
		try (CaseDbConnection connection = this.db.getConnection();
				Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			while (rs.next()) {
				hosts.add(new Host(rs.getLong("id"), rs.getString("name"), Host.HostStatus.fromID(rs.getInt("status"))));
			}

			return hosts;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting hosts"), ex);
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
	Host getHost(DataSource dataSource) throws TskCoreException {

		String queryString = "SELECT tsk_hosts.id AS hostId, tsk_hosts.name AS name, tsk_hosts.status AS status FROM \n"
				+ "tsk_hosts INNER JOIN data_source_info \n"
				+ "ON tsk_hosts.id = data_source_info.host_id \n"
				+ "WHERE data_source_info.obj_id = " + dataSource.getId();

		try (CaseDbConnection connection = this.db.getConnection();
				Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			if (!rs.next()) {
				throw new TskCoreException(String.format("Host not found for data source with ID = %d", dataSource.getId()));
			} else {
				return new Host(rs.getLong("hostId"), rs.getString("name"), Host.HostStatus.fromID(rs.getInt("status")));
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting host for data source with ID = %d", dataSource.getId()), ex);
		}
	}
}
