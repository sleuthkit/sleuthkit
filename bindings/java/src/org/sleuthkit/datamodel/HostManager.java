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
import org.sleuthkit.datamodel.Host.HostStatus;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbConnection;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbTransaction;

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
	 * Get or create host with specified name.
	 *
	 * TODO: This should be deleted before release
	 *
	 * @param name	Host name.
	 *
	 * @return Host with the specified name.
	 *
	 * @throws TskCoreException
	 */
	public Host getOrCreateHost(String name) throws TskCoreException {
		return createHost(name);
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
		CaseDbTransaction transaction = db.beginTransaction();
		try {
			Host host = createHost(name, transaction);
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
	 * NOTE: Whenever possible, create hosts as part of a single step transaction so
	 * that it can quickly determine a host of the same name already exists. If you call 
	 * this as part of a multi-step CaseDbTransaction, then this method may think it can
	 * insert the host name, but then when it comes time to call CaseDbTransaction.commit(),
	 * there could be a uniqueness constraint violation and other inserts in the same 
	 * transaction could have problems. 
	 *
	 * This method should never be made public and exists only because we need to support
	 * APIs that do not take in a host and we must make one. Ensure that if you call this 
	 * method that the host name you give will be unique.
	 *
	 * @param name  Host name that must be unique if this is called as part of a 
	 *              multi-step transaction
	 * @param trans Database transaction to use.
	 *
	 * @return Newly created host.
	 *
	 * @throws TskCoreException
	 */
	Host createHost(String name, CaseDbTransaction trans) throws TskCoreException {
		// must have a name
		if (Strings.isNullOrEmpty(name)) {
			throw new IllegalArgumentException("Host name is required.");
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
			Optional<Host> optHost = getHost(name, connection);
			if (optHost.isPresent()) {
				return optHost.get();
			}
			throw new TskCoreException(String.format("Error adding host with name = %s", name), ex);
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

		Host updatedHost = null;
		db.acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = db.getConnection()) {
			String hostInsertSQL = "UPDATE tsk_hosts \n"
					+ "SET name = ? \n"
					+ "WHERE id = ?";

			PreparedStatement preparedStatement = connection.getPreparedStatement(hostInsertSQL, Statement.RETURN_GENERATED_KEYS);

			preparedStatement.clearParameters();
			preparedStatement.setString(1, newHost.getName());
			preparedStatement.setLong(2, newHost.getId());

			connection.executeUpdate(preparedStatement);

			updatedHost = getHost(newHost.getId(), connection).orElseThrow(()
					-> new TskCoreException((String.format("Error while fetching newly updated host with id: %d, "))));

		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error updating host with name = %s", newHost.getName()), ex);
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
			throw new IllegalArgumentException("Name provided must be non-null");
		}

		// query to check if there are any dependencies on this host.  If so, don't delete.
		String queryString = "SELECT COUNT(*) AS count FROM\n"
				+ "(SELECT obj_id AS id, host_id FROM data_source_info\n"
				+ "UNION\n"
				+ "SELECT id, scope_host_id AS host_id FROM tsk_os_account_realms\n"
				+ "UNION\n"
				+ "SELECT id, host_id FROM tsk_os_account_attributes\n"
				+ "UNION\n"
				+ "SELECT id, host_id FROM tsk_os_account_instances\n"
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
		String queryString = "SELECT * FROM data_source_info WHERE host_id = " + host.getId();

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

		db.acquireSingleUserCaseReadLock();
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
	public Optional<Host> getHost(long id) throws TskCoreException {
		try (CaseDbConnection connection = db.getConnection()) {
			return getHost(id, connection);
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

		db.acquireSingleUserCaseReadLock();
		try (Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			if (rs.next()) {
				return Optional.of(new Host(rs.getLong("id"), rs.getString("name"), Host.HostStatus.fromID(rs.getInt("status"))));
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
	public List<Host> getHosts() throws TskCoreException {
		String queryString = "SELECT * FROM tsk_hosts WHERE status = " + HostStatus.ACTIVE.getId();

		List<Host> hosts = new ArrayList<>();
		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = this.db.getConnection();
				Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			while (rs.next()) {
				hosts.add(new Host(rs.getLong("id"), rs.getString("name"), Host.HostStatus.fromID(rs.getInt("status"))));
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
	public Host getHost(DataSource dataSource) throws TskCoreException {

		String queryString = "SELECT tsk_hosts.id AS hostId, tsk_hosts.name AS name, tsk_hosts.status AS status FROM \n"
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
				return new Host(rs.getLong("hostId"), rs.getString("name"), Host.HostStatus.fromID(rs.getInt("status")));
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting host for data source with ID = %d", dataSource.getId()), ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get person for the given host or empty if no associated person.
	 *
	 * @param host The host.
	 *
	 * @return The parent person or empty if no parent person.
	 *
	 * @throws TskCoreException if error occurs.
	 */
	public Optional<Person> getPerson(Host host) throws TskCoreException {

		String queryString = "SELECT p.id AS personId, p.name AS name FROM \n"
				+ "tsk_persons p INNER JOIN tsk_hosts h\n"
				+ "ON p.id = h.person_id \n"
				+ "WHERE h.id = " + host.getId();

		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = this.db.getConnection();
				Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			if (rs.next()) {
				return Optional.of(new Person(rs.getLong("personId"), rs.getString("name")));
			} else {
				return Optional.empty();
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting person for host with ID = %d", host.getId()), ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Set host's parent person.
	 *
	 * @param host   The host whose parent will be set.
	 * @param person The person to be a parent or null to remove any parent
	 *               person reference from this host.
	 *
	 * @throws IllegalArgumentException
	 * @throws TskCoreException
	 */
	public void setPerson(Host host, Person person) throws IllegalArgumentException, TskCoreException {
		if (host == null) {
			throw new IllegalArgumentException("host must be non-null.");
		}

		String queryString = (person == null)
				? String.format("UPDATE tsk_hosts SET person_id = NULL WHERE id = %d", host.getId())
				: String.format("UPDATE tsk_hosts SET person_id = %d WHERE id = %d", person.getId(), host.getId());

		db.acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = this.db.getConnection();
				Statement s = connection.createStatement();) {
			s.executeUpdate(queryString);
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting persons"), ex);
		} finally {
			db.releaseSingleUserCaseWriteLock();
		}
		
		db.getPersonManager().fireChangeEvent(person);
	}

	private void fireChangeEvent(Host newValue) {
		db.fireTSKEvent(new HostsUpdateEvent(Collections.singletonList(newValue)));
	}

	private void fireDeletedEvent(Host deleted) {
		db.fireTSKEvent(new HostsDeletionEvent(Collections.singletonList(deleted)));
	}

	/**
	 * Base event for all host events
	 */
	static class BaseHostEvent {

		private final List<Host> hosts;

		/**
		 * Main constructor.
		 * @param hosts The hosts that are objects of the event.
		 */
		BaseHostEvent(List<Host> hosts) {
			this.hosts = Collections.unmodifiableList(new ArrayList<>(hosts));
		}

		/**
		 * @return The hosts effected in the event.
		 */
		public List<Host> getHosts() {
			return hosts;
		}
	}

	/**
	 * Event fired when hosts are created.
	 */
	public static final class HostsCreationEvent extends BaseHostEvent {

		/**
		 * Main constructor.
		 * @param hosts The added hosts.
		 */
		HostsCreationEvent(List<Host> hosts) {
			super(hosts);
		}
	}

	/**
	 * Event fired when hosts are updated.
	 */
	public static final class HostsUpdateEvent extends BaseHostEvent {

		/**
		 * Main constructor.
		 * @param hosts The new values for the hosts that were changed.
		 */
		HostsUpdateEvent(List<Host> hosts) {
			super(hosts);
		}
	}

	/**
	 * Event fired when hosts are deleted.
	 */
	public static final class HostsDeletionEvent extends BaseHostEvent {

		/**
		 * Main constructor.
		 * @param hosts The hosts that were deleted.
		 */
		HostsDeletionEvent(List<Host> hosts) {
			super(hosts);
		}
	}
}
