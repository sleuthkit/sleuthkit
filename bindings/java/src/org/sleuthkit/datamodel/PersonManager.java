/*
 * Sleuth Kit Data Model
 *
 * Copyright 2021 Basis Technology Corp.
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
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbConnection;
import org.sleuthkit.datamodel.TskEvent.PersonsAddedTskEvent;

/**
 * Responsible for creating/updating/retrieving Persons.
 */
public final class PersonManager {

	private final SleuthkitCase db;

	/**
	 * Construct a PersonManager for the given SleuthkitCase.
	 *
	 * @param skCase The SleuthkitCase
	 *
	 */
	PersonManager(SleuthkitCase skCase) {
		this.db = skCase;
	}

	/**
	 * Get all persons in the database.
	 *
	 * @return List of persons
	 *
	 * @throws TskCoreException
	 */
	public List<Person> getPersons() throws TskCoreException {
		String queryString = "SELECT * FROM tsk_persons";

		List<Person> persons = new ArrayList<>();
		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = this.db.getConnection();
				Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			while (rs.next()) {
				persons.add(new Person(rs.getLong("id"), rs.getString("name")));
			}

			return persons;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting persons"), ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Update the database to match the given Person.
	 *
	 * @param person The person to update.
	 *
	 * @return person The person that was updated.
	 *
	 * @throws TskCoreException
	 */
	public Person updatePerson(Person person) throws TskCoreException {

		// Must have a non-empty name
		if (Strings.isNullOrEmpty(person.getName())) {
			throw new TskCoreException("Illegal argument passed to updatePerson: Name field for person with ID " + person.getPersonId() + " is null/empty. Will not update database.");
		}

		String queryString = "UPDATE tsk_persons"
				+ " SET name = ? WHERE id = " + person.getPersonId();
		db.acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = db.getConnection()) {
			PreparedStatement s = connection.getPreparedStatement(queryString, Statement.NO_GENERATED_KEYS);
			s.clearParameters();
			s.setString(1, person.getName());
			s.executeUpdate();
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error updating person with id = %d", person.getPersonId()), ex);
		} finally {
			db.releaseSingleUserCaseWriteLock();
		}

		db.fireTSKEvent(new TskEvent.PersonsUpdatedTskEvent(Collections.singletonList(person)));
		return person;
	}

	/**
	 * Delete a person. Name comparison is case-insensitive.
	 *
	 * @param name Name of the person to delete
	 *
	 * @throws TskCoreException
	 */
	public void deletePerson(String name) throws TskCoreException {
		String queryString = "DELETE FROM tsk_persons"
				+ " WHERE LOWER(name) = LOWER(?)";

		Person deletedPerson = null;
		db.acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = db.getConnection()) {
			PreparedStatement s = connection.getPreparedStatement(queryString, Statement.RETURN_GENERATED_KEYS);
			s.clearParameters();
			s.setString(1, name);
			s.executeUpdate();

			try (ResultSet resultSet = s.getGeneratedKeys()) {
				if (resultSet.next()) {
					deletedPerson = new Person(resultSet.getLong(1), name);
				}
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error deleting person with name %s", name), ex);
		} finally {
			db.releaseSingleUserCaseWriteLock();
		}

		if (deletedPerson != null) {
			db.fireTSKEvent(new TskEvent.PersonsDeletedTskEvent(Collections.singletonList(deletedPerson.getPersonId())));
		}
	}

	/**
	 * Get person with given name. Name comparison is case-insensitive.
	 *
	 * @param name Person name to look for.
	 *
	 * @return Optional with person. Optional.empty if no matching person is
	 *         found.
	 *
	 * @throws TskCoreException
	 */
	public Optional<Person> getPerson(String name) throws TskCoreException {
		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = this.db.getConnection()) {
			return getPerson(name, connection);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get person with given id.
	 *
	 * @param id Id of the person to look for.
	 *
	 * @return Optional with person. Optional.empty if no matching person is
	 *         found.
	 *
	 * @throws TskCoreException
	 */
	public Optional<Person> getPerson(long id) throws TskCoreException {
		String queryString = "SELECT * FROM tsk_persons WHERE id = " + id;
		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = this.db.getConnection();
				Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			if (rs.next()) {
				return Optional.of(new Person(rs.getLong("id"), rs.getString("name")));
			} else {
				return Optional.empty();
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting persons"), ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Create a person with specified name. If a person already exists with the
	 * given name, it returns the existing person. Name comparison is
	 * case-insensitive.
	 *
	 * @param name	Person name.
	 *
	 * @return Person with the specified name.
	 *
	 * @throws TskCoreException
	 */
	public Person newPerson(String name) throws TskCoreException {

		// Must have a name
		if (Strings.isNullOrEmpty(name)) {
			throw new TskCoreException("Illegal argument passed to createPerson: Non-empty name is required.");
		}

		Person toReturn = null;
		CaseDbConnection connection = null;
		db.acquireSingleUserCaseWriteLock();
		try {
			connection = db.getConnection();
		
			// First try to load it from the database. This is a case-insensitive look-up
			// to attempt to prevent having two entries with the same lower-case name.
			Optional<Person> person = getPerson(name, connection);
			if (person.isPresent()) {
				return person.get();
			}

			// Attempt to insert the new Person.
			String personInsertSQL = "INSERT INTO tsk_persons(name) VALUES (?)"; // NON-NLS
			PreparedStatement preparedStatement = connection.getPreparedStatement(personInsertSQL, Statement.RETURN_GENERATED_KEYS);
			preparedStatement.clearParameters();
			preparedStatement.setString(1, name);
			connection.executeUpdate(preparedStatement);

			// Read back the row id.
			try (ResultSet resultSet = preparedStatement.getGeneratedKeys();) {
				if (resultSet.next()) {
					toReturn = new Person(resultSet.getLong(1), name); //last_insert_rowid()
				} else {
					throw new SQLException("Error executing SQL: " + personInsertSQL);
				}
			}
		} catch (SQLException ex) {
			if (connection != null) {
				// The insert may have failed because this person was just added on another thread, so try getting the person again.
				// (Note: the SingleUserCaseWriteLock is a no-op for multi-user cases so acquiring it does not prevent this situation)
				Optional<Person> person = getPerson(name, connection);
				if (person.isPresent()) {
					return person.get();
				}
			}
			throw new TskCoreException(String.format("Error adding person with name = %s", name), ex);
		} finally {
			db.releaseSingleUserCaseWriteLock();
		}

		if (toReturn != null) {
			db.fireTSKEvent(new PersonsAddedTskEvent(Collections.singletonList(toReturn)));
		}
		return toReturn;
	}

	/**
	 * Get all hosts associated with the given person.
	 *
	 * @param person The person.
	 *
	 * @return The list of hosts corresponding to the person.
	 *
	 * @throws TskCoreException Thrown if there is an issue querying the case
	 *                          database.
	 */
	public List<Host> getHostsForPerson(Person person) throws TskCoreException {
		return executeHostsQuery("SELECT * FROM tsk_hosts WHERE person_id = " + person.getPersonId());
	}

	/**
	 * Gets all hosts not associated with any person.
	 *
	 * @return The hosts.
	 *
	 * @throws TskCoreException Thrown if there is an issue querying the case
	 *                          database.
	 */
	public List<Host> getHostsWithoutPersons() throws TskCoreException {
		return executeHostsQuery("SELECT * FROM tsk_hosts WHERE person_id IS NULL");
	}

	/**
	 * Executes a query of the tsk_hosts table in the case database.
	 *
	 * @param hostsQuery The SQL query to execute.
	 *
	 * @throws TskCoreException Thrown if there is an issue querying the case
	 *                          database.
	 *
	 * @throws TskCoreException
	 */
	private List<Host> executeHostsQuery(String hostsQuery) throws TskCoreException {
		String sql = hostsQuery + " AND db_status = " + Host.HostDbStatus.ACTIVE.getId();
		List<Host> hosts = new ArrayList<>();
		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = this.db.getConnection();
				Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, sql)) {
			while (rs.next()) {
				hosts.add(new Host(rs.getLong("id"), rs.getString("name"), Host.HostDbStatus.fromID(rs.getInt("db_status"))));
			}
			return hosts;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error executing '" + sql + "'"), ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get person with given name. Name comparison is case-insensitive.
	 *
	 * @param name       Person name to look for.
	 * @param connection Database connection to use.
	 *
	 * @return Optional with person. Optional.empty if no matching person is
	 *         found.
	 *
	 * @throws TskCoreException
	 */
	private Optional<Person> getPerson(String name, CaseDbConnection connection) throws TskCoreException {

		String queryString = "SELECT * FROM tsk_persons"
				+ " WHERE LOWER(name) = LOWER(?)";
		try {
			PreparedStatement s = connection.getPreparedStatement(queryString, Statement.RETURN_GENERATED_KEYS);
			s.clearParameters();
			s.setString(1, name);

			try (ResultSet rs = s.executeQuery()) {
				if (!rs.next()) {
					return Optional.empty();	// no match found
				} else {
					return Optional.of(new Person(rs.getLong("id"), rs.getString("name")));
				}
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting person with name = %s", name), ex);
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
				+ "WHERE h.id = " + host.getHostId();

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
			throw new TskCoreException(String.format("Error getting person for host with ID = %d", host.getHostId()), ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Adds one or more hosts to a person.
	 *
	 * @param person The person.
	 * @param hosts  The hosts.
	 *
	 * @throws TskCoreException Thrown if the operation cannot be completed.
	 */
	public void addHostsToPerson(Person person, List<Host> hosts) throws TskCoreException {
		if (person == null) {
			throw new TskCoreException("Illegal argument: person must be non-null");
		}
		if (hosts == null || hosts.isEmpty()) {
			throw new TskCoreException("Illegal argument: hosts must be non-null and non-empty");
		}
		executeHostsUpdate(person, getHostIds(hosts), new TskEvent.HostsAddedToPersonTskEvent(person, hosts));
	}

	/**
	 * Removes one or more hosts from a person.
	 *
	 * @param person The person.
	 * @param hosts  The hosts.
	 *
	 * @throws TskCoreException Thrown if the operation cannot be completed.
	 */
	public void removeHostsFromPerson(Person person, List<Host> hosts) throws TskCoreException {
		if (person == null) {
			throw new TskCoreException("Illegal argument: person must be non-null");
		}
		if (hosts == null || hosts.isEmpty()) {
			throw new TskCoreException("Illegal argument: hosts must be non-null and non-empty");
		}
		List<Long> hostIds = getHostIds(hosts);
		executeHostsUpdate(null, hostIds, new TskEvent.HostsRemovedFromPersonTskEvent(person, hostIds));
	}

	/**
	 * Executes an update of the person_id column for one or more hosts in the
	 * tsk_hosts table in the case database.
	 *
	 * @param person  The person to get the person ID from or null if the person
	 *                ID of the hosts should be set to NULL.
	 * @param hostIds The host IDs of the hosts.
	 * @param event   A TSK event to be published if the update succeeds.
	 *
	 * @throws TskCoreException Thrown if the update fails.
	 */
	private void executeHostsUpdate(Person person, List<Long> hostIds, TskEvent event) throws TskCoreException {
		String updateSql = null;
		db.acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = this.db.getConnection(); Statement statement = connection.createStatement()) {
			updateSql = (person == null)
					? String.format("UPDATE tsk_hosts SET person_id = NULL")
					: String.format("UPDATE tsk_hosts SET person_id = %d", person.getPersonId());
			String hostIdsCsvList = hostIds.stream()
					.map(hostId -> hostId.toString())
					.collect(Collectors.joining(","));
			updateSql += " WHERE id IN (" + hostIdsCsvList + ")";
			statement.executeUpdate(updateSql);
			db.fireTSKEvent(event);
		} catch (SQLException ex) {
			throw new TskCoreException(String.format(updateSql == null ? "Error connecting to case database" : "Error executing '" + updateSql + "'"), ex);
		} finally {
			db.releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Gets a list of host IDs from a list of hosts.
	 *
	 * @param hosts The hosts.
	 *
	 * @return The host IDs.
	 */
	private List<Long> getHostIds(List<Host> hosts) {
		List<Long> hostIds = new ArrayList<>();
		hostIds.addAll(hosts.stream()
				.map(host -> host.getHostId())
				.collect(Collectors.toList()));
		return hostIds;
	}

}
