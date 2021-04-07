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
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbConnection;
import org.sleuthkit.datamodel.TskEvent.PersonsAddedTskEvent;

/**
 * Responsible for creating/updating/retrieving Persons.
 *
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

		fireChangeEvent(person);
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
			fireDeletedEvent(deletedPerson);
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

		List<Person> persons = new ArrayList<>();
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
		CaseDbConnection connection = this.db.getConnection();
		db.acquireSingleUserCaseWriteLock();
		try {
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
			// The insert may have failed because this person was just added on another thread, so try getting the person again.
			// (Note: the SingleUserCaseWriteLock is a no-op for multi-user cases so acquiring it does not prevent this situation)
			Optional<Person> person = getPerson(name, connection);
			if (person.isPresent()) {
				return person.get();
			} else {
				throw new TskCoreException(String.format("Error adding person with name = %s", name), ex);
			}
		} finally {
			connection.close();
			db.releaseSingleUserCaseWriteLock();
		}

		if (toReturn != null) {
			fireCreationEvent(toReturn);
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
	 * @throws TskCoreException
	 */
	public List<Host> getHostsForPerson(Person person) throws TskCoreException {
		String whereStatement = (person == null) ? " WHERE person_id IS NULL " : " WHERE person_id = " + person.getPersonId();
		whereStatement +=  " AND db_status = " + Host.HostDbStatus.ACTIVE.getId();

		String queryString = "SELECT * FROM tsk_hosts " + whereStatement;

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
			throw new TskCoreException(String.format("Error getting host for data source: " + person.getName()), ex);
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
	 * Set host's parent person.
	 *
	 * @param host   The host whose parent will be set.
	 * @param person The person to be a parent or null to remove any parent
	 *               person reference from this host.
	 *
	 * @throws TskCoreException
	 */
	public void setPerson(Host host, Person person) throws TskCoreException {
		if (host == null) {
			throw new TskCoreException("Illegal argument passed to setPerson: host must be non-null.");
		}

		String queryString = (person == null)
				? String.format("UPDATE tsk_hosts SET person_id = NULL WHERE id = %d", host.getHostId())
				: String.format("UPDATE tsk_hosts SET person_id = %d WHERE id = %d", person.getPersonId(), host.getHostId());

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

	/**
	 * Fires an event when a person is created.
	 *
	 * @param added The person that was created.
	 */
	private void fireCreationEvent(Person added) {
		db.fireTSKEvent(new PersonsAddedTskEvent(Collections.singletonList(added)));
	}

	/**
	 * Fires a change event for the specified person.
	 *
	 * @param newValue The person value that has changed.
	 */
	void fireChangeEvent(Person newValue) {
		db.fireTSKEvent(new TskEvent.PersonsChangedTskEvent(Collections.singletonList(newValue)));
	}

	private void fireDeletedEvent(Person deleted) {
		db.fireTSKEvent(new TskEvent.PersonsDeletedTskEvent(Collections.singletonList(deleted)));
	}
}
