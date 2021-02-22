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
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbConnection;

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
	 * @throws IllegalArgumentException If name field of the person is empty.
	 */
	public Person updatePerson(Person person) throws TskCoreException {
		
		// Must have a non-empty name
		if (Strings.isNullOrEmpty(person.getName())) {
			throw new IllegalArgumentException("Name field for person with ID " + person.getId() + " is null/empty. Will not update database.");
		}
		
		String queryString = "UPDATE tsk_persons"
				+ " SET name = ? WHERE id = " + person.getId();
		db.acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = db.getConnection()) {
			PreparedStatement s = connection.getPreparedStatement(queryString, Statement.NO_GENERATED_KEYS);
			s.clearParameters();
			s.setString(1, person.getName());
			s.executeUpdate();
			return person;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error updating person with id = %d", person.getId()), ex);
		} finally {
			db.releaseSingleUserCaseWriteLock();
		}
	}
	
	/**
	 * Delete a person.
	 * Name comparison is case-insensitive.
	 * 
	 * @param name Name of the person to delete
	 * 
	 * @throws TskCoreException 
	 */
	public void deletePerson(String name) throws TskCoreException {
		String queryString = "DELETE FROM tsk_persons"
				+ " WHERE LOWER(name) = LOWER(?)";
		
		db.acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = db.getConnection()) {
			PreparedStatement s = connection.getPreparedStatement(queryString, Statement.NO_GENERATED_KEYS);
			s.clearParameters();
			s.setString(1, name);
			s.executeUpdate();
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error deleting person with name %s", name), ex);
		} finally {
			db.releaseSingleUserCaseWriteLock();
		}
	}
	
	/**
	 * Get person with given name.
	 * Name comparison is case-insensitive.
	 *
	 * @param name        Person name to look for.
	 *
	 * @return Optional with person. Optional.empty if no matching person is found.
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
	 * Create a person with specified name. If a person already exists with the
	 * given name, it returns the existing person. Name comparison is case-insensitive.
	 *
	 * @param name	Person name.
	 *
	 * @return Person with the specified name.
	 *
	 * @throws TskCoreException
	 * @throws IllegalArgumentException If name field of the person is empty.
	 */
	public Person createPerson(String name) throws TskCoreException, IllegalArgumentException {

		// Must have a name
		if (Strings.isNullOrEmpty(name)) {
			throw new IllegalArgumentException("Non-empty name is required.");
		}

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
					return new Person(resultSet.getLong(1), name); //last_insert_rowid()
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
		String queryString = "SELECT * FROM tsk_hosts WHERE person_id = " + person.getId();

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
			throw new TskCoreException(String.format("Error getting host for data source: " + person.getName()), ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}
	
	
	/**
	 * Get person for the given host or null if no associated person.
	 *
	 * @param host The host.
	 *
	 * @return The parent person or empty if no parent person.
	 *
	 * @throws TskCoreException if  error occurs.
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
	 * Get person with given name.
	 * Name comparison is case-insensitive.
	 *
	 * @param name       Person name to look for.
	 * @param connection Database connection to use.
	 *
	 * @return Optional with person. Optional.empty if no matching person is found.
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
	
}