/*
 * Sleuth Kit Data Model
 *
 * Copyright 2026 Basis Technology Corp.
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

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Optional;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbConnection;
import org.sleuthkit.datamodel.TskData.TSK_AUTHOR_TYPE_ENUM;

/**
 * Responsible for creating and retrieving the authors (people, models and
 * modules) that content in a case can be attributed to.
 *
 * An author is identified by its type and name together; the name is stable
 * (a login name, a model id, a module name) while the display name is not, so
 * lookups never match on the display name.
 */
public final class AuthorManager {

	private final SleuthkitCase db;

	/**
	 * Construct an AuthorManager for the given SleuthkitCase.
	 *
	 * @param skCase The SleuthkitCase.
	 */
	AuthorManager(SleuthkitCase skCase) {
		this.db = skCase;
	}

	/**
	 * Get the author with the given type and name.
	 *
	 * @param type Kind of principal to look for.
	 * @param name Stable name of the principal to look for.
	 *
	 * @return Optional with the author. Optional.empty if no author with that
	 *         type and name exists.
	 *
	 * @throws TskCoreException
	 */
	public Optional<Author> getAuthor(TSK_AUTHOR_TYPE_ENUM type, String name) throws TskCoreException {
		if (type == null) {
			throw new TskCoreException("Illegal argument passed to getAuthor: author type is required.");
		}
		if (name == null || name.isEmpty()) {
			throw new TskCoreException("Illegal argument passed to getAuthor: author name is required.");
		}

		try (CaseDbConnection connection = db.getConnection()) {
			return getAuthor(type, name, connection);
		}
	}

	/**
	 * Create an author with the given type, name and display name.
	 *
	 * @param type        Kind of principal.
	 * @param name        Stable name of the principal. Required.
	 * @param displayName Name to render for the principal. Required.
	 *
	 * @return The new author.
	 *
	 * @throws TskCoreException if an author with this type and name already
	 *                          exists.
	 */
	public Author createAuthor(TSK_AUTHOR_TYPE_ENUM type, String name, String displayName) throws TskCoreException {
		if (type == null) {
			throw new TskCoreException("Illegal argument passed to createAuthor: author type is required.");
		}
		if (name == null || name.isEmpty()) {
			throw new TskCoreException("Illegal argument passed to createAuthor: author name is required.");
		}
		if (displayName == null || displayName.isEmpty()) {
			throw new TskCoreException("Illegal argument passed to createAuthor: author display name is required.");
		}

		db.acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = db.getConnection()) {
			PreparedStatement insert = connection.getPreparedStatement(
					"INSERT INTO tsk_authors (author_type, author_name, display_name) VALUES (?, ?, ?)",
					Statement.RETURN_GENERATED_KEYS);
			insert.clearParameters();
			insert.setInt(1, type.getValue());
			insert.setString(2, name);
			insert.setString(3, displayName);
			connection.executeUpdate(insert);

			try (ResultSet rs = insert.getGeneratedKeys()) {
				if (!rs.next()) {
					throw new TskCoreException(String.format("Error reading back author of type = %s, name = %s", type, name));
				}
				return new Author(rs.getLong(1), type, name, displayName);
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error creating author of type = %s, name = %s", type, name), ex);
		} finally {
			db.releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Get the author with the given type and name, creating it if it does not
	 * exist yet.
	 *
	 * If the author already exists the existing row is returned unchanged, so
	 * the display name given here only takes effect when the author is
	 * created.
	 *
	 * @param type        Kind of principal.
	 * @param name        Stable name of the principal. Required.
	 * @param displayName Name to render for the principal, used only if the
	 *                    author does not already exist. Required.
	 *
	 * @return The author.
	 *
	 * @throws TskCoreException
	 */
	public Author getOrCreateAuthor(TSK_AUTHOR_TYPE_ENUM type, String name, String displayName) throws TskCoreException {
		if (type == null) {
			throw new TskCoreException("Illegal argument passed to getOrCreateAuthor: author type is required.");
		}
		if (name == null || name.isEmpty()) {
			throw new TskCoreException("Illegal argument passed to getOrCreateAuthor: author name is required.");
		}
		if (displayName == null || displayName.isEmpty()) {
			throw new TskCoreException("Illegal argument passed to getOrCreateAuthor: author display name is required.");
		}

		db.acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = db.getConnection()) {
			// Insert-then-select rather than select-then-insert. On PostgreSQL two
			// clients can open the same case at once, so a check-then-act here would
			// race; the UNIQUE constraint on (author_type, author_name) settles it instead.
			String insertSql = "INTO tsk_authors (author_type, author_name, display_name) VALUES (?, ?, ?)";
			switch (db.getDatabaseType()) {
				case POSTGRESQL:
					insertSql = "INSERT " + insertSql + " ON CONFLICT DO NOTHING"; //NON-NLS
					break;
				case SQLITE:
					insertSql = "INSERT OR IGNORE " + insertSql;
					break;
				default:
					throw new TskCoreException("Unknown DB Type: " + db.getDatabaseType().name());
			}

			PreparedStatement insert = connection.getPreparedStatement(insertSql, Statement.NO_GENERATED_KEYS);
			insert.clearParameters();
			insert.setInt(1, type.getValue());
			insert.setString(2, name);
			insert.setString(3, displayName);
			connection.executeUpdate(insert);

			return getAuthor(type, name, connection).orElseThrow(()
					-> new TskCoreException(String.format("Error reading back author of type = %s, name = %s", type, name)));
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error adding author of type = %s, name = %s", type, name), ex);
		} finally {
			db.releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Get the author with the given type and name.
	 *
	 * @param type       Kind of principal to look for.
	 * @param name       Stable name of the principal to look for.
	 * @param connection Database connection to use.
	 *
	 * @return Optional with the author. Optional.empty if no author with that
	 *         type and name exists.
	 *
	 * @throws TskCoreException
	 */
	private Optional<Author> getAuthor(TSK_AUTHOR_TYPE_ENUM type, String name, CaseDbConnection connection) throws TskCoreException {
		String queryString = "SELECT author_id, author_type, author_name, display_name FROM tsk_authors "
				+ "WHERE author_type = ? AND author_name = ?";

		db.acquireSingleUserCaseReadLock();
		try {
			PreparedStatement statement = connection.getPreparedStatement(queryString, Statement.NO_GENERATED_KEYS);
			statement.clearParameters();
			statement.setInt(1, type.getValue());
			statement.setString(2, name);

			try (ResultSet rs = statement.executeQuery()) {
				if (!rs.next()) {
					return Optional.empty();
				}
				return Optional.of(getAuthorFromResultSet(rs));
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting author of type = %s, name = %s", type, name), ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Build an author from a row that carries the tsk_authors columns.
	 *
	 * @param rs The result set, positioned on the row.
	 *
	 * @return The author.
	 *
	 * @throws SQLException
	 */
	private static Author getAuthorFromResultSet(ResultSet rs) throws SQLException {
		return new Author(rs.getLong("author_id"), TSK_AUTHOR_TYPE_ENUM.fromID(rs.getInt("author_type")),
				rs.getString("author_name"), rs.getString("display_name"));
	}
}
