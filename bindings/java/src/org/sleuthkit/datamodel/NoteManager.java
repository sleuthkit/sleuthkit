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

import com.google.common.collect.Lists;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbConnection;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbTransaction;
import org.sleuthkit.datamodel.TskData.DbType;
import org.sleuthkit.datamodel.TskData.TSK_AUTHOR_TYPE_ENUM;

/**
 * Responsible for creating, revising, deleting and retrieving Notes.
 *
 * A note is edited in place: reviseNote() updates the row and sets its
 * modified time, rather than writing a new row. There is therefore at most one
 * row per note; a soft-deleted note keeps its row so replies stay reachable
 * and a consumer can render a tombstone, and reads do not filter it out.
 *
 * This manager enforces no permissions. It exposes the author of each note so
 * a consumer can decide who may act, and that is the whole contract. The one
 * rule here that looks like policy, reviseNote() requiring the same author, is
 * not: it holds a property of the data, that a note has one author for its
 * whole life.
 */
public final class NoteManager {

	/**
	 * Maximum number of notes per PostgreSQL insert chunk in addNotes().
	 * Internal chunking unit; callers may pass any number of requests and the
	 * manager partitions.
	 *
	 * Sized to keep the tsk_notes INSERT (11 bound columns per row) under
	 * PostgreSQL's 65,535 bind-parameter ceiling: 4000 rows = 44,000
	 * parameters.
	 */
	static final int PG_NOTES_CHUNK_SIZE = 4000;

	/**
	 * The same, for SQLite, whose bind-parameter ceiling is the lower one:
	 * SQLITE_MAX_VARIABLE_NUMBER defaults to 32,766, so 2000 rows = 22,000
	 * parameters leaves room to spare. A chunk sized for PostgreSQL would
	 * exceed it.
	 */
	static final int SQLITE_NOTES_CHUNK_SIZE = 2000;

	/**
	 * Maximum reply depth in a thread. SQL cannot express this, so the manager
	 * has to, alongside the cycle check in checkThreadDepth().
	 */
	private static final int MAX_THREAD_DEPTH = 100;

	/**
	 * The bound columns of an insert, in order. A thread root's root_note_id is
	 * unknown until the note id is generated, so it is bound NULL and
	 * back-filled; modified_time / is_deleted take their column defaults.
	 */
	private static final String NOTE_INSERT_COLUMNS
			= "obj_id, data_source_obj_id, note_type_id, body, details, "
			+ "author_id, configuration, created_time, "
			+ "parent_note_id, root_note_id, analysis_result_id";

	private static final String NOTE_INSERT_PLACEHOLDERS = "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

	private static final int NOTE_INSERT_PARAM_COUNT = 11;

	/**
	 * Reads join the type and author tables rather than caching them, so a
	 * type or author added by another client of the same PostgreSQL case
	 * database is never missing.
	 */
	static final String NOTE_SELECT
			= "SELECT notes.note_id, notes.obj_id, notes.data_source_obj_id, notes.note_type_id, "
			+ "notes.body, notes.details, notes.author_id, "
			+ "notes.configuration, notes.created_time, notes.modified_time, notes.parent_note_id, notes.root_note_id, "
			+ "notes.is_deleted, notes.analysis_result_id, "
			+ "types.type_name, types.display_name, types.description, "
			+ "authors.author_type, authors.author_name, authors.display_name "
			+ "FROM tsk_notes notes "
			+ "INNER JOIN tsk_note_types types ON notes.note_type_id = types.note_type_id "
			+ "INNER JOIN tsk_authors authors ON notes.author_id = authors.author_id ";

	/**
	 * Oldest first, ties broken on note id. created_time is milliseconds, but
	 * two notes written in the same millisecond still need a stable order.
	 */
	static final String NOTE_ORDER = " ORDER BY notes.created_time, notes.note_id";

	/**
	 * What a delete does to the row. The schema supports both; which one a user
	 * gets is the consumer's ruling.
	 */
	public enum DeleteMode {

		/**
		 * Remove the row. Through the parent_note_id cascade, its reply
		 * subtree goes with it.
		 */
		HARD,
		/**
		 * Mark the note deleted and keep the row, so replies stay reachable and
		 * the UI can show a tombstone.
		 */
		SOFT;
	}

	private final SleuthkitCase db;

	/**
	 * Construct a NoteManager for the given SleuthkitCase.
	 *
	 * @param skCase The SleuthkitCase.
	 */
	NoteManager(SleuthkitCase skCase) {
		this.db = skCase;
	}

	/**
	 * Get the note type with the given name, adding it if it does not exist
	 * yet. Note types are open: a consumer does not have to wait on a Sleuth
	 * Kit release to add one.
	 *
	 * If the type already exists the existing row is returned unchanged, so the
	 * display name given here only takes effect when the type is created.
	 *
	 * @param typeName    Unique name of the type. Required.
	 * @param displayName Name to render for the type, may be null.
	 *
	 * @return The note type.
	 *
	 * @throws TskCoreException
	 */
	NoteType getOrAddNoteType(String typeName, String displayName) throws TskCoreException {
		return getOrAddNoteType(typeName, displayName, null);
	}

	/**
	 * Get the note type with the given name, adding it if it does not exist
	 * yet.
	 *
	 * If the type already exists the existing row is returned unchanged, so the
	 * display name and description given here only take effect when the type is
	 * created.
	 *
	 * @param typeName    Unique name of the type. Required.
	 * @param displayName Name to render for the type, may be null.
	 * @param description Description of the type, may be null.
	 *
	 * @return The note type.
	 *
	 * @throws TskCoreException
	 */
	NoteType getOrAddNoteType(String typeName, String displayName, String description) throws TskCoreException {
		if (typeName == null || typeName.isEmpty()) {
			throw new TskCoreException("Illegal argument passed to getOrAddNoteType: type name is required.");
		}

		db.acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = db.getConnection()) {
			// Insert-then-select rather than select-then-insert. On PostgreSQL two
			// clients can open the same case at once, so a check-then-act here would
			// race; the UNIQUE constraint on type_name settles it instead.
			String insertSql = "INTO tsk_note_types (type_name, display_name, description) VALUES (?, ?, ?)";
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
			insert.setString(1, typeName);
			insert.setString(2, displayName);
			insert.setString(3, description);
			connection.executeUpdate(insert);

			return getNoteType(typeName, connection).orElseThrow(()
					-> new TskCoreException(String.format("Error reading back note type with name = %s", typeName)));
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error adding note type with name = %s", typeName), ex);
		} finally {
			db.releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Get the note type with the given name.
	 *
	 * @param typeName Name of the type to look for.
	 *
	 * @return Optional with the note type. Optional.empty if no type with that
	 *         name exists.
	 *
	 * @throws TskCoreException
	 */
	public Optional<NoteType> getNoteType(String typeName) throws TskCoreException {
		if (typeName == null) {
			throw new TskCoreException("Illegal argument passed to getNoteType: type name is required.");
		}

		try (CaseDbConnection connection = db.getConnection()) {
			return getNoteType(typeName, connection);
		}
	}

	/**
	 * Get the note type with the given name.
	 *
	 * @param typeName   Name of the type to look for.
	 * @param connection Database connection to use.
	 *
	 * @return Optional with the note type. Optional.empty if no type with that
	 *         name exists.
	 *
	 * @throws TskCoreException
	 */
	private Optional<NoteType> getNoteType(String typeName, CaseDbConnection connection) throws TskCoreException {
		String queryString = "SELECT note_type_id, type_name, display_name, description FROM tsk_note_types WHERE type_name = ?";

		db.acquireSingleUserCaseReadLock();
		try {
			PreparedStatement statement = connection.getPreparedStatement(queryString, Statement.NO_GENERATED_KEYS);
			statement.clearParameters();
			statement.setString(1, typeName);

			try (ResultSet rs = statement.executeQuery()) {
				if (!rs.next()) {
					return Optional.empty();
				}
				return Optional.of(getNoteTypeFromResultSet(rs));
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting note type with name = %s", typeName), ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Add notes as part of the caller's transaction.
	 *
	 * A batch is one transaction: if any request is invalid nothing is written
	 * and the exception names the offending index. One event is fired for the
	 * whole batch, after the caller commits.
	 *
	 * The requests are partitioned and each chunk written as one multi-row
	 * INSERT, on both engines. The SQL is not PostgreSQL specific; only the
	 * chunk size is, because the two have different bind-parameter ceilings
	 * (see PG_NOTES_CHUNK_SIZE and SQLITE_NOTES_CHUNK_SIZE). Both then run the
	 * same back-fill statement, so the derived columns are set by one piece of
	 * SQL rather than two.
	 *
	 * A reply must name a note that already exists, so a batch cannot build a
	 * thread in one call. The write this is for is one answer applied to many
	 * items, which is many thread roots rather than one thread.
	 *
	 * @param requests The notes to add. May be empty. Must not be null.
	 * @param trans    Transaction to use.
	 *
	 * @return The notes as written, in request order.
	 *
	 * @throws TskCoreException
	 */
	public List<Note> addNotes(List<NewNoteRequest> requests, CaseDbTransaction trans) throws TskCoreException {
		if (requests == null) {
			throw new TskCoreException("Illegal argument passed to addNotes: requests list is required.");
		}
		if (trans == null) {
			throw new TskCoreException("Illegal argument passed to addNotes: transaction is required.");
		}
		if (requests.isEmpty()) {
			return Collections.emptyList();
		}

		CaseDbConnection connection = trans.getConnection();

		// Validate and resolve the derived columns for every request before writing
		// anything, so a bad request fails the batch rather than half-writing it.
		List<PendingNote> pending = prepareNotes(requests, connection);

		int chunkSize = db.getDatabaseType() == DbType.POSTGRESQL
				? PG_NOTES_CHUNK_SIZE
				: SQLITE_NOTES_CHUNK_SIZE;

		List<Long> noteIds = new ArrayList<>(pending.size());
		for (List<PendingNote> chunk : Lists.partition(pending, chunkSize)) {
			noteIds.addAll(insertNotes(chunk, connection));
		}

		backFillRootNoteId(noteIds, connection);

		List<Note> notes = new ArrayList<>(pending.size());
		for (int i = 0; i < pending.size(); i++) {
			notes.add(pending.get(i).toNote(noteIds.get(i)));
		}
		trans.registerAddedNotes(notes);
		return notes;
	}

	/**
	 * Revise a note as part of the caller's transaction.
	 *
	 * The row is updated in place and modified_time is set to now, so the
	 * note's own id never changes and anything pointing at it still resolves.
	 *
	 * You revise your own note. You reply to someone else's - there is no
	 * operation that rewrites another person's words under their name.
	 *
	 * @param noteId        Id of the note to revise.
	 * @param body          The new prose. Required.
	 * @param details       The new structured payload, may be null.
	 * @param configuration The new prompt or module configuration version, may
	 *                      be null. May differ from the note's previous value,
	 *                      since a model or module can move on to a newer
	 *                      configuration between edits.
	 * @param author        Who is revising. Must be the note's author.
	 * @param trans         Transaction to use.
	 *
	 * @return The revised note.
	 *
	 * @throws TskCoreException
	 */
	public Note reviseNote(long noteId, String body, String details, String configuration, Author author,
			CaseDbTransaction trans) throws TskCoreException {
		if (body == null) {
			throw new TskCoreException("Illegal argument passed to reviseNote: body is required.");
		}
		if (author == null) {
			throw new TskCoreException("Illegal argument passed to reviseNote: author is required.");
		}
		if (trans == null) {
			throw new TskCoreException("Illegal argument passed to reviseNote: transaction is required.");
		}

		CaseDbConnection connection = trans.getConnection();
		Note existing = getNoteById(noteId, connection).orElseThrow(()
				-> new TskCoreException(String.format("Cannot revise note with id = %d, it does not exist", noteId)));

		if (existing.isDeleted()) {
			// A retraction stands; without this the update would quietly bring a
			// retracted note back to life under a new body.
			throw new TskCoreException(String.format("Cannot revise note with id = %d, it has been deleted.", noteId));
		}
		if (!existing.getAuthor().equals(author)) {
			throw new TskCoreException(String.format("Cannot revise note with id = %d, it was written by a different author. "
					+ "Reply to it instead.", noteId));
		}

		try {
			long modifiedTime = System.currentTimeMillis();
			PreparedStatement update = connection.getPreparedStatement(
					"UPDATE tsk_notes SET body = ?, details = ?, configuration = ?, modified_time = ? WHERE note_id = ?",
					Statement.NO_GENERATED_KEYS);
			update.clearParameters();
			update.setString(1, body);
			update.setString(2, details);
			update.setString(3, configuration);
			update.setLong(4, modifiedTime);
			update.setLong(5, noteId);
			connection.executeUpdate(update);

			Note revised = new Note(noteId, existing.getObjectId(), existing.getDataSourceObjectId().orElse(null),
					existing.getType(), body, details, author, configuration, existing.getCreatedTime(), modifiedTime,
					existing.getParentNoteId().orElse(null), existing.getRootNoteId(), false,
					existing.getAnalysisResultId().orElse(null));
			trans.registerUpdatedNote(revised);
			return revised;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error revising note with id = %d", noteId), ex);
		}
	}

	/**
	 * Delete notes, in one transaction.
	 *
	 * A hard delete removes the row and, through the parent_note_id cascade,
	 * the replies underneath it. A soft delete marks the note deleted and
	 * leaves the row, and the replies, alone.
	 *
	 * The fired event carries the notes the caller asked to delete, read just
	 * before they went, not the replies that went with them under a hard
	 * delete.
	 *
	 * @param noteIds Ids of the notes to delete. May be empty.
	 * @param mode    Whether to remove the rows or mark the notes deleted.
	 *
	 * @throws TskCoreException
	 */
	public void deleteNotes(Collection<Long> noteIds, DeleteMode mode) throws TskCoreException {
		if (noteIds == null) {
			throw new TskCoreException("Illegal argument passed to deleteNotes: note ids are required.");
		}
		if (mode == null) {
			throw new TskCoreException("Illegal argument passed to deleteNotes: delete mode is required.");
		}
		if (noteIds.isEmpty()) {
			return;
		}

		List<Long> requested = new ArrayList<>(new LinkedHashSet<>(noteIds));
		List<Note> deleted = new ArrayList<>();
		CaseDbTransaction trans = db.beginTransaction();
		try {
			CaseDbConnection connection = trans.getConnection();
			try (Statement s = connection.createStatement()) {
				for (List<Long> chunk : Lists.partition(requested, PG_NOTES_CHUNK_SIZE)) {
					// Read what is about to go, for the event. It has to happen here: after a
					// hard delete there is no row left to describe, and an event carrying only
					// ids tells a consumer nothing about which object lost a note.
					try (ResultSet rs = connection.executeQuery(s, NOTE_SELECT + "WHERE notes.note_id IN ("
							+ toIdList(chunk) + ")" + NOTE_ORDER)) {
						while (rs.next()) {
							deleted.add(getNoteFromResultSet(rs));
						}
					}

					if (mode == DeleteMode.SOFT) {
						connection.executeUpdate(s, "UPDATE tsk_notes SET is_deleted = 1 WHERE note_id IN (" + toIdList(chunk) + ")");
					} else {
						connection.executeUpdate(s, "DELETE FROM tsk_notes WHERE note_id IN (" + toIdList(chunk) + ")");
					}
				}
			}

			trans.registerDeletedNotes(deleted);
			trans.commit();
			trans = null;
		} catch (SQLException ex) {
			throw new TskCoreException("Error deleting notes", ex);
		} finally {
			if (trans != null) {
				trans.rollback();
			}
		}
	}

	/**
	 * Get the notes of several types, written by particular types of author,
	 * on many objects.
	 *
	 * The author filter is here rather than left to the caller because "never
	 * show a model its own output" is the kind of rule that has to hold for
	 * every consumer at once: one filtered query is a single place to be right,
	 * where an in-memory check is one place per call site to be wrong.
	 *
	 * Soft-deleted notes are still included.
	 *
	 * @param objIds      The objects.
	 * @param types       The note types. Required and must not be empty: an
	 *                    empty collection would otherwise have to mean either
	 *                    "every type" or "no type", and silently returning
	 *                    everything to a caller that built an empty list by
	 *                    accident is the worse of the two.
	 * @param authorTypes The author types to include, or null for every type.
	 *                    Must not be empty when given, for the same reason.
	 *
	 * @return Map of object id to its notes, oldest first. Objects with no
	 *         matching note are absent from the map.
	 *
	 * @throws TskCoreException
	 */
	public Map<Long, List<Note>> getCurrentNotes(Collection<Long> objIds, Collection<NoteType> types,
			Collection<TSK_AUTHOR_TYPE_ENUM> authorTypes) throws TskCoreException {
		requireTypes(types);
		if (authorTypes != null) {
			requireAuthorTypes(authorTypes);
		}
		return getCurrentNotes(objIds, types, authorTypes, "Error getting current notes for %d objects");
	}

	/**
	 * Count the notes of several types on many objects, per type, without
	 * loading any prose. This is what a table that badges each row with a note
	 * count wants: reading every body to count them is the obvious N+1 trap.
	 *
	 * Counts the same rows getCurrentNotes() returns, retracted notes included.
	 * Whether a retraction is shown is the consumer's ruling, and it has to be
	 * the same ruling for the badge and for the list behind it.
	 *
	 * @param objIds      The objects.
	 * @param types       The note types. Required and must not be empty.
	 * @param authorTypes The author types to include, or null for every type.
	 *                    Must not be empty when given.
	 *
	 * @return Map of object id to a map of note type to count. Objects with no
	 *         matching note are absent from the outer map, and types with no
	 *         matching note are absent from the inner one.
	 *
	 * @throws TskCoreException
	 */
	public Map<Long, Map<NoteType, Integer>> getCurrentNoteCounts(Collection<Long> objIds, Collection<NoteType> types,
			Collection<TSK_AUTHOR_TYPE_ENUM> authorTypes) throws TskCoreException {
		requireTypes(types);
		if (authorTypes != null) {
			requireAuthorTypes(authorTypes);
		}
		if (objIds == null) {
			throw new TskCoreException("Illegal argument passed to getCurrentNoteCounts: object ids are required.");
		}

		// Indexed by id from what the caller passed, so turning a counted note_type_id
		// back into a NoteType costs no extra query.
		Map<Long, NoteType> typesById = new HashMap<>();
		for (NoteType type : types) {
			typesById.put(type.getNoteTypeId(), type);
		}

		Map<Long, Map<NoteType, Integer>> countsByObject = new HashMap<>();
		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = db.getConnection();
				Statement s = connection.createStatement()) {

			for (List<Long> chunk : partitionIds(objIds)) {
				String queryString = "SELECT notes.obj_id, notes.note_type_id, COUNT(*) AS count FROM tsk_notes notes "
						+ "INNER JOIN tsk_authors authors ON notes.author_id = authors.author_id "
						+ "WHERE " + currentNotesPredicate(chunk, types, authorTypes)
						+ " GROUP BY notes.obj_id, notes.note_type_id";
				try (ResultSet rs = connection.executeQuery(s, queryString)) {
					while (rs.next()) {
						NoteType type = typesById.get(rs.getLong("note_type_id"));
						if (type == null) {
							continue; // cannot happen: the query filtered on these very ids
						}
						countsByObject.computeIfAbsent(rs.getLong("obj_id"), key -> new HashMap<>())
								.put(type, rs.getInt("count"));
					}
				}
			}
			return countsByObject;
		} catch (SQLException ex) {
			throw new TskCoreException("Error counting notes", ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Read the live notes of several types on many objects.
	 *
	 * @param objIds       The objects.
	 * @param types        The note types, already validated.
	 * @param authorTypes  The author types to include, or null for no filter.
	 * @param errorMessage Format string taking the chunk size.
	 *
	 * @return Map of object id to its notes, oldest first.
	 *
	 * @throws TskCoreException
	 */
	private Map<Long, List<Note>> getCurrentNotes(Collection<Long> objIds, Collection<NoteType> types,
			Collection<TSK_AUTHOR_TYPE_ENUM> authorTypes, String errorMessage) throws TskCoreException {
		if (objIds == null) {
			throw new TskCoreException("Illegal argument passed to getCurrentNotes: object ids are required.");
		}

		Map<Long, List<Note>> notesByObject = new HashMap<>();
		for (List<Long> chunk : partitionIds(objIds)) {
			List<Note> notes = getNotes(NOTE_SELECT + "WHERE " + currentNotesPredicate(chunk, types, authorTypes) + NOTE_ORDER,
					String.format(errorMessage, chunk.size()));
			for (Note note : notes) {
				notesByObject.computeIfAbsent(note.getObjectId(), key -> new ArrayList<>()).add(note);
			}
		}
		return notesByObject;
	}

	/**
	 * Build the WHERE clause shared by the multi-type reads, so that a count
	 * can never disagree with the list it is counting.
	 *
	 * @param objIdChunk  The objects, already chunked.
	 * @param types       The note types.
	 * @param authorTypes The author types to include, or null for no filter.
	 *
	 * @return The predicate, with every column qualified by the notes or
	 *         authors alias.
	 */
	private static String currentNotesPredicate(List<Long> objIdChunk, Collection<NoteType> types,
			Collection<TSK_AUTHOR_TYPE_ENUM> authorTypes) {

		List<Long> typeIds = new ArrayList<>(types.size());
		for (NoteType type : types) {
			typeIds.add(type.getNoteTypeId());
		}

		StringBuilder predicate = new StringBuilder();
		predicate.append("notes.obj_id IN (").append(toIdList(objIdChunk)).append(")")
				.append(" AND notes.note_type_id IN (").append(toIdList(typeIds)).append(")");
		if (authorTypes != null) {
			List<Long> authorTypeIds = new ArrayList<>(authorTypes.size());
			for (TSK_AUTHOR_TYPE_ENUM authorType : authorTypes) {
				authorTypeIds.add((long) authorType.getValue());
			}
			predicate.append(" AND authors.author_type IN (").append(toIdList(authorTypeIds)).append(")");
		}
		return predicate.toString();
	}

	/**
	 * Get one note by its id.
	 *
	 * @param noteId     The note id.
	 * @param connection Database connection to use.
	 *
	 * @return Optional with the note. Optional.empty if there is no such note.
	 *
	 * @throws TskCoreException
	 */
	private Optional<Note> getNoteById(long noteId, CaseDbConnection connection) throws TskCoreException {
		String queryString = NOTE_SELECT + "WHERE notes.note_id = " + noteId;

		db.acquireSingleUserCaseReadLock();
		try (Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			if (!rs.next()) {
				return Optional.empty();
			}
			return Optional.of(getNoteFromResultSet(rs));
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting note with id = %d", noteId), ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Run a note query on its own connection.
	 *
	 * @param queryString  The query, which must select the NOTE_SELECT columns.
	 * @param errorMessage Message for the exception if the query fails.
	 *
	 * @return The notes.
	 *
	 * @throws TskCoreException
	 */
	private List<Note> getNotes(String queryString, String errorMessage) throws TskCoreException {
		List<Note> notes = new ArrayList<>();
		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = db.getConnection();
				Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			while (rs.next()) {
				notes.add(getNoteFromResultSet(rs));
			}
			return notes;
		} catch (SQLException ex) {
			throw new TskCoreException(errorMessage, ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Validate the requests and work out the columns the caller does not
	 * supply. This is the only place the derived columns are computed, so the
	 * single-note, SQLite batch and PostgreSQL batch paths cannot disagree
	 * about them.
	 *
	 * @param requests   The requests, in caller order.
	 * @param connection Database connection to use.
	 *
	 * @return The pending notes, in request order.
	 *
	 * @throws TskCoreException if any request is invalid.
	 */
	private List<PendingNote> prepareNotes(List<NewNoteRequest> requests, CaseDbConnection connection) throws TskCoreException {
		Set<Long> objIds = new HashSet<>();
		Set<Long> parentNoteIds = new HashSet<>();
		for (int i = 0; i < requests.size(); i++) {
			NewNoteRequest request = requests.get(i);
			if (request == null) {
				throw new TskCoreException(String.format("Illegal argument passed to addNotes: request at index %d is null.", i));
			}
			objIds.add(request.getObjectId());
			request.getParentNoteId().ifPresent(parentNoteIds::add);
		}

		Map<Long, Long> dataSourceObjIds = getDataSourceObjIds(objIds, connection);
		Map<Long, ParentNote> parents = getParentNotes(parentNoteIds, connection);
		Map<Long, Map<Long, Long>> threadsByRoot = new HashMap<>();

		List<PendingNote> pending = new ArrayList<>(requests.size());
		for (int i = 0; i < requests.size(); i++) {
			NewNoteRequest request = requests.get(i);
			Long parentNoteId = request.getParentNoteId().orElse(null);
			Long rootNoteId = null;

			if (parentNoteId != null) {
				ParentNote parent = parents.get(parentNoteId);
				if (parent == null) {
					throw new TskCoreException(String.format(
							"Illegal argument passed to addNotes: request at index %d replies to note with id = %d, which does not exist.",
							i, parentNoteId));
				}
				if (parent.objId != request.getObjectId()) {
					throw new TskCoreException(String.format(
							"Illegal argument passed to addNotes: request at index %d is on object with id = %d but replies to a note on "
							+ "object with id = %d. A thread cannot span objects.", i, request.getObjectId(), parent.objId));
				}
				rootNoteId = parent.rootNoteId;
				checkThreadDepth(i, parentNoteId, rootNoteId, threadsByRoot, connection);
			}

			pending.add(new PendingNote(request.getObjectId(), dataSourceObjIds.get(request.getObjectId()),
					request.getType(), request.getBody(), request.getDetails().orElse(null), request.getAuthor(),
					request.getConfiguration().orElse(null), request.getCreatedTime(), parentNoteId, rootNoteId,
					request.getAnalysisResultId().orElse(null)));
		}
		return pending;
	}

	/**
	 * Find the data source each object belongs to.
	 *
	 * Notes are anchored on files, artifacts (analysis results included), data
	 * sources and the case object. The first three are what this places. The
	 * case object is not in a data source, and neither are the other root level
	 * objects - OS accounts, host addresses, reports - so no data source is the
	 * right answer for them. An object of some other kind comes back with none
	 * as well, rather than an error, and would then not be found by
	 * getNotesForDataSource().
	 *
	 * @param objIds     The objects.
	 * @param connection Database connection to use.
	 *
	 * @return Map of object id to data source object id, holding only the
	 *         objects that have one.
	 *
	 * @throws TskCoreException
	 */
	private Map<Long, Long> getDataSourceObjIds(Set<Long> objIds, CaseDbConnection connection) throws TskCoreException {
		Map<Long, Long> dataSourceObjIds = new HashMap<>();
		db.acquireSingleUserCaseReadLock();
		try (Statement s = connection.createStatement()) {
			for (List<Long> chunk : partitionIds(objIds)) {
				String idList = toIdList(chunk);
				// Read the data source columns directly rather than walking par_obj_id up
				// to a root: the walk would report the case object as its own data source.
				String queryString = "SELECT obj_id, data_source_obj_id FROM tsk_files WHERE obj_id IN (" + idList + ")"
						+ " UNION ALL "
						+ "SELECT artifact_obj_id, data_source_obj_id FROM blackboard_artifacts WHERE artifact_obj_id IN (" + idList + ")"
						+ " UNION ALL "
						+ "SELECT obj_id, obj_id FROM data_source_info WHERE obj_id IN (" + idList + ")";
				try (ResultSet rs = connection.executeQuery(s, queryString)) {
					while (rs.next()) {
						long dataSourceObjId = rs.getLong(2);
						if (!rs.wasNull()) {
							dataSourceObjIds.put(rs.getLong(1), dataSourceObjId);
						}
					}
				}
			}
			return dataSourceObjIds;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting the data sources of the objects being annotated", ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Read the object and thread of the notes being replied to.
	 *
	 * @param parentNoteIds The notes being replied to. May be empty.
	 * @param connection    Database connection to use.
	 *
	 * @return Map of note id to its object and thread root.
	 *
	 * @throws TskCoreException
	 */
	private Map<Long, ParentNote> getParentNotes(Set<Long> parentNoteIds, CaseDbConnection connection) throws TskCoreException {
		Map<Long, ParentNote> parents = new HashMap<>();
		if (parentNoteIds.isEmpty()) {
			return parents;
		}

		db.acquireSingleUserCaseReadLock();
		try (Statement s = connection.createStatement()) {
			for (List<Long> chunk : partitionIds(parentNoteIds)) {
				String queryString = "SELECT note_id, obj_id, root_note_id FROM tsk_notes WHERE note_id IN (" + toIdList(chunk) + ")";
				try (ResultSet rs = connection.executeQuery(s, queryString)) {
					while (rs.next()) {
						parents.put(rs.getLong("note_id"), new ParentNote(rs.getLong("obj_id"), rs.getLong("root_note_id")));
					}
				}
			}
			return parents;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting the notes being replied to", ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Check that adding a reply under the given note keeps the thread inside
	 * MAX_THREAD_DEPTH, and that walking up from it terminates. A self
	 * referencing foreign key permits A to B to A and SQL will not stop it, so
	 * the manager does. Every note in a thread shares a root note id, which
	 * makes the walk one indexed query.
	 *
	 * @param requestIndex  Index of the request, for the error message.
	 * @param parentNoteId  The note being replied to.
	 * @param rootNoteId    Root of the thread it belongs to.
	 * @param threadsByRoot Cache of note id to parent note id, per thread, so a
	 *                      batch of replies to one thread reads it once.
	 * @param connection    Database connection to use.
	 *
	 * @throws TskCoreException if the reply would be too deep, or if the thread
	 *                          contains a cycle.
	 */
	private void checkThreadDepth(int requestIndex, long parentNoteId, long rootNoteId,
			Map<Long, Map<Long, Long>> threadsByRoot, CaseDbConnection connection) throws TskCoreException {

		Map<Long, Long> parentsInThread = threadsByRoot.get(rootNoteId);
		if (parentsInThread == null) {
			parentsInThread = new HashMap<>();
			db.acquireSingleUserCaseReadLock();
			try (Statement s = connection.createStatement();
					ResultSet rs = connection.executeQuery(s,
							"SELECT note_id, parent_note_id FROM tsk_notes WHERE root_note_id = " + rootNoteId)) {

				while (rs.next()) {
					long noteId = rs.getLong("note_id");
					long parent = rs.getLong("parent_note_id");
					if (!rs.wasNull()) {
						parentsInThread.put(noteId, parent);
					}
				}
			} catch (SQLException ex) {
				throw new TskCoreException(String.format("Error reading the thread rooted at note with id = %d", rootNoteId), ex);
			} finally {
				db.releaseSingleUserCaseReadLock();
			}
			threadsByRoot.put(rootNoteId, parentsInThread);
		}

		Set<Long> visited = new HashSet<>();
		Long ancestor = parentNoteId;
		int depth = 1;
		while (ancestor != null) {
			if (!visited.add(ancestor)) {
				throw new TskCoreException(String.format(
						"Illegal argument passed to addNotes: request at index %d replies into a thread that contains a cycle at note with id = %d.",
						requestIndex, ancestor));
			}
			if (depth > MAX_THREAD_DEPTH) {
				throw new TskCoreException(String.format(
						"Illegal argument passed to addNotes: request at index %d would exceed the maximum thread depth of %d.",
						requestIndex, MAX_THREAD_DEPTH));
			}
			ancestor = parentsInThread.get(ancestor);
			depth++;
		}
	}

	/**
	 * Insert a chunk of notes as one multi-row INSERT and return their
	 * generated ids in insertion order.
	 *
	 * @param chunk      The notes to write, at most one chunk's worth for this
	 *                   engine (see PG_NOTES_CHUNK_SIZE,
	 *                   SQLITE_NOTES_CHUNK_SIZE).
	 * @param connection Database connection to use.
	 *
	 * @return The generated note ids, in the order the notes were given.
	 *
	 * @throws TskCoreException
	 */
	private List<Long> insertNotes(List<PendingNote> chunk, CaseDbConnection connection) throws TskCoreException {
		StringBuilder insertSql = new StringBuilder("INSERT INTO tsk_notes (").append(NOTE_INSERT_COLUMNS).append(") VALUES ");
		for (int i = 0; i < chunk.size(); i++) {
			if (i > 0) {
				insertSql.append(", ");
			}
			insertSql.append(NOTE_INSERT_PLACEHOLDERS);
		}
		insertSql.append(" RETURNING note_id");

		// Prepared directly rather than through the connection's ad hoc statement
		// cache, which is keyed by SQL text and would hold one entry per chunk size.
		try (PreparedStatement statement = connection.getConnection().prepareStatement(insertSql.toString())) {
			for (int i = 0; i < chunk.size(); i++) {
				setNoteParameters(statement, chunk.get(i), i * NOTE_INSERT_PARAM_COUNT);
			}

			List<Long> noteIds = new ArrayList<>(chunk.size());
			try (ResultSet rs = statement.executeQuery()) {
				while (rs.next()) {
					noteIds.add(rs.getLong(1));
				}
			}
			if (noteIds.size() != chunk.size()) {
				throw new TskCoreException(String.format("Error adding notes, wrote %d rows but expected %d",
						noteIds.size(), chunk.size()));
			}
			// note_id is a sequence consumed in VALUES order, so sorting ascending gives
			// the order the rows were given rather than relying on the order RETURNING
			// happens to emit them in.
			Collections.sort(noteIds);
			return noteIds;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error adding a batch of %d notes", chunk.size()), ex);
		}
	}

	/**
	 * Point a thread root's root_note_id at its own row. It cannot be set on
	 * the insert because it holds the row's own note id, and pre-allocating
	 * that id from the sequence is possible only on PostgreSQL, which would
	 * give the two engines different mechanisms for the column the batch paths
	 * exist to keep identical. So both engines insert it as NULL and run this
	 * one statement per batch instead.
	 *
	 * A reply already has its root note id, inherited from the note it replies
	 * to, which is why the root is coalesced rather than overwritten.
	 *
	 * @param noteIds    The notes just written.
	 * @param connection Database connection to use.
	 *
	 * @throws TskCoreException
	 */
	private void backFillRootNoteId(List<Long> noteIds, CaseDbConnection connection) throws TskCoreException {
		try (Statement s = connection.createStatement()) {
			for (List<Long> chunk : Lists.partition(noteIds, PG_NOTES_CHUNK_SIZE)) {
				connection.executeUpdate(s, "UPDATE tsk_notes SET "
						+ "root_note_id = COALESCE(root_note_id, note_id) WHERE note_id IN (" + toIdList(chunk) + ")");
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error setting the thread root of %d new notes", noteIds.size()), ex);
		}
	}

	/**
	 * Bind one note onto an insert statement, starting at the first parameter.
	 *
	 * @param statement The insert statement.
	 * @param note      The note to bind.
	 *
	 * @throws SQLException
	 */
	private static void setNoteParameters(PreparedStatement statement, PendingNote note) throws SQLException {
		setNoteParameters(statement, note, 0);
	}

	/**
	 * Bind one note onto an insert statement.
	 *
	 * @param statement The insert statement.
	 * @param note      The note to bind.
	 * @param offset    Number of parameters already bound, so a multi-row
	 *                  insert can bind row after row.
	 *
	 * @throws SQLException
	 */
	private static void setNoteParameters(PreparedStatement statement, PendingNote note, int offset) throws SQLException {
		statement.setLong(offset + 1, note.objId);
		setNullableLong(statement, offset + 2, note.dataSourceObjId);
		statement.setLong(offset + 3, note.type.getNoteTypeId());
		statement.setString(offset + 4, note.body);
		statement.setString(offset + 5, note.details);
		statement.setLong(offset + 6, note.author.getAuthorId());
		statement.setString(offset + 7, note.configuration);
		statement.setLong(offset + 8, note.createdTime);
		setNullableLong(statement, offset + 9, note.parentNoteId);
		setNullableLong(statement, offset + 10, note.rootNoteId);
		setNullableLong(statement, offset + 11, note.analysisResultId);
	}

	/**
	 * Bind a long that may be null.
	 *
	 * @param statement      The statement.
	 * @param parameterIndex Index of the parameter to bind.
	 * @param value          The value, may be null.
	 *
	 * @throws SQLException
	 */
	private static void setNullableLong(PreparedStatement statement, int parameterIndex, Long value) throws SQLException {
		if (value == null) {
			statement.setNull(parameterIndex, Types.BIGINT);
		} else {
			statement.setLong(parameterIndex, value);
		}
	}

	/**
	 * Read a long that may be null.
	 *
	 * @param rs         The result set.
	 * @param columnName Name of the column to read.
	 *
	 * @return The value, or null.
	 *
	 * @throws SQLException
	 */
	private static Long getNullableLong(ResultSet rs, String columnName) throws SQLException {
		long value = rs.getLong(columnName);
		return rs.wasNull() ? null : value;
	}

	/**
	 * Build a note from a row of a NOTE_SELECT query.
	 *
	 * @param rs The result set, positioned on the row.
	 *
	 * @return The note.
	 *
	 * @throws SQLException
	 */
	static Note getNoteFromResultSet(ResultSet rs) throws SQLException {
		NoteType type = getNoteTypeFromResultSet(rs);
		Author author = new Author(rs.getLong("author_id"), TSK_AUTHOR_TYPE_ENUM.fromID(rs.getInt("author_type")),
				rs.getString("author_name"), rs.getString("display_name"));

		return new Note(rs.getLong("note_id"), rs.getLong("obj_id"), getNullableLong(rs, "data_source_obj_id"),
				type, rs.getString("body"), rs.getString("details"), author, rs.getString("configuration"),
				rs.getLong("created_time"), getNullableLong(rs, "modified_time"), getNullableLong(rs, "parent_note_id"),
				rs.getLong("root_note_id"), rs.getInt("is_deleted") != 0, getNullableLong(rs, "analysis_result_id"));
	}

	/**
	 * Build a note type from a row that carries the type columns.
	 *
	 * @param rs The result set, positioned on the row.
	 *
	 * @return The note type.
	 *
	 * @throws SQLException
	 */
	private static NoteType getNoteTypeFromResultSet(ResultSet rs) throws SQLException {
		return new NoteType(rs.getLong("note_type_id"), rs.getString("type_name"),
				rs.getString("display_name"), rs.getString("description"));
	}

	/**
	 * Reject a missing note type.
	 *
	 * @param type The type given by the caller.
	 *
	 * @throws TskCoreException if the type is null.
	 */
	private static void requireType(NoteType type) throws TskCoreException {
		if (type == null) {
			throw new TskCoreException("Illegal argument passed to NoteManager: note type is required.");
		}
	}

	/**
	 * Reject a missing or empty set of note types.
	 *
	 * @param types The types given by the caller.
	 *
	 * @throws TskCoreException if the collection is null, empty, or holds a
	 *                          null.
	 */
	private static void requireTypes(Collection<NoteType> types) throws TskCoreException {
		if (types == null || types.isEmpty()) {
			throw new TskCoreException("Illegal argument passed to NoteManager: at least one note type is required.");
		}
		for (NoteType type : types) {
			requireType(type);
		}
	}

	/**
	 * Reject a missing or empty set of author types. The unfiltered read is a
	 * separate overload, so reaching here with nothing to filter on is a bug in
	 * the caller rather than a request for everything.
	 *
	 * @param authorTypes The author types given by the caller.
	 *
	 * @throws TskCoreException if the collection is null, empty, or holds a
	 *                          null.
	 */
	private static void requireAuthorTypes(Collection<TSK_AUTHOR_TYPE_ENUM> authorTypes) throws TskCoreException {
		if (authorTypes == null || authorTypes.isEmpty()) {
			throw new TskCoreException("Illegal argument passed to NoteManager: at least one author type is required.");
		}
		if (authorTypes.contains(null)) {
			throw new TskCoreException("Illegal argument passed to NoteManager: author type must not be null.");
		}
	}

	/**
	 * Split a collection of ids into chunks that fit comfortably in an IN
	 * clause, dropping duplicates.
	 *
	 * @param ids The ids.
	 *
	 * @return The chunks.
	 */
	private static List<List<Long>> partitionIds(Collection<Long> ids) {
		return Lists.partition(new ArrayList<>(new LinkedHashSet<>(ids)), PG_NOTES_CHUNK_SIZE);
	}

	/**
	 * Render ids as the body of an IN clause. They are written as literals
	 * rather than bound, so that a chunk is one statement whatever the
	 * parameter ceiling is.
	 *
	 * @param ids The ids, which must not be empty.
	 *
	 * @return The comma separated ids.
	 */
	private static String toIdList(Collection<Long> ids) {
		StringBuilder idList = new StringBuilder();
		for (Long id : ids) {
			if (idList.length() > 0) {
				idList.append(",");
			}
			idList.append(id);
		}
		return idList.toString();
	}

	/**
	 * A note with its derived columns resolved, ready to be written.
	 */
	private static final class PendingNote {

		private final long objId;
		private final Long dataSourceObjId;
		private final NoteType type;
		private final String body;
		private final String details;
		private final Author author;
		private final String configuration;
		private final long createdTime;
		private final Long parentNoteId;
		private final Long rootNoteId;
		private final Long analysisResultId;

		PendingNote(long objId, Long dataSourceObjId, NoteType type, String body, String details,
				Author author, String configuration, long createdTime, Long parentNoteId, Long rootNoteId,
				Long analysisResultId) {
			this.objId = objId;
			this.dataSourceObjId = dataSourceObjId;
			this.type = type;
			this.body = body;
			this.details = details;
			this.author = author;
			this.configuration = configuration;
			this.createdTime = createdTime;
			this.parentNoteId = parentNoteId;
			this.rootNoteId = rootNoteId;
			this.analysisResultId = analysisResultId;
		}

		/**
		 * Build the note this became once it was written, so that it is its own
		 * root if it starts a thread.
		 *
		 * @param noteId The generated note id.
		 *
		 * @return The note.
		 */
		Note toNote(long noteId) {
			return new Note(noteId, objId, dataSourceObjId, type, body, details, author, configuration, createdTime,
					null, parentNoteId, rootNoteId == null ? noteId : rootNoteId, false, analysisResultId);
		}
	}

	/**
	 * The parts of a note being replied to that a reply needs.
	 */
	private static final class ParentNote {

		private final long objId;
		private final long rootNoteId;

		ParentNote(long objId, long rootNoteId) {
			this.objId = objId;
			this.rootNoteId = rootNoteId;
		}
	}
}
