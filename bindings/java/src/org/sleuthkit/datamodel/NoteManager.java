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

/**
 * Responsible for creating, revising, deleting and retrieving Notes.
 *
 * Reads do not filter. Superseded revisions and soft-deleted rows come back
 * along with everything else and the caller decides what to render, so no
 * method quietly drops a row. The narrower reads - getCurrentNotes(),
 * getCurrentRevision(), getCurrentNoteCounts() - are opt-in.
 *
 * This manager enforces no permissions. It exposes the author kind and author
 * id so a consumer can decide who may act, and that is the whole contract. The
 * one rule here that looks like policy, reviseNote() requiring the same author,
 * is not: it holds a property of the data, that every revision in a lineage has
 * one author, so that "who wrote this" has a single answer no matter which
 * revision you are looking at.
 */
public final class NoteManager {

	/**
	 * Maximum number of notes per PostgreSQL batch chunk in addNotes().
	 * Internal chunking unit; callers may pass any number of requests and the
	 * manager partitions.
	 *
	 * Sized to keep the tsk_notes INSERT (13 bound columns per row) under
	 * PostgreSQL's 65,535 bind-parameter ceiling: 4000 rows = 52,000
	 * parameters.
	 */
	static final int PG_NOTES_CHUNK_SIZE = 4000;

	/**
	 * Maximum reply depth in a thread. SQL cannot express this, so the manager
	 * has to, alongside the cycle check in checkThreadDepth().
	 */
	private static final int MAX_THREAD_DEPTH = 100;

	/**
	 * The bound columns of an insert, in order. original_note_id is left to its
	 * default of NULL and back-filled, and is_current / is_deleted take their
	 * column defaults.
	 */
	private static final String NOTE_INSERT_COLUMNS
			= "obj_id, data_source_obj_id, note_type_id, body, details, "
			+ "author_kind, author_id, author_display, config_id, created_time, "
			+ "parent_note_id, root_note_id, analysis_result_id";

	private static final String NOTE_INSERT_PLACEHOLDERS = "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

	private static final int NOTE_INSERT_PARAM_COUNT = 13;

	/**
	 * Reads join the type table rather than caching it, so a type added by
	 * another client of the same PostgreSQL case database is never missing.
	 */
	private static final String NOTE_SELECT
			= "SELECT notes.note_id, notes.obj_id, notes.data_source_obj_id, notes.note_type_id, "
			+ "notes.body, notes.details, notes.author_kind, notes.author_id, notes.author_display, "
			+ "notes.config_id, notes.created_time, notes.parent_note_id, notes.root_note_id, "
			+ "notes.original_note_id, notes.is_current, notes.is_deleted, notes.analysis_result_id, "
			+ "types.type_name, types.display_name, types.description "
			+ "FROM tsk_notes notes "
			+ "INNER JOIN tsk_note_types types ON notes.note_type_id = types.note_type_id ";

	/**
	 * Oldest first, ties broken on note id. created_time is milliseconds, but
	 * two notes written in the same millisecond still need a stable order.
	 */
	private static final String NOTE_ORDER = " ORDER BY notes.created_time, notes.note_id";

	/**
	 * What a delete does to the row. The schema supports both; which one a user
	 * gets is the consumer's ruling.
	 */
	public enum DeleteMode {

		/**
		 * Remove the rows. This takes the whole revision lineage of the note
		 * and, through the parent_note_id cascade, its reply subtree with it.
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
	public NoteType getOrAddNoteType(String typeName, String displayName) throws TskCoreException {
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
	public NoteType getOrAddNoteType(String typeName, String displayName, String description) throws TskCoreException {
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
	 * Get all note types, both the built-in ones and any a consumer has added.
	 *
	 * @return The note types.
	 *
	 * @throws TskCoreException
	 */
	public List<NoteType> getNoteTypes() throws TskCoreException {
		String queryString = "SELECT note_type_id, type_name, display_name, description FROM tsk_note_types ORDER BY type_name";

		List<NoteType> types = new ArrayList<>();
		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = db.getConnection();
				Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			while (rs.next()) {
				types.add(getNoteTypeFromResultSet(rs));
			}
			return types;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting note types", ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Add a note, in its own transaction.
	 *
	 * @param request The note to add.
	 *
	 * @return The note as written, with its derived columns filled in.
	 *
	 * @throws TskCoreException
	 */
	public Note addNote(NoteRequest request) throws TskCoreException {
		CaseDbTransaction trans = db.beginTransaction();
		try {
			Note note = addNote(request, trans);
			trans.commit();
			trans = null;
			return note;
		} finally {
			if (trans != null) {
				trans.rollback();
			}
		}
	}

	/**
	 * Add a note as part of the caller's transaction.
	 *
	 * This delegates to addNotes() rather than duplicating the insert, so the
	 * single-note and batch paths cannot drift on how data_source_obj_id,
	 * root_note_id and original_note_id are derived.
	 *
	 * @param request The note to add.
	 * @param trans   Transaction to use.
	 *
	 * @return The note as written, with its derived columns filled in.
	 *
	 * @throws TskCoreException
	 */
	public Note addNote(NoteRequest request, CaseDbTransaction trans) throws TskCoreException {
		if (request == null) {
			throw new TskCoreException("Illegal argument passed to addNote: request is required.");
		}
		return addNotes(Collections.singletonList(request), trans).get(0);
	}

	/**
	 * Add notes as part of the caller's transaction.
	 *
	 * A batch is one transaction: if any request is invalid nothing is written
	 * and the exception names the offending index. One event is fired for the
	 * whole batch, after the caller commits.
	 *
	 * On PostgreSQL the requests are partitioned at PG_NOTES_CHUNK_SIZE and
	 * each chunk is written as one multi-row INSERT. On SQLite, whose in-process
	 * driver makes cross-row batching unprofitable, each row is inserted on its
	 * own. Both engines then run the same back-fill statement, so the derived
	 * columns are set by one piece of SQL rather than two.
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
	public List<Note> addNotes(List<NoteRequest> requests, CaseDbTransaction trans) throws TskCoreException {
		return addNotes(requests, trans, db.getDatabaseType() == DbType.POSTGRESQL);
	}

	/**
	 * Add notes as part of the caller's transaction, choosing how the rows are
	 * written rather than letting the engine decide.
	 *
	 * The multi-row INSERT is not PostgreSQL specific SQL, only the decision to
	 * prefer it is, so this exists to let the test suite run the batched path
	 * against SQLite and check it against the row at a time path. Production
	 * code should call the two argument form.
	 *
	 * @param requests The notes to add. May be empty. Must not be null.
	 * @param trans    Transaction to use.
	 * @param batched  True to write each chunk as one multi-row INSERT, false
	 *                 to insert a row at a time.
	 *
	 * @return The notes as written, in request order.
	 *
	 * @throws TskCoreException
	 */
	List<Note> addNotes(List<NoteRequest> requests, CaseDbTransaction trans, boolean batched) throws TskCoreException {
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

		List<Long> noteIds = new ArrayList<>(pending.size());
		if (batched) {
			for (List<PendingNote> chunk : Lists.partition(pending, PG_NOTES_CHUNK_SIZE)) {
				noteIds.addAll(insertNotesBatched(chunk, connection));
			}
		} else {
			for (PendingNote note : pending) {
				noteIds.add(insertNote(note, connection));
			}
		}

		backFillSelfReferences(noteIds, connection);

		List<Note> notes = new ArrayList<>(pending.size());
		for (int i = 0; i < pending.size(); i++) {
			notes.add(pending.get(i).toNote(noteIds.get(i)));
		}
		trans.registerAddedNotes(notes);
		return notes;
	}

	/**
	 * Revise a note, in its own transaction.
	 *
	 * @param noteId  Id of the revision being replaced. It must be the current
	 *                revision of its lineage.
	 * @param body    The new prose. Required.
	 * @param details The new structured payload, may be null.
	 * @param author  Who is revising. The author id must match the note's, and
	 *                the config id may have moved on.
	 *
	 * @return The new current revision.
	 *
	 * @throws TskCoreException
	 */
	public Note reviseNote(long noteId, String body, String details, Note.Author author) throws TskCoreException {
		CaseDbTransaction trans = db.beginTransaction();
		try {
			Note revision = reviseNote(noteId, body, details, author, trans);
			trans.commit();
			trans = null;
			return revision;
		} finally {
			if (trans != null) {
				trans.rollback();
			}
		}
	}

	/**
	 * Revise a note as part of the caller's transaction.
	 *
	 * Nothing is rewritten in place. The previous revision keeps its row and
	 * stops being current, and a new row is inserted carrying the same original
	 * note id, so the earlier text survives and anything pointing at the note
	 * still resolves. The partial unique index on (original_note_id) where
	 * is_current = 1 makes it impossible for two writers to both leave the
	 * lineage with a current revision; the loser gets a constraint violation it
	 * can retry.
	 *
	 * You revise your own note. You reply to someone else's - there is no
	 * operation that rewrites another person's words under their name.
	 *
	 * @param noteId  Id of the revision being replaced. It must be the current
	 *                revision of its lineage.
	 * @param body    The new prose. Required.
	 * @param details The new structured payload, may be null.
	 * @param author  Who is revising. The author id must match the note's, and
	 *                the config id may have moved on.
	 * @param trans   Transaction to use.
	 *
	 * @return The new current revision.
	 *
	 * @throws TskCoreException
	 */
	public Note reviseNote(long noteId, String body, String details, Note.Author author, CaseDbTransaction trans) throws TskCoreException {
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

		if (!existing.isCurrent()) {
			throw new TskCoreException(String.format("Cannot revise note with id = %d, it has already been superseded. "
					+ "Use getCurrentRevision(%d) to find the revision to revise.", noteId, existing.getOriginalNoteId()));
		}
		if (existing.isDeleted()) {
			// Without this the new row would take the is_deleted default of 0 and quietly
			// bring a retracted note back. A retraction stands; write a new note instead.
			throw new TskCoreException(String.format("Cannot revise note with id = %d, it has been deleted.", noteId));
		}
		if (!existing.getAuthor().getId().equals(author.getId())) {
			throw new TskCoreException(String.format("Cannot revise note with id = %d, it was written by a different author. "
					+ "Reply to it instead.", noteId));
		}

		try {
			// Clear the old revision first. Doing it the other way round would put two
			// current rows in the lineage for the length of a statement, which the
			// unique index rejects.
			PreparedStatement clear = connection.getPreparedStatement(
					"UPDATE tsk_notes SET is_current = 0 WHERE note_id = ?", Statement.NO_GENERATED_KEYS);
			clear.clearParameters();
			clear.setLong(1, noteId);
			connection.executeUpdate(clear);

			String insertSql = "INSERT INTO tsk_notes (" + NOTE_INSERT_COLUMNS + ", original_note_id) "
					+ "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
			PreparedStatement insert = connection.getPreparedStatement(insertSql, Statement.RETURN_GENERATED_KEYS);
			insert.clearParameters();

			PendingNote revision = new PendingNote(existing.getObjectId(),
					existing.getDataSourceObjectId().orElse(null), existing.getType(), body, details, author,
					System.currentTimeMillis(), existing.getParentNoteId().orElse(null), existing.getRootNoteId(),
					existing.getAnalysisResultId().orElse(null));
			setNoteParameters(insert, revision);
			insert.setLong(NOTE_INSERT_PARAM_COUNT + 1, existing.getOriginalNoteId());
			connection.executeUpdate(insert);

			long revisionId;
			try (ResultSet rs = insert.getGeneratedKeys()) {
				if (!rs.next()) {
					throw new TskCoreException(String.format("Error reading back the revision of note with id = %d", noteId));
				}
				revisionId = rs.getLong(1);
			}

			Note note = revision.toNote(revisionId, existing.getOriginalNoteId());
			trans.registerUpdatedNote(note);
			return note;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error revising note with id = %d", noteId), ex);
		}
	}

	/**
	 * Delete a note, in its own transaction.
	 *
	 * @param noteId Id of the note to delete.
	 * @param mode   Whether to remove the rows or mark the note deleted.
	 *
	 * @throws TskCoreException
	 */
	public void deleteNote(long noteId, DeleteMode mode) throws TskCoreException {
		deleteNotes(Collections.singletonList(noteId), mode);
	}

	/**
	 * Delete notes, in one transaction.
	 *
	 * Both modes act on the whole revision lineage of each named note, so it
	 * does not matter whether the caller holds a revision id or the stable
	 * original note id - the id an analysis result's TSK_NOTE_ID attribute
	 * carries. A hard delete removes the lineage and, through the
	 * parent_note_id cascade, the replies underneath it; it has to take the
	 * whole lineage, since the later revisions reference the first one and
	 * deleting that row on its own would be a foreign key violation. A soft
	 * delete marks the lineage deleted and leaves the rows, and the replies,
	 * alone.
	 *
	 * The fired event names the notes the caller asked to delete, not the other
	 * rows that went with them.
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
		CaseDbTransaction trans = db.beginTransaction();
		try {
			CaseDbConnection connection = trans.getConnection();
			try (Statement s = connection.createStatement()) {
				for (List<Long> chunk : Lists.partition(requested, PG_NOTES_CHUNK_SIZE)) {
					// Resolve the lineages first, in two steps rather than a subquery on
					// the table being written to. Both modes work on lineages, so a caller
					// holding either a revision id or the stable original id gets the same
					// answer.
					List<Long> lineageIds = new ArrayList<>();
					try (ResultSet rs = connection.executeQuery(s, "SELECT DISTINCT original_note_id FROM tsk_notes "
							+ "WHERE note_id IN (" + toIdList(chunk) + ")")) {
						while (rs.next()) {
							lineageIds.add(rs.getLong(1));
						}
					}
					if (lineageIds.isEmpty()) {
						continue;
					}

					if (mode == DeleteMode.SOFT) {
						connection.executeUpdate(s, "UPDATE tsk_notes SET is_deleted = 1 WHERE original_note_id IN (" + toIdList(lineageIds) + ")");
					} else {
						connection.executeUpdate(s, "DELETE FROM tsk_notes WHERE original_note_id IN (" + toIdList(lineageIds) + ")");
					}
				}
			}

			trans.registerDeletedNotes(requested);
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
	 * Get every note on an object, of every type. Superseded revisions and
	 * soft-deleted notes are included.
	 *
	 * @param objId The object.
	 *
	 * @return The notes, oldest first.
	 *
	 * @throws TskCoreException
	 */
	public List<Note> getNotes(long objId) throws TskCoreException {
		return getNotes(NOTE_SELECT + "WHERE notes.obj_id = " + objId + NOTE_ORDER,
				String.format("Error getting notes for object with id = %d", objId));
	}

	/**
	 * Get every note of one type on an object. Superseded revisions and
	 * soft-deleted notes are included.
	 *
	 * @param objId The object.
	 * @param type  The note type. Required.
	 *
	 * @return The notes, oldest first.
	 *
	 * @throws TskCoreException
	 */
	public List<Note> getNotes(long objId, NoteType type) throws TskCoreException {
		requireType(type);
		return getNotes(NOTE_SELECT + "WHERE notes.obj_id = " + objId
				+ " AND notes.note_type_id = " + type.getNoteTypeId() + NOTE_ORDER,
				String.format("Error getting %s notes for object with id = %d", type.getTypeName(), objId));
	}

	/**
	 * Get the live notes of one type on an object, that is the current revision
	 * of each note. This is a list rather than an Optional: nothing guarantees
	 * one live note per object and type, and two models writing enrichment
	 * about one item is not an error.
	 *
	 * Soft-deleted notes are still included; only superseded revisions are
	 * dropped.
	 *
	 * @param objId The object.
	 * @param type  The note type. Required.
	 *
	 * @return The current revisions, oldest first.
	 *
	 * @throws TskCoreException
	 */
	public List<Note> getCurrentNotes(long objId, NoteType type) throws TskCoreException {
		requireType(type);
		return getNotes(NOTE_SELECT + "WHERE notes.obj_id = " + objId
				+ " AND notes.note_type_id = " + type.getNoteTypeId()
				+ " AND notes.is_current = 1" + NOTE_ORDER,
				String.format("Error getting current %s notes for object with id = %d", type.getTypeName(), objId));
	}

	/**
	 * Get the live revision of one note. This is what an analysis result's
	 * TSK_NOTE_ID attribute resolves to, since that attribute holds the
	 * original note id and never a revision id.
	 *
	 * @param originalNoteId The stable id of the note.
	 *
	 * @return Optional with the current revision. Optional.empty if no note
	 *         with that original id exists.
	 *
	 * @throws TskCoreException
	 */
	public Optional<Note> getCurrentRevision(long originalNoteId) throws TskCoreException {
		List<Note> notes = getNotes(NOTE_SELECT + "WHERE notes.original_note_id = " + originalNoteId
				+ " AND notes.is_current = 1",
				String.format("Error getting the current revision of note with original id = %d", originalNoteId));
		return notes.isEmpty() ? Optional.empty() : Optional.of(notes.get(0));
	}

	/**
	 * Get a whole thread in one query.
	 *
	 * @param rootNoteId The root of the thread. A thread root is its own root,
	 *                   so this is the note id of the first note in the thread.
	 *
	 * @return The notes in the thread, oldest first.
	 *
	 * @throws TskCoreException
	 */
	public List<Note> getThread(long rootNoteId) throws TskCoreException {
		return getNotes(NOTE_SELECT + "WHERE notes.root_note_id = " + rootNoteId + NOTE_ORDER,
				String.format("Error getting the thread rooted at note with id = %d", rootNoteId));
	}

	/**
	 * Get the full edit history of one note.
	 *
	 * @param originalNoteId The stable id of the note.
	 *
	 * @return Every revision of the note, oldest first.
	 *
	 * @throws TskCoreException
	 */
	public List<Note> getRevisions(long originalNoteId) throws TskCoreException {
		return getNotes(NOTE_SELECT + "WHERE notes.original_note_id = " + originalNoteId + NOTE_ORDER,
				String.format("Error getting the revisions of note with original id = %d", originalNoteId));
	}

	/**
	 * Get the notes of one type on many objects, in one query per chunk. This
	 * is what a table of items uses when it needs the notes themselves.
	 *
	 * @param objIds The objects.
	 * @param type   The note type. Required.
	 *
	 * @return Map of object id to its notes, oldest first. Objects with no
	 *         matching note are absent from the map.
	 *
	 * @throws TskCoreException
	 */
	public Map<Long, List<Note>> getNotes(Collection<Long> objIds, NoteType type) throws TskCoreException {
		requireType(type);
		if (objIds == null) {
			throw new TskCoreException("Illegal argument passed to getNotes: object ids are required.");
		}

		Map<Long, List<Note>> notesByObject = new HashMap<>();
		for (List<Long> chunk : partitionIds(objIds)) {
			List<Note> notes = getNotes(NOTE_SELECT + "WHERE notes.obj_id IN (" + toIdList(chunk) + ")"
					+ " AND notes.note_type_id = " + type.getNoteTypeId() + NOTE_ORDER,
					String.format("Error getting %s notes for %d objects", type.getTypeName(), chunk.size()));
			for (Note note : notes) {
				notesByObject.computeIfAbsent(note.getObjectId(), key -> new ArrayList<>()).add(note);
			}
		}
		return notesByObject;
	}

	/**
	 * Count the notes of one type on many objects, without loading any prose.
	 * A table showing hundreds of items and a note badge on each is the reason
	 * this exists: reading every body to count them is the obvious N+1 trap.
	 *
	 * Like the other broad reads this counts everything, so every revision of a
	 * note counts separately and retracted notes are included. Use
	 * getCurrentNoteCounts() for a badge.
	 *
	 * @param objIds The objects.
	 * @param type   The note type. Required.
	 *
	 * @return Map of object id to note count. Objects with no matching note are
	 *         absent from the map.
	 *
	 * @throws TskCoreException
	 */
	public Map<Long, Integer> getNoteCounts(Collection<Long> objIds, NoteType type) throws TskCoreException {
		return getNoteCounts(objIds, type, false);
	}

	/**
	 * Count the live notes of one type on many objects, without loading any
	 * prose. This is the count a note badge wants: one per note rather than one
	 * per revision.
	 *
	 * This is the exact counterpart of getCurrentNotes(): it counts the same
	 * rows that method returns, retracted notes included. Whether a retraction
	 * is shown is the consumer's ruling, and it has to be the same ruling for
	 * the badge and for the list behind it.
	 *
	 * @param objIds The objects.
	 * @param type   The note type. Required.
	 *
	 * @return Map of object id to note count. Objects with no matching note are
	 *         absent from the map.
	 *
	 * @throws TskCoreException
	 */
	public Map<Long, Integer> getCurrentNoteCounts(Collection<Long> objIds, NoteType type) throws TskCoreException {
		return getNoteCounts(objIds, type, true);
	}

	/**
	 * Get the notes of one type anywhere in a data source.
	 *
	 * This finds notes on the objects the manager can place in a data source -
	 * files, artifacts and the data source itself. Notes on the case object are
	 * not in any data source and never appear here.
	 *
	 * @param dataSourceObjId The data source.
	 * @param type            The note type. Required.
	 *
	 * @return The notes, oldest first.
	 *
	 * @throws TskCoreException
	 */
	public List<Note> getNotesForDataSource(long dataSourceObjId, NoteType type) throws TskCoreException {
		requireType(type);
		return getNotes(NOTE_SELECT + "WHERE notes.data_source_obj_id = " + dataSourceObjId
				+ " AND notes.note_type_id = " + type.getNoteTypeId() + NOTE_ORDER,
				String.format("Error getting %s notes for data source with id = %d", type.getTypeName(), dataSourceObjId));
	}

	/**
	 * Get one note by the id of the revision.
	 *
	 * @param noteId The note id.
	 *
	 * @return Optional with the note. Optional.empty if there is no such note.
	 *
	 * @throws TskCoreException
	 */
	public Optional<Note> getNoteById(long noteId) throws TskCoreException {
		try (CaseDbConnection connection = db.getConnection()) {
			return getNoteById(noteId, connection);
		}
	}

	/**
	 * Get one note by the id of the revision.
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
	 * Count the notes of one type on many objects.
	 *
	 * @param objIds      The objects.
	 * @param type        The note type.
	 * @param currentOnly True to count only live, undeleted notes.
	 *
	 * @return Map of object id to note count.
	 *
	 * @throws TskCoreException
	 */
	private Map<Long, Integer> getNoteCounts(Collection<Long> objIds, NoteType type, boolean currentOnly) throws TskCoreException {
		requireType(type);
		if (objIds == null) {
			throw new TskCoreException("Illegal argument passed to getNoteCounts: object ids are required.");
		}

		Map<Long, Integer> countsByObject = new HashMap<>();
		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = db.getConnection();
				Statement s = connection.createStatement()) {

			for (List<Long> chunk : partitionIds(objIds)) {
				String queryString = "SELECT obj_id, COUNT(*) AS count FROM tsk_notes "
						+ "WHERE obj_id IN (" + toIdList(chunk) + ")"
						+ " AND note_type_id = " + type.getNoteTypeId()
						+ (currentOnly ? " AND is_current = 1" : "")
						+ " GROUP BY obj_id";
				try (ResultSet rs = connection.executeQuery(s, queryString)) {
					while (rs.next()) {
						countsByObject.put(rs.getLong("obj_id"), rs.getInt("count"));
					}
				}
			}
			return countsByObject;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error counting %s notes", type.getTypeName()), ex);
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
	private List<PendingNote> prepareNotes(List<NoteRequest> requests, CaseDbConnection connection) throws TskCoreException {
		Set<Long> objIds = new HashSet<>();
		Set<Long> parentNoteIds = new HashSet<>();
		for (int i = 0; i < requests.size(); i++) {
			NoteRequest request = requests.get(i);
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
			NoteRequest request = requests.get(i);
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
					request.getCreatedTime(), parentNoteId, rootNoteId, request.getAnalysisResultId().orElse(null)));
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
	 * Insert one note and return its generated id.
	 *
	 * @param note       The note to write.
	 * @param connection Database connection to use.
	 *
	 * @return The generated note id.
	 *
	 * @throws TskCoreException
	 */
	private long insertNote(PendingNote note, CaseDbConnection connection) throws TskCoreException {
		String insertSql = "INSERT INTO tsk_notes (" + NOTE_INSERT_COLUMNS + ") VALUES " + NOTE_INSERT_PLACEHOLDERS;
		try {
			PreparedStatement statement = connection.getPreparedStatement(insertSql, Statement.RETURN_GENERATED_KEYS);
			statement.clearParameters();
			setNoteParameters(statement, note);
			connection.executeUpdate(statement);

			try (ResultSet rs = statement.getGeneratedKeys()) {
				if (!rs.next()) {
					throw new TskCoreException(String.format("Error adding note on object with id = %d", note.objId));
				}
				return rs.getLong(1);
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error adding note on object with id = %d", note.objId), ex);
		}
	}

	/**
	 * Insert a chunk of notes as one multi-row INSERT and return their
	 * generated ids in insertion order.
	 *
	 * @param chunk      The notes to write, at most PG_NOTES_CHUNK_SIZE of
	 *                   them.
	 * @param connection Database connection to use.
	 *
	 * @return The generated note ids, in the order the notes were given.
	 *
	 * @throws TskCoreException
	 */
	private List<Long> insertNotesBatched(List<PendingNote> chunk, CaseDbConnection connection) throws TskCoreException {
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
	 * Point the self-referencing columns of newly inserted notes at their own
	 * rows. They cannot be set on the insert because they hold the row's own
	 * note id, and pre-allocating that id from the sequence is possible only on
	 * PostgreSQL, which would give the two engines different mechanisms for the
	 * two columns the batch paths exist to keep identical. So both engines
	 * insert them as NULL and run this one statement per batch instead.
	 *
	 * A reply already has its root note id, inherited from the note it replies
	 * to, which is why the root is coalesced rather than overwritten.
	 *
	 * @param noteIds    The notes just written.
	 * @param connection Database connection to use.
	 *
	 * @throws TskCoreException
	 */
	private void backFillSelfReferences(List<Long> noteIds, CaseDbConnection connection) throws TskCoreException {
		try (Statement s = connection.createStatement()) {
			for (List<Long> chunk : Lists.partition(noteIds, PG_NOTES_CHUNK_SIZE)) {
				connection.executeUpdate(s, "UPDATE tsk_notes SET original_note_id = note_id, "
						+ "root_note_id = COALESCE(root_note_id, note_id) WHERE note_id IN (" + toIdList(chunk) + ")");
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error setting the thread and revision ids of %d new notes", noteIds.size()), ex);
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
		statement.setInt(offset + 6, note.author.getKind().getId());
		statement.setString(offset + 7, note.author.getId());
		statement.setString(offset + 8, note.author.getDisplayName());
		statement.setString(offset + 9, note.author.getConfigId().orElse(null));
		statement.setLong(offset + 10, note.createdTime);
		setNullableLong(statement, offset + 11, note.parentNoteId);
		setNullableLong(statement, offset + 12, note.rootNoteId);
		setNullableLong(statement, offset + 13, note.analysisResultId);
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
	private static Note getNoteFromResultSet(ResultSet rs) throws SQLException {
		NoteType type = getNoteTypeFromResultSet(rs);
		Note.Author author = new Note.Author(Note.AuthorKind.fromID(rs.getInt("author_kind")),
				rs.getString("author_id"), rs.getString("author_display"), rs.getString("config_id"));

		return new Note(rs.getLong("note_id"), rs.getLong("obj_id"), getNullableLong(rs, "data_source_obj_id"),
				type, rs.getString("body"), rs.getString("details"), author, rs.getLong("created_time"),
				getNullableLong(rs, "parent_note_id"), rs.getLong("root_note_id"), rs.getLong("original_note_id"),
				rs.getInt("is_current") != 0, rs.getInt("is_deleted") != 0, getNullableLong(rs, "analysis_result_id"));
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
		private final Note.Author author;
		private final long createdTime;
		private final Long parentNoteId;
		private final Long rootNoteId;
		private final Long analysisResultId;

		PendingNote(long objId, Long dataSourceObjId, NoteType type, String body, String details,
				Note.Author author, long createdTime, Long parentNoteId, Long rootNoteId, Long analysisResultId) {
			this.objId = objId;
			this.dataSourceObjId = dataSourceObjId;
			this.type = type;
			this.body = body;
			this.details = details;
			this.author = author;
			this.createdTime = createdTime;
			this.parentNoteId = parentNoteId;
			this.rootNoteId = rootNoteId;
			this.analysisResultId = analysisResultId;
		}

		/**
		 * Build the note this became once it was written as a first version, so
		 * that it is its own original and, if it starts a thread, its own root.
		 *
		 * @param noteId The generated note id.
		 *
		 * @return The note.
		 */
		Note toNote(long noteId) {
			return toNote(noteId, noteId);
		}

		/**
		 * Build the note this became once it was written.
		 *
		 * @param noteId         The generated note id.
		 * @param originalNoteId The lineage this note belongs to.
		 *
		 * @return The note.
		 */
		Note toNote(long noteId, long originalNoteId) {
			return new Note(noteId, objId, dataSourceObjId, type, body, details, author, createdTime,
					parentNoteId, rootNoteId == null ? noteId : rootNoteId, originalNoteId, true, false, analysisResultId);
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
