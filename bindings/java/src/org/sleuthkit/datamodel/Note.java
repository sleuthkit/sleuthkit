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

import java.util.Optional;

/**
 * Text that belongs to an object in the case, has no score, and can change
 * after it is written. Comments, AI enrichment, remediation advice and
 * summaries are all notes.
 *
 * A note is edited in place: revising it updates the row and sets
 * modifiedTime, rather than writing a new row. Its own note id is therefore
 * stable for the life of the note, which is what outside references (the
 * TSK_ASSOCIATED_NOTE_ID attribute) point at.
 *
 * Instances are immutable snapshots of a row. Use NoteManager to create,
 * revise and read them.
 */
public final class Note {

	private final long noteId;
	private final long objId;
	private final Long dataSourceObjId;
	private final NoteType type;
	private final String body;
	private final String payload;
	private final Author author;
	private final String configuration;
	private final long createdTime;
	private final Long modifiedTime;
	private final Long parentNoteId;
	private final long rootNoteId;
	private final boolean isDeleted;
	private final Long analysisResultId;

	/**
	 * Constructs a note from a persisted row.
	 *
	 * @param noteId           Id of this note. Stable for its whole life.
	 * @param objId            Object the note is about.
	 * @param dataSourceObjId  Data source the object belongs to, null for a
	 *                         case level note.
	 * @param type             Note type.
	 * @param body             The prose a person reads.
	 * @param payload          Structured payload as JSON, may be null. The
	 *                         Sleuth Kit never parses it.
	 * @param author           Who wrote it.
	 * @param configuration    Prompt or module configuration version that
	 *                         produced the note, may be null.
	 * @param createdTime      Creation time, epoch milliseconds.
	 * @param modifiedTime     Time of the last edit, epoch milliseconds, null
	 *                         unless the note has been revised.
	 * @param parentNoteId     Note this one replies to, null on a thread root.
	 * @param rootNoteId       Root of the thread, own note id on a root.
	 * @param isDeleted        True if this note has been retracted.
	 * @param analysisResultId The scored finding this note explains, null if it
	 *                         explains none.
	 */
	Note(long noteId, long objId, Long dataSourceObjId, NoteType type, String body, String payload,
			Author author, String configuration, long createdTime, Long modifiedTime, Long parentNoteId,
			long rootNoteId, boolean isDeleted, Long analysisResultId) {
		this.noteId = noteId;
		this.objId = objId;
		this.dataSourceObjId = dataSourceObjId;
		this.type = type;
		this.body = body;
		this.payload = payload;
		this.author = author;
		this.configuration = configuration;
		this.createdTime = createdTime;
		this.modifiedTime = modifiedTime;
		this.parentNoteId = parentNoteId;
		this.rootNoteId = rootNoteId;
		this.isDeleted = isDeleted;
		this.analysisResultId = analysisResultId;
	}

	/**
	 * Gets the id of this note. Stable for the whole life of the note, since
	 * it is edited in place rather than replaced by a new row.
	 *
	 * @return The note id.
	 */
	public long getNoteId() {
		return noteId;
	}

	/**
	 * Gets the object this note is about. It may be a file, an artifact, an
	 * analysis result, a data source or the case object.
	 *
	 * @return The object id.
	 */
	public long getObjectId() {
		return objId;
	}

	/**
	 * Gets the data source the object belongs to. Derived by NoteManager when
	 * the note is written, not supplied by the caller.
	 *
	 * @return Optional with the data source object id, empty for a note on the
	 *         case object or on anything else outside a data source.
	 */
	public Optional<Long> getDataSourceObjectId() {
		return Optional.ofNullable(dataSourceObjId);
	}

	/**
	 * Gets the type of this note.
	 *
	 * @return The note type.
	 */
	public NoteType getType() {
		return type;
	}

	/**
	 * Gets the prose a person reads.
	 *
	 * @return The body.
	 */
	public String getBody() {
		return body;
	}

	/**
	 * Gets the structured payload that goes with the prose, as JSON. The Sleuth
	 * Kit stores it and never parses it.
	 *
	 * @return Optional with the payload, empty if there is none.
	 */
	public Optional<String> getPayload() {
		return Optional.ofNullable(payload);
	}

	/**
	 * Gets who wrote this note.
	 *
	 * @return The author.
	 */
	public Author getAuthor() {
		return author;
	}

	/**
	 * Gets the prompt or module configuration version that produced this
	 * note.
	 *
	 * @return Optional with the configuration, empty if there is none.
	 */
	public Optional<String> getConfiguration() {
		return Optional.ofNullable(configuration);
	}

	/**
	 * Gets the creation time of this note, in epoch milliseconds.
	 * Milliseconds rather than seconds because ordering collaborative comments
	 * needs sub-second resolution. Ties break on note id.
	 *
	 * @return The creation time.
	 */
	public long getCreatedTime() {
		return createdTime;
	}

	/**
	 * Gets the time of the last edit to this note, in epoch milliseconds.
	 *
	 * @return Optional with the modified time, empty if the note has never
	 *         been revised.
	 */
	public Optional<Long> getModifiedTime() {
		return Optional.ofNullable(modifiedTime);
	}

	/**
	 * Gets the note this one replies to.
	 *
	 * @return Optional with the parent note id, empty on a thread root.
	 */
	public Optional<Long> getParentNoteId() {
		return Optional.ofNullable(parentNoteId);
	}

	/**
	 * Gets the root of the thread this note belongs to. A thread root is its
	 * own root. Reading a whole thread is one indexed query on this value.
	 *
	 * @return The root note id.
	 */
	public long getRootNoteId() {
		return rootNoteId;
	}

	/**
	 * Indicates whether this note has been retracted with a soft delete. The
	 * row is kept so that replies stay reachable.
	 *
	 * @return True if the note is deleted.
	 */
	public boolean isDeleted() {
		return isDeleted;
	}

	/**
	 * Gets the scored finding whose reasoning this note holds. This is not the
	 * same as a note anchored on a finding through getObjectId(), which is
	 * someone discussing the finding rather than explaining it.
	 *
	 * @return Optional with the analysis result object id, empty if this note
	 *         explains no finding.
	 */
	public Optional<Long> getAnalysisResultId() {
		return Optional.ofNullable(analysisResultId);
	}
}
