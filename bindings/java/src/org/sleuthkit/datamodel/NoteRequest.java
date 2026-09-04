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
 * Per-note request data for NoteManager.addNote() and NoteManager.addNotes().
 *
 * This carries only what a caller supplies. The derived columns -
 * data_source_obj_id, root_note_id and original_note_id - are computed by
 * NoteManager and are deliberately not settable here, so that the single-row
 * and batch write paths cannot disagree about them.
 */
public final class NoteRequest {

	private final long objId;
	private final NoteType type;
	private final String body;
	private final String details;
	private final Note.Author author;
	private final Long parentNoteId;
	private final Long analysisResultId;
	private final long createdTime;

	/**
	 * Constructs a request for a note with no structured payload, that starts
	 * its own thread and explains no finding.
	 *
	 * @param objId  Object the note is about. It may be a file, an artifact, an
	 *               analysis result, a data source or the case object.
	 * @param type   Note type. Required.
	 * @param body   The prose a person reads. Required.
	 * @param author Who wrote it. Required.
	 */
	public NoteRequest(long objId, NoteType type, String body, Note.Author author) {
		this(objId, type, body, null, author, null, null, null);
	}

	/**
	 * Constructs a request for a note.
	 *
	 * @param objId            Object the note is about. A reply must name the
	 *                         same object as the note it replies to, so that a
	 *                         thread cannot span objects.
	 * @param type             Note type. Required.
	 * @param body             The prose a person reads. Required.
	 * @param details          Structured payload as JSON, may be null. The
	 *                         Sleuth Kit stores it and never parses it.
	 * @param author           Who wrote it. Required.
	 * @param parentNoteId     Note this one replies to, null to start a thread.
	 * @param analysisResultId The scored finding whose reasoning this note
	 *                         holds, null if it explains none. Pass the
	 *                         artifact_obj_id of the analysis result.
	 * @param createdTime      Creation time in epoch milliseconds, null for
	 *                         now.
	 */
	public NoteRequest(long objId, NoteType type, String body, String details, Note.Author author,
			Long parentNoteId, Long analysisResultId, Long createdTime) {
		if (type == null) {
			throw new IllegalArgumentException("Note type is required");
		}
		if (body == null) {
			throw new IllegalArgumentException("Note body is required");
		}
		if (author == null) {
			throw new IllegalArgumentException("Note author is required");
		}
		this.objId = objId;
		this.type = type;
		this.body = body;
		this.details = details;
		this.author = author;
		this.parentNoteId = parentNoteId;
		this.analysisResultId = analysisResultId;
		this.createdTime = (createdTime == null) ? System.currentTimeMillis() : createdTime;
	}

	/**
	 * Gets the object the note is about.
	 *
	 * @return The object id.
	 */
	public long getObjectId() {
		return objId;
	}

	/**
	 * Gets the note type.
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
	 * Gets the structured payload that goes with the prose.
	 *
	 * @return Optional with the details, empty if there are none.
	 */
	public Optional<String> getDetails() {
		return Optional.ofNullable(details);
	}

	/**
	 * Gets who wrote the note.
	 *
	 * @return The author.
	 */
	public Note.Author getAuthor() {
		return author;
	}

	/**
	 * Gets the note this one replies to.
	 *
	 * @return Optional with the parent note id, empty if the note starts a
	 *         thread.
	 */
	public Optional<Long> getParentNoteId() {
		return Optional.ofNullable(parentNoteId);
	}

	/**
	 * Gets the scored finding whose reasoning this note holds.
	 *
	 * @return Optional with the analysis result object id, empty if the note
	 *         explains no finding.
	 */
	public Optional<Long> getAnalysisResultId() {
		return Optional.ofNullable(analysisResultId);
	}

	/**
	 * Gets the creation time, in epoch milliseconds.
	 *
	 * @return The creation time.
	 */
	public long getCreatedTime() {
		return createdTime;
	}
}
