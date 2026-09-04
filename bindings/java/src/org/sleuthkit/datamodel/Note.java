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

import java.util.Objects;
import java.util.Optional;

/**
 * Text that belongs to an object in the case, has no score, and can change
 * after it is written. Comments, AI enrichment, remediation advice and
 * summaries are all notes.
 *
 * Notes are append-only. Editing one does not rewrite it: a new row is inserted
 * carrying the same original note id and the previous row stops being the
 * current revision. Every revision in a lineage therefore shares one stable id,
 * which is what outside references (the TSK_NOTE_ID attribute) point at.
 *
 * Instances are immutable snapshots of a row. Use NoteManager to create,
 * revise and read them.
 */
public final class Note {

	/**
	 * What kind of principal wrote a note. This is the only place the question
	 * "did a machine write this" is answered, and it is answered per row: a
	 * chat thread is one note type whose rows have both human and model
	 * authors, so a type-level flag cannot say.
	 */
	public enum AuthorKind {

		USER(0, "User"), ///< A person
		AI(1, "AI"), ///< A model
		MODULE(2, "Module"); ///< Automation that is not a model, such as an ingest module

		private final int id;
		private final String name;

		private AuthorKind(int id, String name) {
			this.id = id;
			this.name = name;
		}

		/**
		 * Gets the id of this author kind, as stored in the author_kind column.
		 *
		 * @return The id.
		 */
		public int getId() {
			return id;
		}

		/**
		 * Gets the name of this author kind.
		 *
		 * @return The name.
		 */
		public String getName() {
			return name;
		}

		/**
		 * Gets the author kind with the given id.
		 *
		 * @param id The id to look for.
		 *
		 * @return The author kind.
		 *
		 * @throws IllegalArgumentException if the id matches no author kind.
		 */
		public static AuthorKind fromID(int id) {
			for (AuthorKind kind : AuthorKind.values()) {
				if (kind.id == id) {
					return kind;
				}
			}
			throw new IllegalArgumentException("No AuthorKind matching id: " + id);
		}
	}

	/**
	 * Who wrote a note, recorded inline on the note rather than as a key into
	 * another table. A case database is an evidence container that gets copied,
	 * archived and reported on, so attribution has to survive on its own, and
	 * it is a point-in-time fact rather than a live lookup that shifts when
	 * someone is renamed.
	 *
	 * The id is whatever the writing product uses to identify a principal - an
	 * Autopsy login name, a Cyber Triage user id, a model id, a module name.
	 * There is one writing product per case database, so the id space is not
	 * shared and needs no namespace prefix.
	 */
	public static final class Author {

		private final AuthorKind kind;
		private final String id;
		private final String displayName;
		private final String configId;

		/**
		 * Constructs an author with no configuration version, which is the
		 * normal case for a person.
		 *
		 * @param kind        The kind of principal.
		 * @param id          Stable id of the principal. Required.
		 * @param displayName What the UI renders for the principal. Required.
		 */
		public Author(AuthorKind kind, String id, String displayName) {
			this(kind, id, displayName, null);
		}

		/**
		 * Constructs an author.
		 *
		 * @param kind        The kind of principal.
		 * @param id          Stable id of the principal. Required.
		 * @param displayName What the UI renders for the principal. Required.
		 * @param configId    Version of the prompt or module configuration that
		 *                    produced the note, so a bad answer can be told
		 *                    from an old one. May be null.
		 */
		public Author(AuthorKind kind, String id, String displayName, String configId) {
			if (kind == null) {
				throw new IllegalArgumentException("Author kind is required");
			}
			if (id == null || id.isEmpty()) {
				throw new IllegalArgumentException("Author id is required");
			}
			if (displayName == null || displayName.isEmpty()) {
				throw new IllegalArgumentException("Author display name is required");
			}
			this.kind = kind;
			this.id = id;
			this.displayName = displayName;
			this.configId = configId;
		}

		/**
		 * Gets the kind of principal that wrote the note.
		 *
		 * @return The author kind.
		 */
		public AuthorKind getKind() {
			return kind;
		}

		/**
		 * Gets the stable id of the principal that wrote the note.
		 *
		 * @return The author id.
		 */
		public String getId() {
			return id;
		}

		/**
		 * Gets the name to render for the principal that wrote the note.
		 *
		 * @return The display name.
		 */
		public String getDisplayName() {
			return displayName;
		}

		/**
		 * Gets the prompt or module configuration version that produced the
		 * note.
		 *
		 * @return Optional with the configuration id, empty if there is none.
		 */
		public Optional<String> getConfigId() {
			return Optional.ofNullable(configId);
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (!(obj instanceof Author)) {
				return false;
			}
			Author other = (Author) obj;
			return kind == other.kind
					&& id.equals(other.id)
					&& displayName.equals(other.displayName)
					&& Objects.equals(configId, other.configId);
		}

		@Override
		public int hashCode() {
			return Objects.hash(kind, id, displayName, configId);
		}
	}

	private final long noteId;
	private final long objId;
	private final Long dataSourceObjId;
	private final NoteType type;
	private final String body;
	private final String details;
	private final Author author;
	private final long createdTime;
	private final Long parentNoteId;
	private final long rootNoteId;
	private final long originalNoteId;
	private final boolean isCurrent;
	private final boolean isDeleted;
	private final Long analysisResultId;

	/**
	 * Constructs a note from a persisted row.
	 *
	 * @param noteId           Id of this row.
	 * @param objId            Object the note is about.
	 * @param dataSourceObjId  Data source the object belongs to, null for a
	 *                         case level note.
	 * @param type             Note type.
	 * @param body             The prose a person reads.
	 * @param details          Structured payload as JSON, may be null. The
	 *                         Sleuth Kit never parses it.
	 * @param author           Who wrote it.
	 * @param createdTime      Creation time, epoch milliseconds.
	 * @param parentNoteId     Note this one replies to, null on a thread root.
	 * @param rootNoteId       Root of the thread, own note id on a root.
	 * @param originalNoteId   First version of this note, own note id on a
	 *                         first version.
	 * @param isCurrent        True if this is the live revision of the lineage.
	 * @param isDeleted        True if this note has been retracted.
	 * @param analysisResultId The scored finding this note explains, null if it
	 *                         explains none.
	 */
	Note(long noteId, long objId, Long dataSourceObjId, NoteType type, String body, String details,
			Author author, long createdTime, Long parentNoteId, long rootNoteId, long originalNoteId,
			boolean isCurrent, boolean isDeleted, Long analysisResultId) {
		this.noteId = noteId;
		this.objId = objId;
		this.dataSourceObjId = dataSourceObjId;
		this.type = type;
		this.body = body;
		this.details = details;
		this.author = author;
		this.createdTime = createdTime;
		this.parentNoteId = parentNoteId;
		this.rootNoteId = rootNoteId;
		this.originalNoteId = originalNoteId;
		this.isCurrent = isCurrent;
		this.isDeleted = isDeleted;
		this.analysisResultId = analysisResultId;
	}

	/**
	 * Gets the id of this revision. This changes every time the note is
	 * revised. Anything that needs to refer to the note across edits should use
	 * getOriginalNoteId() instead.
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
	 * @return Optional with the details, empty if there are none.
	 */
	public Optional<String> getDetails() {
		return Optional.ofNullable(details);
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
	 * Gets the creation time of this revision, in epoch milliseconds.
	 * Milliseconds rather than seconds because ordering collaborative comments
	 * needs sub-second resolution. Ties break on note id.
	 *
	 * @return The creation time.
	 */
	public long getCreatedTime() {
		return createdTime;
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
	 * Gets the stable id of this note across edits. A first version is its own
	 * original. This is the id an analysis result's TSK_NOTE_ID attribute
	 * points at, so the attribute stays correct when the note is revised.
	 *
	 * @return The original note id.
	 */
	public long getOriginalNoteId() {
		return originalNoteId;
	}

	/**
	 * Indicates whether this is the live revision of its lineage. A partial
	 * unique index makes two current revisions of one note impossible.
	 *
	 * @return True if this is the current revision.
	 */
	public boolean isCurrent() {
		return isCurrent;
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
