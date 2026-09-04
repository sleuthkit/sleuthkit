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
 * The kind of a note, such as a user comment or an AI summary.
 *
 * Note types are open, the way artifact types are. The Sleuth Kit seeds the
 * built-in types on every case open and callers add their own by name at
 * runtime through NoteManager.getOrAddNoteType(), so a consumer does not have
 * to wait on a Sleuth Kit release to add a type.
 *
 * The type carries no behaviour. Anything that changes how a note is treated
 * belongs on the note itself: in particular "did a machine write this" is
 * answered by Note.AuthorKind on the row, never by the type, because a type
 * such as chat has rows from both people and models.
 */
public final class NoteType {

	/**
	 * The note types The Sleuth Kit ships with. These are seeded on every case
	 * open; a consumer may add more at runtime by name.
	 */
	public enum BuiltIn {

		COMMENT("Comment", "A comment written by a person"),
		AI_ENRICHMENT("AI Enrichment", "Additional context about an item produced by a model"),
		REMEDIATION("Remediation", "Advice on what to do about an item"),
		AI_SUMMARY("AI Summary", "A summary of the notable items on a host or on the case");

		private final String displayName;
		private final String description;

		private BuiltIn(String displayName, String description) {
			this.displayName = displayName;
			this.description = description;
		}

		/**
		 * Gets the type name of this built-in type, which is the enum constant
		 * name and is what is stored in the type_name column.
		 *
		 * @return The type name.
		 */
		public String getTypeName() {
			return name();
		}

		/**
		 * Gets the display name of this built-in type.
		 *
		 * @return The display name.
		 */
		public String getDisplayName() {
			return displayName;
		}

		/**
		 * Gets the description of this built-in type.
		 *
		 * @return The description.
		 */
		public String getDescription() {
			return description;
		}
	}

	private final long noteTypeId;
	private final String typeName;
	private final String displayName;
	private final String description;

	/**
	 * Constructs a note type from a persisted row.
	 *
	 * @param noteTypeId  Id of the type.
	 * @param typeName    Unique name of the type.
	 * @param displayName Name to render, may be null.
	 * @param description Description of the type, may be null.
	 */
	NoteType(long noteTypeId, String typeName, String displayName, String description) {
		this.noteTypeId = noteTypeId;
		this.typeName = typeName;
		this.displayName = displayName;
		this.description = description;
	}

	/**
	 * Gets the id of this type.
	 *
	 * @return The note type id.
	 */
	public long getNoteTypeId() {
		return noteTypeId;
	}

	/**
	 * Gets the unique name of this type.
	 *
	 * @return The type name.
	 */
	public String getTypeName() {
		return typeName;
	}

	/**
	 * Gets the name to render for this type. A type can appear that nothing
	 * renders specially, in which case this is the fallback.
	 *
	 * @return Optional with the display name, empty if there is none.
	 */
	public Optional<String> getDisplayName() {
		return Optional.ofNullable(displayName);
	}

	/**
	 * Gets the description of this type.
	 *
	 * @return Optional with the description, empty if there is none.
	 */
	public Optional<String> getDescription() {
		return Optional.ofNullable(description);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof NoteType)) {
			return false;
		}
		return noteTypeId == ((NoteType) obj).noteTypeId;
	}

	@Override
	public int hashCode() {
		return Long.hashCode(noteTypeId);
	}

	@Override
	public String toString() {
		return typeName;
	}
}
