/*
 * Sleuth Kit Data Model
 *
 * Copyright 2018-2019 Basis Technology Corp.
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
import java.util.ResourceBundle;
import static org.sleuthkit.datamodel.TimelineEventType.TypeLevel.SUB_TYPE;

/**
 * A single event.
 */
public final class TimelineEvent {

	private final long eventID;
	/**
	 * The TSK object ID of the file this event is derived from.
	 */
	private final long fileObjID;

	/**
	 * The TSK artifact ID of the file this event is derived from. Null, if this
	 * event is not derived from an artifact.
	 */
	private final Long artifactID;

	/**
	 * The TSK datasource ID of the datasource this event belongs to.
	 */
	private final long dataSourceObjID;

	/**
	 * The time of this event in second from the Unix epoch.
	 */
	private final long time;
	/**
	 * The type of this event.
	 */
	private final TimelineEventType type;

	/**
	 * The three descriptions (full, med, short) stored in a map, keyed by
 DescriptionLOD (TypeLevel of Detail)
	 */
	private final TimelineEventDescription descriptions;

	/**
	 * True if the file this event is derived from hits any of the configured
	 * hash sets.
	 */
	private final boolean hashHit;

	/**
	 * True if the file or artifact this event is derived from is tagged.
	 */
	private final boolean tagged;

	/**
	 *
	 * @param eventID         ID from tsk_events table in database
	 * @param dataSourceObjID Object Id for data source event is from
	 * @param fileObjID       object id for non-artifact content that event is
	 *                        associated with
	 * @param artifactID      ID of artifact (not object id) if event came from
	 *                        an artifact
	 * @param time
	 * @param type
	 * @param descriptions
	 * @param hashHit
	 * @param tagged
	 */
	TimelineEvent(long eventID, long dataSourceObjID, long fileObjID, Long artifactID,
			long time, TimelineEventType type,
			String fullDescription,
			String medDescription,
			String shortDescription,
			boolean hashHit, boolean tagged) {
		this.eventID = eventID;
		this.dataSourceObjID = dataSourceObjID;
		this.fileObjID = fileObjID;
		this.artifactID = Long.valueOf(0).equals(artifactID) ? null : artifactID;
		this.time = time;
		this.type = type;
		// This isn't the best design, but it was the most expediant way to reduce 
		// the public API (by keeping parseDescription()) out of the public API.  
		if (type instanceof TimelineEventTypeImpl) {
			this.descriptions = ((TimelineEventTypeImpl)type).parseDescription(fullDescription, medDescription, shortDescription);
		}
		else {
			throw new IllegalArgumentException();
		}
		this.hashHit = hashHit;
		this.tagged = tagged;
	}

	/**
	 * Is the file or artifact this event is derived from tagged?
	 *
	 * @return true if he file or artifact this event is derived from is tagged.
	 */
	public boolean isTagged() {
		return tagged;
	}

	/**
	 * Is the file this event is derived from in any of the configured hash
	 * sets.
	 *
	 *
	 * @return True if the file this event is derived from is in any of the
	 *         configured hash sets.
	 */
	public boolean isHashHit() {
		return hashHit;
	}

	/**
	 * Get the artifact id (not the object ID) of the artifact this event is
	 * derived from.
	 *
	 * @return An Optional containing the artifact ID. Will be empty if this
	 *         event is not derived from an artifact
	 */
	public Optional<Long> getArtifactID() {
		return Optional.ofNullable(artifactID);
	}

	/**
	 * Get the event id of this event.
	 *
	 * @return The event id of this event.
	 */
	public long getEventID() {
		return eventID;
	}

	/**
	 * Get the Content obj id of the "file" (which could be a data source or
	 * other non AbstractFile ContentS) this event is derived from.
	 *
	 * @return the object id.
	 */
	public long getFileObjID() {
		return fileObjID;
	}

	/**
	 * Get the time of this event (in seconds from the Unix epoch).
	 *
	 * @return the time of this event in seconds from Unix epoch
	 */
	public long getTime() {
		return time;
	}

	public TimelineEventType getEventType() {
		return type;
	}

	public TimelineEventType getEventType(TimelineEventType.TypeLevel zoomLevel) {
		return zoomLevel.equals(SUB_TYPE) ? type : type.getBaseType();
	}

	/**
	 * Get the full description of this event.
	 *
	 * @return the full description
	 */
	public String getFullDescription() {
		return getDescription(TimelineEvent.DescriptionLevel.FULL);
	}

	/**
	 * Get the medium description of this event.
	 *
	 * @return the medium description
	 */
	public String getMedDescription() {
		return getDescription(TimelineEvent.DescriptionLevel.MEDIUM);
	}

	/**
	 * Get the short description of this event.
	 *
	 * @return the short description
	 */
	public String getShortDescription() {
		return getDescription(TimelineEvent.DescriptionLevel.SHORT);
	}

	/**
	 * Get the description of this event at the give level of detail(LoD).
	 *
	 * @param lod The level of detail to get.
	 *
	 * @return The description of this event at the given level of detail.
	 */
	public String getDescription(TimelineEvent.DescriptionLevel lod) {
		return descriptions.getDescription(lod);
	}

	/**
	 * Get the datasource id of the datasource this event belongs to.
	 *
	 * @return the datasource id.
	 */
	public long getDataSourceObjID() {
		return dataSourceObjID;
	}

	public long getEndMillis() {
		return time * 1000;
	}

	public long getStartMillis() {
		return time * 1000;
	}

	@Override
	public int hashCode() {
		int hash = 7;
		hash = 13 * hash + (int) (this.eventID ^ (this.eventID >>> 32));
		return hash;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		final TimelineEvent other = (TimelineEvent) obj;
		return this.eventID == other.eventID;
	}

	/**
	 * Defines the zoom levels that are available for the event description
	 */
	public enum DescriptionLevel {
		SHORT(ResourceBundle.getBundle("org.sleuthkit.datamodel.Bundle").getString("DescriptionLOD.short")),
		MEDIUM(ResourceBundle.getBundle("org.sleuthkit.datamodel.Bundle").getString("DescriptionLOD.medium")),
		FULL(ResourceBundle.getBundle("org.sleuthkit.datamodel.Bundle").getString("DescriptionLOD.full"));

		private final String displayName;

		public String getDisplayName() {
			return displayName;
		}

		private DescriptionLevel(String displayName) {
			this.displayName = displayName;
		}

		public DescriptionLevel moreDetailed() {
			try {
				return values()[ordinal() + 1];
			} catch (ArrayIndexOutOfBoundsException e) {
				return null;
			}
		}

		public DescriptionLevel lessDetailed() {
			try {
				return values()[ordinal() - 1];
			} catch (ArrayIndexOutOfBoundsException e) {
				return null;
			}
		}

	}
}
