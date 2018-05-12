/*
 * Sleuth Kit Data Model
 *
 * Copyright 2018 Basis Technology Corp.
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
package org.sleuthkit.datamodel.timeline;

import org.sleuthkit.datamodel.DescriptionLoD;
import com.google.common.collect.ImmutableMap;
import java.util.Optional;
import org.sleuthkit.datamodel.TskData;

/**
 * A single event.
 */
public final class TimelineEvent {

	private final long eventID;
	/**
	 * The TSK object ID of the file this event is derived from.
	 */
	private final long objID;

	/**
	 * The TSK artifact ID of the file this event is derived from. Null, if this
	 * event is not derived from an artifact.
	 */
	private final Long artifactID;

	/**
	 * The TSK datasource ID of the datasource this event belongs to.
	 */
	private final long dataSourceID;

	/**
	 * The time of this event in second from the Unix epoch.
	 */
	private final long time;
	/**
	 * The type of this event.
	 */
	private final EventType type;

	/**
	 * The three descriptions (full, med, short) stored in a map, keyed by
	 * DescriptionLOD (Level of Detail)
	 */
	private final ImmutableMap<DescriptionLoD, String> descriptions;

	/**
	 * The known value for the file this event is derived from.
	 */
	private final TskData.FileKnown known;

	/**
	 * True if the file this event is derived from hits any of the configured
	 * hash sets.
	 */
	private final boolean hashHit;

	/**
	 * True if the file or artifact this event is derived from is tagged.
	 */
	private final boolean tagged;

	public TimelineEvent(long eventID, long dataSourceID, long objID, Long artifactID, long time, EventType type, String fullDescription, String medDescription, String shortDescription, TskData.FileKnown known, boolean hashHit, boolean tagged) {
		this.eventID = eventID;
		this.dataSourceID = dataSourceID;
		this.objID = objID;
		this.artifactID = Long.valueOf(0).equals(artifactID) ? null : artifactID;
		this.time = time;
		this.type = type;
		descriptions = ImmutableMap.<DescriptionLoD, String>of(DescriptionLoD.FULL, fullDescription,
				DescriptionLoD.MEDIUM, medDescription,
				DescriptionLoD.SHORT, shortDescription);
		this.known = known;
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
	 * Get the artifact id of the artifact this event is derived from.
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
	 * Get the obj id of the file this event is derived from.
	 *
	 * @return the object id.
	 */
	public long getFileID() {
		return objID;
	}

	/**
	 * Get the time of this event (in seconds from the Unix epoch).
	 *
	 * @return the time of this event in seconds from Unix epoch
	 */
	public long getTime() {
		return time;
	}

	public EventType getEventType() {
		return type;
	}

	/**
	 * Get the full description of this event.
	 *
	 * @return the full description
	 */
	public String getFullDescription() {
		return getDescription(DescriptionLoD.FULL);
	}

	/**
	 * Get the medium description of this event.
	 *
	 * @return the medium description
	 */
	public String getMedDescription() {
		return getDescription(DescriptionLoD.MEDIUM);
	}

	/**
	 * Get the short description of this event.
	 *
	 * @return the short description
	 */
	public String getShortDescription() {
		return getDescription(DescriptionLoD.SHORT);
	}

	/**
	 * Get the known value of the file this event is derived from.
	 *
	 * @return the known value
	 */
	public TskData.FileKnown getKnown() {
		return known;
	}

	/**
	 * Get the description of this event at the give level of detail(LoD).
	 *
	 * @param lod The level of detail to get.
	 *
	 * @return The description of this event at the given level of detail.
	 */
	public String getDescription(DescriptionLoD lod) {
		return descriptions.get(lod);
	}

	/**
	 * Get the datasource id of the datasource this event belongs to.
	 *
	 * @return the datasource id.
	 */
	public long getDataSourceID() {
		return dataSourceID;
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

}
