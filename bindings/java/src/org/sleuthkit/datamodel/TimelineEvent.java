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

/**
 * A representation of an event in the timeline of a case.
 */
public final class TimelineEvent {

	/**
	 * The unique ID of this event in the case database.
	 */
	private final long eventID;

	/**
	 * The object ID of the content that is either the direct or indirect source
	 * of this event. For events associated with files, this will be the object
	 * ID of the file. For events associated with artifacts, this will be the
	 * object ID of the artifact source: a file, a data source, or another
	 * artifact.
	 */
	private final long contentObjID;

	/**
	 * The artifact ID (not the object ID) of the artifact, if any, that is the
	 * source of this event. Null for events assoicated directly with files.
	 */
	private final Long artifactID;

	/**
	 * The object ID of the data source for the event source.
	 */
	private final long dataSourceObjID;

	/**
	 * When this event occurred, in seconds from the UNIX epoch.
	 */
	private final long time;

	/**
	 * The type of this event.
	 */
	private final TimelineEventType type;

	/**
	 * The description of this event, provided at three levels of detail: high
	 * (full description), medium (medium description), and low (short
	 * description).
	 */
	private final TimelineEventDescription descriptions;

	/**
	 * True if the file, if any, associated with this event, either directly or
	 * indirectly, is a file for which a hash set hit has been detected.
	 */
	private final boolean eventSourceHashHitDetected;

	/**
	 * True if the direct source (file or artifact) of this event has been
	 * tagged.
	 */
	private final boolean eventSourceTagged;

	/**
	 * Constructs a representation of an event in the timeline of a case.
	 *
	 * @param eventID                    The unique ID of this event in the case
	 *                                   database.
	 * @param dataSourceObjID            The object ID of the data source for
	 *                                   the event source.
	 * @param contentObjID               The object ID of the content that is
	 *                                   either the direct or indirect source of
	 *                                   this event. For events associated with
	 *                                   files, this will be the object ID of
	 *                                   the file. For events associated with
	 *                                   artifacts, this will be the object ID
	 *                                   of the artifact source: a file, a data
	 *                                   source, or another artifact.
	 * @param artifactID                 The artifact ID (not the object ID) of
	 *                                   the artifact, if any, that is the
	 *                                   source of this event. Null for events
	 *                                   assoicated directly with files.
	 * @param time                       The time this event occurred, in
	 *                                   seconds from the UNIX epoch.
	 * @param type                       The type of this event.
	 * @param fullDescription            The full length description of this
	 *                                   event.
	 * @param medDescription             The medium length description of this
	 *                                   event.
	 * @param shortDescription           The short length description of this
	 *                                   event.
	 * @param eventSourceHashHitDetected True if the file, if any, associated
	 *                                   with this event, either directly or
	 *                                   indirectly, is a file for which a hash
	 *                                   set hit has been detected.
	 * @param eventSourceTagged          True if the direct source (file or
	 *                                   artifact) of this event has been
	 *                                   tagged.
	 */
	TimelineEvent(long eventID,
			long dataSourceObjID,
			long contentObjID,
			Long artifactID,
			long time,
			TimelineEventType type,
			String fullDescription,
			String medDescription,
			String shortDescription,
			boolean eventSourceHashHitDetected,
			boolean eventSourceTagged) {
		this.eventID = eventID;
		this.dataSourceObjID = dataSourceObjID;
		this.contentObjID = contentObjID;
		this.artifactID = Long.valueOf(0).equals(artifactID) ? null : artifactID;
		this.time = time;
		this.type = type;
		/*
		 * The cast that follows reflects the fact that we have not decided
		 * whether or not to add the parseDescription method to the
		 * TimelineEventType interface yet. Currently (9/18/19), this method is
		 * part of TimelineEventTypeImpl and all implementations of
		 * TimelineEventType are subclasses of TimelineEventTypeImpl.
		 */
		if (type instanceof TimelineEventTypeImpl) {
			this.descriptions = ((TimelineEventTypeImpl) type).parseDescription(fullDescription, medDescription, shortDescription);
		} else {
			this.descriptions = new TimelineEventDescription(fullDescription, medDescription, shortDescription);
		}
		this.eventSourceHashHitDetected = eventSourceHashHitDetected;
		this.eventSourceTagged = eventSourceTagged;
	}

	/**
	 * Indicates whether or not the direct source (file or artifact) of this
	 * artifact has been tagged.
	 *
	 * @return True or false.
	 */
	public boolean eventSourceIsTagged() {
		return eventSourceTagged;
	}

	/**
	 * Indicates whether or not the file, if any, associated with this event,
	 * either directly or indirectly, is a file for which a hash set hit has
	 * been detected.
	 *
	 * @return True or false.
	 */
	public boolean eventSourceHasHashHits() {
		return eventSourceHashHitDetected;
	}

	/**
	 * Gets the artifact ID (not object ID) of the artifact, if any, that is the
	 * direct source of this event.
	 *
	 * @return An Optional object containing the artifact ID. May be empty.
	 */
	public Optional<Long> getArtifactID() {
		return Optional.ofNullable(artifactID);
	}

	/**
	 * Gets the unique ID of this event in the case database.
	 *
	 * @return The event ID.
	 */
	public long getEventID() {
		return eventID;
	}

	/**
	 * Gets the object ID of the content that is the direct or indirect source
	 * of this event. For events associated with files, this will be the object
	 * ID of the file that is the direct event source. For events associated
	 * with artifacts, this will be the object ID of the artifact source: a
	 * file, a data source, or another artifact.
	 *
	 * @return The object ID.
	 */
	public long getContentObjID() {
		return contentObjID;
	}

	/**
	 * Gets the time this event occurred.
	 *
	 * @return The time this event occurred, in seconds from UNIX epoch.
	 */
	public long getTime() {
		return time;
	}

	/**
	 * Gets the type of this event.
	 *
	 * @return The event type.
	 */
	public TimelineEventType getEventType() {
		return type;
	}

	/**
	 * Gets the description of this event at a given level of detail.
	 *
	 * @param levelOfDetail The desired level of detail.
	 *
	 * @return The description of this event at the given level of detail.
	 */
	public String getDescription(TimelineLevelOfDetail levelOfDetail) {
		return descriptions.getDescription(levelOfDetail);
	}

	/**
	 * Gets the object ID of the data source for the source content of this
	 * event.
	 *
	 * @return The data source object ID.
	 */
	public long getDataSourceObjID() {
		return dataSourceObjID;
	}

	/**
	 * Gets the time this event occured, in milliseconds from the UNIX epoch.
	 *
	 * @return The event time in milliseconds from the UNIX epoch.
	 */
	public long getEventTimeInMs() {
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
		return this.eventID == other.getEventID();
	}

}
