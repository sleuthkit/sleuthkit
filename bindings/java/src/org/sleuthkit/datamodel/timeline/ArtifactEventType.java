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
 *	 http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.datamodel.timeline;

import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.TskCoreException;

/**
 * Interface for EventTypes that are derived from Artifacts.
 */
public interface ArtifactEventType extends EventType {

	/**
	 * Get the artifact type this event type is derived from.
	 *
	 * @return The artifact type this event type is derived from.
	 */
	BlackboardArtifact.Type getArtifactType();

	/**
	 * The attribute type this event type is derived from.
	 *
	 * @return The attribute type this event type is derived from.
	 */
	BlackboardAttribute.Type getDateTimeAttributeType();

	/**
	 * @param artifact The artifact to extract the full description from.
	 *
	 * @return The full event description
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	String extractFullDescription(BlackboardArtifact artifact) throws TskCoreException;

	/**
	 * @param artifact The artifact to extract the medium description from.
	 *
	 * @return The medium event description
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	String extractMedDescription(BlackboardArtifact artifact) throws TskCoreException;

	/**
	 * @param artifact The artifact to extract the short description from.
	 *
	 * @return The short event description
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	String extractShortDescription(BlackboardArtifact artifact) throws TskCoreException;

	/**
	 * Get the ID of the the artifact type that this EventType is derived from.
	 *
	 * @return the ID of the the artifact type that this EventType is derived
	 *         from.
	 */
	default int getArtifactTypeID() {
		return getArtifactType().getTypeID();
	}

	/**
	 * Build an EventPayload derived from a BlackboardArtifact.
	 *
	 * @param artifact The BlackboardArtifact to derive the event description
	 *                 from.
	 *
	 * @return An EventPayload derived from the given artifact.
	 *
	 * @throws TskCoreException is there is a problem accessing the blackboard
	 *                          data
	 */
	EventPayload buildEventPayload(BlackboardArtifact artifact) throws TskCoreException;

	/**
	 * Bundles the per event information derived from a BlackBoard Artifact into
	 * one object. Primarily used to have a single return value for
	 * ArtifactEventType#buildEventDescription(ArtifactEventType,
	 * BlackboardArtifact).
	 */
	 final class EventPayload {

		final private long time;
		final private String shortDescription;
		final private String medDescription;
		final private String fullDescription;

		public long getTime() {
			return time;
		}

		public String getShortDescription() {
			return shortDescription;
		}

		public String getMedDescription() {
			return medDescription;
		}

		public String getFullDescription() {
			return fullDescription;
		}

		EventPayload(long time, String shortDescription,
				String medDescription,
				String fullDescription) {
			this.time = time;
			this.shortDescription = shortDescription;
			this.medDescription = medDescription;
			this.fullDescription = fullDescription;
		}
	}
}
