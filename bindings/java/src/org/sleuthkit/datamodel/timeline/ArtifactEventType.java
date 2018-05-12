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
	 * Extract the full description for an event of this type from the given
	 * artifact.
	 *
	 * @param artifact The artifact to extract the description from.
	 *
	 * @return a function from an artifact to a String to use as the full event
	 *         description
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	String extractFullDescription(BlackboardArtifact artifact) throws TskCoreException;

	/**
	 * Extract the medium description for an event of this type from the given
	 * artifact.
	 *
	 * @param artifact The artifact to extract the description from.
	 *
	 * @return a function from an artifact to a String to use as the medium
	 *         event description
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	String extractMedDescription(BlackboardArtifact artifact) throws TskCoreException;

	/**
	 * Extract the short description for an event of this type from the given
	 * artifact.
	 *
	 * @param artifact The artifact to extract the description from.
	 *
	 * @return a function from an artifact to a String to use as the short event
	 *         description
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
	 * Build a AttributeEventDescription derived from a BlackboardArtifact. This
	 * is a template method that relies on each ArtifactEventType's
	 * implementation of ArtifactEventType#parseAttributesHelper() to know how
	 * to go from BlackboardAttributes to the event description.
	 *
	 * @param artf the BlackboardArtifact to derive the event description from
	 *
	 * @return an AttributeEventDescription derived from the given artifact, if
	 *         the given artifact has no timestamp
	 *
	 * @throws TskCoreException is there is a problem accessing the blackboard
	 *                          data
	 */
	AttributeEventDescription buildEventDescription(BlackboardArtifact artf) throws TskCoreException;

	/**
	 * bundles the per event information derived from a BlackBoard Artifact into
	 * one object. Primarily used to have a single return value for
	 * ArtifactEventType#buildEventDescription(ArtifactEventType,
	 * BlackboardArtifact).
	 */
	class AttributeEventDescription {

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

		AttributeEventDescription(long time, String shortDescription,
				String medDescription,
				String fullDescription) {
			this.time = time;
			this.shortDescription = shortDescription;
			this.medDescription = medDescription;
			this.fullDescription = fullDescription;
		}
	}
}
