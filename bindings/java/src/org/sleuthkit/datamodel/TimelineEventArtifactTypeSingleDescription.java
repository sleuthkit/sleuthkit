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

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Package level extension of TimelineEventArtifactTypeImpl for event types 
 that have only one description (because we don't know how to break it 
 up further). 
 */
class TimelineEventArtifactTypeSingleDescription extends TimelineEventArtifactTypeImpl {

	private static final Logger logger = Logger.getLogger(TimelineEventArtifactTypeSingleDescription.class.getName());

	@Override
	public TimelineEventDescriptionWithTime makeEventDescription(BlackboardArtifact artifact) throws TskCoreException {
		String description = extractFullDescription(artifact);
		if (description.length() > MAX_FULL_DESCRIPTION_LENGTH) {
			description = description.substring(0, MAX_FULL_DESCRIPTION_LENGTH);
		}
		BlackboardAttribute timeAttribute = artifact.getAttribute(getDateTimeAttributeType());

		if (timeAttribute == null) {
			logger.log(Level.WARNING, "Artifact {0} has no date/time attribute, skipping it.", artifact.toString()); // NON-NLS
			return null;
		}

		long time = timeAttribute.getValueLong();
		return new TimelineEventDescriptionWithTime(time, null, null, description);
	}

	TimelineEventArtifactTypeSingleDescription(int typeID, String displayName,
			TimelineEventType superType, BlackboardArtifact.Type artifactType, BlackboardAttribute.Type timeAttribute, BlackboardAttribute.Type descriptionAttribute) {
		super(typeID, displayName, superType, artifactType, timeAttribute,
				new NullExtractor(), new NullExtractor(), new AttributeExtractor(descriptionAttribute));
	}

	TimelineEventDescription parseDescription(String fullDescription, String medDescription, String shortDescription) {
		return new TimelineEventDescription(fullDescription);
	}

	/**
	 * Function that always returns the empty string no matter what it is
	 * applied to.
	 *
	 */
	final static class NullExtractor implements TSKCoreCheckedFunction<BlackboardArtifact, String> {

		@Override
		public String apply(BlackboardArtifact ignored) throws TskCoreException {
			return null;
		}
	}
}
