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

import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.DescriptionLoD;
import org.sleuthkit.datamodel.TskCoreException;

/**
 * Package level extension of StandardArtifactEventType for event types only
 * store one description in the db. They may support parsing the decription in
 * memory, or one one zoom level.S
 */
class SingleDescriptionArtifactEventType extends StandardArtifactEventType {

	@Override
	public EventPayload buildEventPayload(BlackboardArtifact artifact) throws TskCoreException {
		String description = extractFullDescription(artifact);
		long time = artifact.getAttribute(getDateTimeAttributeType()).getValueLong();
		return new EventPayload(time, null, null, description);
	}

	SingleDescriptionArtifactEventType(int typeID, String displayName,
			EventType superType, BlackboardArtifact.Type artifactType, BlackboardAttribute.Type timeAttribute, BlackboardAttribute.Type descriptionAttribute) {
		super(typeID, displayName, superType, artifactType, timeAttribute,
				new NullExtractor(), new NullExtractor(), new AttributeExtractor(descriptionAttribute));
	}

	@Override
	public String getDescription(DescriptionLoD lod, String fullDescription, String medDescription, String shortDescription) {
		return fullDescription;
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
