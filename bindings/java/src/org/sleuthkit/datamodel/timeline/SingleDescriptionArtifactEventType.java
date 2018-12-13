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
import org.sleuthkit.datamodel.TskCoreException;

/**
 * Package level extension of StandardArtifactEventType for event types that
 * don't support zoomable descriptions. These events have the same description
 * at all zoom levels.
 */
final class SingleDescriptionArtifactEventType extends StandardArtifactEventType {

	@Override
	public EventPayload buildEventPayload(BlackboardArtifact artifact) throws TskCoreException {
		String description = extractShortDescription(artifact);
		long time = artifact.getAttribute(getDateTimeAttributeType()).getValueLong();
		return new EventPayload(time, description, null, null);
	}

	SingleDescriptionArtifactEventType(int typeID, String displayName,
			EventType superType, BlackboardArtifact.Type artifactType, BlackboardAttribute.Type timeAttribute, BlackboardAttribute.Type descriptionAttribute) {
		super(typeID, displayName, superType, artifactType, timeAttribute,
				new AttributeExtractor(descriptionAttribute), new NullExtractor(), new NullExtractor());
	}
}
