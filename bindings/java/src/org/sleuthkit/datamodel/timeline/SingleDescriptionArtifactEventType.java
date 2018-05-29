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
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DESCRIPTION;
import org.sleuthkit.datamodel.TskCoreException;

/**
 *
 */
final class SingleDescriptionArtifactEventType extends StandardArtifactEventType {

	static private final AttributeExtractor descriptionExtractor = new AttributeExtractor(new BlackboardAttribute.Type(TSK_DESCRIPTION));

	@Override
	public EventPayload buildEventPayload(BlackboardArtifact artifact) throws TskCoreException {
		String description = extractFullDescription(artifact);
		long time = artifact.getAttribute(getDateTimeAttributeType()).getValueLong();
		return new EventPayload(time, description, description, description);
	}

	SingleDescriptionArtifactEventType(int typeID, String displayName,
			EventType superType, BlackboardArtifact.Type artifactType) {
		super(typeID, displayName, superType, artifactType, new BlackboardAttribute.Type(TSK_DATETIME),
				descriptionExtractor,
				descriptionExtractor,
				descriptionExtractor);
	}
}
