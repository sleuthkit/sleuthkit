/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.datamodel.timeline;

import java.util.Optional;
import java.util.SortedSet;
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
