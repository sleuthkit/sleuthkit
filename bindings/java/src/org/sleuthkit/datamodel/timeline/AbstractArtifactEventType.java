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

import java.text.MessageFormat;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.lang3.StringUtils;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.TskCoreException;

/**
 *
 */
abstract class AbstractArtifactEventType extends AbstractEventType implements ArtifactEventType {

	private static final Logger logger = Logger.getLogger(AbstractArtifactEventType.class.getName());

	private final BlackboardArtifact.Type artifactType;
	private final BlackboardAttribute.Type dateTimeAttributeType;
	private final StringExtractor<BlackboardArtifact> longExtractor;
	private final StringExtractor<BlackboardArtifact> medExtractor;
	private final StringExtractor<BlackboardArtifact> shortExtractor;
	private final CheckedFunction<BlackboardArtifact, AttributeEventDescription> parseAttributesHelper;

	AbstractArtifactEventType(int id, String displayName,
			EventType superType,
			BlackboardArtifact.Type artifactType,
			BlackboardAttribute.Type dateTimeAttributeType,
			StringExtractor<BlackboardArtifact> shortExtractor,
			StringExtractor<BlackboardArtifact> medExtractor,
			StringExtractor<BlackboardArtifact> longExtractor) {
		this(id, displayName, superType, artifactType, dateTimeAttributeType, shortExtractor, medExtractor, longExtractor, null);
	}

	AbstractArtifactEventType(int id, String displayName,
			EventType superType,
			BlackboardArtifact.Type artifactType,
			BlackboardAttribute.Type dateTimeAttributeType,
			StringExtractor<BlackboardArtifact> shortExtractor,
			StringExtractor<BlackboardArtifact> medExtractor,
			StringExtractor<BlackboardArtifact> longExtractor,
			CheckedFunction<BlackboardArtifact, AttributeEventDescription> parseAttributesHelper) {

		super(id, displayName, EventTypeZoomLevel.SUB_TYPE, superType);
		this.artifactType = artifactType;
		this.dateTimeAttributeType = dateTimeAttributeType;
		this.shortExtractor = shortExtractor;
		this.medExtractor = medExtractor;
		this.longExtractor = longExtractor;
		this.parseAttributesHelper = parseAttributesHelper;
	}

	@Override
	public int getArtifactTypeID() {
		return getArtifactType().getTypeID();
	}

	/**
	 * The attribute type this event type is derived from.
	 *
	 * @return The attribute type this event type is derived from.
	 */
	@Override
	public BlackboardAttribute.Type getDateTimeAttributeType() {
		return dateTimeAttributeType;
	}

	/**
	 * @return a function from an artifact to a String to use as part of the
	 *         full event description
	 */
	@Override
	public String extractFullDescription(BlackboardArtifact artf) throws TskCoreException {
		return longExtractor.extract(artf);
	}

	/**
	 * @return a function from an artifact to a String to use as part of the
	 *         medium event description
	 */
	@Override
	public String extractMedDescription(BlackboardArtifact artf) throws TskCoreException {
		return medExtractor.extract(artf);
	}

	/**
	 * @return a function from an artifact to a String to use as part of the
	 *         short event description
	 */
	@Override
	public String extractShortDescription(BlackboardArtifact artf) throws TskCoreException {
		return shortExtractor.extract(artf);
	}

	/**
	 * Get the artifact type this event type is derived from.
	 *
	 * @return The artifact type this event type is derived from.
	 */
	@Override
	public BlackboardArtifact.Type getArtifactType() {
		return artifactType;
	}

	/**
	 * Build a AttributeEventDescription derived from a BlackboardArtifact. This
	 * is a template method that relies on each ArtifactEventType's
	 * implementation of ArtifactEventType#parseAttributesHelper() to know how
	 * to go from BlackboardAttributes to the event description.
	 *
	 * @param type
	 * @param artf the BlackboardArtifact to derive the event description from
	 *
	 * @return an AttributeEventDescription derived from the given artifact, if
	 *         the given artifact has no timestamp
	 *
	 * @throws TskCoreException is there is a problem accessing the blackboard
	 *                          data
	 */
	@Override
	public AttributeEventDescription buildEventDescription(BlackboardArtifact artf) throws TskCoreException {
		//if we got passed an artifact that doesn't correspond to the type of the event, 
		//something went very wrong. throw an exception.
		if (this.getArtifactTypeID() != artf.getArtifactTypeID()) {
			throw new IllegalArgumentException();
		}
		if (artf.getAttribute(this.getDateTimeAttributeType()) == null) {
			logger.log(Level.WARNING, "Artifact {0} has no date/time attribute, skipping it.", artf.getArtifactID()); // NON-NLS
			return null;
		}
		//use the hook provided by this subtype implementation
		if (this.parseAttributesHelper != null) {
			return this.parseAttributesHelper.apply(artf);
		}
		final BlackboardAttribute dateTimeAttr = artf.getAttribute(getDateTimeAttributeType());

		long time = dateTimeAttr.getValueLong();
		String shortDescription = extractShortDescription(artf);
		String medDescription = shortDescription + " : " + extractMedDescription(artf);
		String fullDescription = medDescription + " : " + extractFullDescription(artf);
		return new AttributeEventDescription(time, shortDescription, medDescription, fullDescription);
	}

	interface StringExtractor<X> {

		String extract(X artf) throws TskCoreException;
	}

	static class DefaultAttributeExtractor implements AbstractArtifactEventType.StringExtractor<BlackboardArtifact> {

		private final BlackboardAttribute.Type attributeType;

		DefaultAttributeExtractor(BlackboardAttribute.Type attribute) {
			this.attributeType = attribute;
		}

		@Override
		public String extract(BlackboardArtifact artf) throws TskCoreException {
			return Optional.ofNullable(getAttributeSafe(artf, attributeType))
					.map(BlackboardAttribute::getDisplayString)
					.map(StringUtils::defaultString)
					.orElse("");
		}
	}

	final static class EmptyExtractor<X> implements StringExtractor<X> {

		@Override
		public String extract(X ignored) throws TskCoreException {
			return "";
		}
	}

	static BlackboardAttribute getAttributeSafe(BlackboardArtifact artf, BlackboardAttribute.Type attrType) {
		try {
			return artf.getAttribute(attrType);
		} catch (TskCoreException ex) {
			logger.log(Level.SEVERE, MessageFormat.format("Error getting attribute from artifact {0}.", artf.getArtifactID()), ex); // NON-NLS
			return null;
		}
	}

}
