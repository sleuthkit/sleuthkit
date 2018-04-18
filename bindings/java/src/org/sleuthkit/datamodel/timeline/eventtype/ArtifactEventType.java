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
package org.sleuthkit.datamodel.timeline.eventtype;

import java.text.MessageFormat;
import java.util.Collections;
import java.util.Optional;
import java.util.function.Function;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.lang3.StringUtils;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.timeline.EventTypeZoomLevel;

/**
 *
 */
abstract class ArtifactEventType extends AbstractEventType {

	private static final Logger logger = Logger.getLogger(ArtifactEventType.class.getName());

	private final BlackboardArtifact.Type artifactType;
	private final BlackboardAttribute.Type dateTimeAttributeType;
	private final Function<BlackboardArtifact, String> longExtractor;
	private final Function<BlackboardArtifact, String> medExtractor;
	private final Function<BlackboardArtifact, String> shortExtractor;
	private final CheckedFunction<BlackboardArtifact, AttributeEventDescription> parseAttributesHelper;

	ArtifactEventType(int id, String displayName,
			EventType superType,
			BlackboardArtifact.Type artifactType,
			BlackboardAttribute.Type dateTimeAttributeType,
			Function<BlackboardArtifact, String> shortExtractor,
			Function<BlackboardArtifact, String> medExtractor,
			Function<BlackboardArtifact, String> longExtractor) {
		this(id, displayName, superType, artifactType, dateTimeAttributeType, shortExtractor, medExtractor, longExtractor, null);
	}

	ArtifactEventType(int id, String displayName,
			EventType superType,
			BlackboardArtifact.Type artifactType,
			BlackboardAttribute.Type dateTimeAttributeType,
			Function<BlackboardArtifact, String> shortExtractor,
			Function<BlackboardArtifact, String> medExtractor,
			Function<BlackboardArtifact, String> longExtractor,
			CheckedFunction<BlackboardArtifact, AttributeEventDescription> parseAttributesHelper) {

		super(id, displayName, EventTypeZoomLevel.SUB_TYPE, superType, Collections.emptySortedSet());
		this.artifactType = artifactType;
		this.dateTimeAttributeType = dateTimeAttributeType;
		this.shortExtractor = shortExtractor;
		this.medExtractor = medExtractor;
		this.longExtractor = longExtractor;
		this.parseAttributesHelper = parseAttributesHelper;
	}

	/**
	 * The attribute type this event type is derived from.
	 *
	 * @return The attribute type this event type is derived from.
	 */
	public BlackboardAttribute.Type getDateTimeAttributeType() {
		return dateTimeAttributeType;
	}

	/**
	 * @return a function from an artifact to a String to use as part of the
	 *         full event description
	 */
	public Function<BlackboardArtifact, String> getFullExtractor() {
		return longExtractor;
	}

	/**
	 * @return a function from an artifact to a String to use as part of the
	 *         medium event description
	 */
	public Function<BlackboardArtifact, String> getMedExtractor() {
		return medExtractor;
	}

	/**
	 * @return a function from an artifact to a String to use as part of the
	 *         short event description
	 */
	public Function<BlackboardArtifact, String> getShortExtractor() {
		return shortExtractor;
	}

	/**
	 * Get the artifact type this event type is derived from.
	 *
	 * @return The artifact type this event type is derived from.
	 */
	public BlackboardArtifact.Type getArtifactType() {
		return artifactType;
	}

	/**
	 * Get the ID of the the artifact type that this EventType is derived from.
	 *
	 * @return the ID of the the artifact type that this EventType is derived
	 *         from.
	 */
	int getArtifactTypeID() {
		return getArtifactType().getTypeID();
	}

	/**
	 * given an artifact, pull out the time stamp, and compose the descriptions.
	 * Each implementation of ArtifactEventType needs to implement
	 * parseAttributesHelper() as hook for
	 * buildEventDescription(org.sleuthkit.datamodel.BlackboardArtifact) to
	 * invoke. Most subtypes can use this default implementation.
	 *
	 * @param artf
	 *
	 * @return an AttributeEventDescription containing the timestamp and
	 *         description information
	 *
	 * @throws TskCoreException
	 */
	AttributeEventDescription parseAttributesHelper(BlackboardArtifact artf) throws TskCoreException {
		if (this.parseAttributesHelper == null) {
			return this.parseAttributesHelper(artf);
		}
		final BlackboardAttribute dateTimeAttr = artf.getAttribute(getDateTimeAttributeType());

		long time = dateTimeAttr.getValueLong();
		String shortDescription = getShortExtractor().apply(artf);
		String medDescription = shortDescription + " : " + getMedExtractor().apply(artf);
		String fullDescription = medDescription + " : " + getFullExtractor().apply(artf);
		return new AttributeEventDescription(time, shortDescription, medDescription, fullDescription);
	}

	/**
	 * bundles the per event information derived from a BlackBoard Artifact into
	 * one object. Primarily used to have a single return value for
	 * ArtifactEventType#buildEventDescription(ArtifactEventType,
	 * BlackboardArtifact).
	 */
	static class AttributeEventDescription {

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
	static AttributeEventDescription buildEventDescription(ArtifactEventType type, BlackboardArtifact artf) throws TskCoreException {
		//if we got passed an artifact that doesn't correspond to the type of the event, 
		//something went very wrong. throw an exception.
		if (type.getArtifactTypeID() != artf.getArtifactTypeID()) {
			throw new IllegalArgumentException();
		}
		if (artf.getAttribute(type.getDateTimeAttributeType()) == null) {
			logger.log(Level.WARNING, "Artifact {0} has no date/time attribute, skipping it.", artf.getArtifactID()); // NON-NLS
			return null;
		}
		//use the hook provided by this subtype implementation
		return type.parseAttributesHelper(artf);
	}

	static class AttributeExtractor implements Function<BlackboardArtifact, String> {

		private final BlackboardAttribute.Type attributeType;

		AttributeExtractor(BlackboardAttribute.Type attribute) {
			this.attributeType = attribute;
		}

		public String apply(BlackboardArtifact artf) {
			return Optional.ofNullable(getAttributeSafe(artf, attributeType))
					.map(BlackboardAttribute::getDisplayString)
					.map(StringUtils::defaultString)
					.orElse("");
		}
	}

	static class EmptyExtractor implements Function<BlackboardArtifact, String> {

		@Override
		public String apply(BlackboardArtifact ignored) {
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

	interface CheckedFunction<I, O> {

		O apply(I input) throws TskCoreException;
	}
}
