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

import com.google.common.net.InternetDomainName;
import java.text.MessageFormat;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.lang3.StringUtils;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DOMAIN;
import org.sleuthkit.datamodel.TskCoreException;

/**
 * Implementation of ArtifactEventType for the standard predefined artifact
 * based event types
 */
class StandardArtifactEventType extends StandardEventType implements ArtifactEventType {

	private static final Logger logger = Logger.getLogger(StandardArtifactEventType.class.getName());

	private final BlackboardArtifact.Type artifactType;
	private final BlackboardAttribute.Type dateTimeAttributeType;
	private final CheckedFunction<BlackboardArtifact, String> longExtractor;
	private final CheckedFunction<BlackboardArtifact, String> medExtractor;
	private final CheckedFunction<BlackboardArtifact, String> shortExtractor;
	private final CheckedFunction<BlackboardArtifact, EventPayload> eventPayloadFunction;

	StandardArtifactEventType(int typeID, String displayName,
			EventType superType,
			BlackboardArtifact.Type artifactType,
			BlackboardAttribute.Type dateTimeAttributeType,
			CheckedFunction<BlackboardArtifact, String> shortExtractor,
			CheckedFunction<BlackboardArtifact, String> medExtractor,
			CheckedFunction<BlackboardArtifact, String> longExtractor) {
		this(typeID, displayName, superType, artifactType, dateTimeAttributeType, shortExtractor, medExtractor, longExtractor, null);
	}

	StandardArtifactEventType(int typeID, String displayName,
			EventType superType,
			BlackboardArtifact.Type artifactType,
			BlackboardAttribute.Type dateTimeAttributeType,
			CheckedFunction<BlackboardArtifact, String> shortExtractor,
			CheckedFunction<BlackboardArtifact, String> medExtractor,
			CheckedFunction<BlackboardArtifact, String> longExtractor,
			CheckedFunction<BlackboardArtifact, EventPayload> eventPayloadFunction) {

		super(typeID, displayName, EventTypeZoomLevel.SUB_TYPE, superType);
		this.artifactType = artifactType;
		this.dateTimeAttributeType = dateTimeAttributeType;
		this.shortExtractor = shortExtractor;
		this.medExtractor = medExtractor;
		this.longExtractor = longExtractor;
		this.eventPayloadFunction = eventPayloadFunction;
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
		return longExtractor.apply(artf);
	}

	/**
	 * @return a function from an artifact to a String to use as part of the
	 *         medium event description
	 */
	@Override
	public String extractMedDescription(BlackboardArtifact artf) throws TskCoreException {
		return medExtractor.apply(artf);
	}

	/**
	 * @return a function from an artifact to a String to use as part of the
	 *         short event description
	 */
	@Override
	public String extractShortDescription(BlackboardArtifact artf) throws TskCoreException {
		return shortExtractor.apply(artf);
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

	@Override
	public EventPayload buildEventPayload(BlackboardArtifact artifact) throws TskCoreException {
		//if we got passed an artifact that doesn't correspond to this event type, 
		//something went very wrong. throw an exception.
		if (this.getArtifactTypeID() != artifact.getArtifactTypeID()) {
			throw new IllegalArgumentException();
		}
		if (artifact.getAttribute(this.getDateTimeAttributeType()) == null) {
			logger.log(Level.WARNING, "Artifact {0} has no date/time attribute, skipping it.", artifact.getArtifactID()); // NON-NLS
			return null;
		}

		if (this.eventPayloadFunction != null) {
			//use the hook provided by this subtype implementation to build the descriptions.
			return this.eventPayloadFunction.apply(artifact);
		}

		long time = artifact.getAttribute(getDateTimeAttributeType()).getValueLong();
		//combine descriptions in standard way
		String shortDescription = extractShortDescription(artifact);
		String medDescription = shortDescription + " : " + extractMedDescription(artifact);
		String fullDescription = medDescription + " : " + extractFullDescription(artifact);
		return new EventPayload(time, shortDescription, medDescription, fullDescription);
	}

	static BlackboardAttribute getAttributeSafe(BlackboardArtifact artf, BlackboardAttribute.Type attrType) {
		try {
			return artf.getAttribute(attrType);
		} catch (TskCoreException ex) {
			logger.log(Level.SEVERE, MessageFormat.format("Error getting attribute from artifact {0}.", artf.getArtifactID()), ex); // NON-NLS
			return null;
		}
	}

	/**
	 * Function that extracts a string representation of the given attribute
	 * from the artifact it is applied to.
	 */
	static class AttributeExtractor implements CheckedFunction<BlackboardArtifact, String> {

		private final BlackboardAttribute.Type attributeType;

		AttributeExtractor(BlackboardAttribute.Type attribute) {
			this.attributeType = attribute;
		}

		@Override
		public String apply(BlackboardArtifact artf) throws TskCoreException {
			return Optional.ofNullable(getAttributeSafe(artf, attributeType))
					.map(BlackboardAttribute::getDisplayString)
					.orElse("");
		}
	}

	/**
	 * Function that always returns the empty string no matter what it is
	 * applied to.
	 *
	 * @param <X> Generic type paramater, can be anything.
	 */
	final static class EmptyExtractor<X> implements CheckedFunction<X, String> {

		@Override
		public String apply(X ignored) throws TskCoreException {
			return "";
		}
	}

	/**
	 * Specialization of AttributeExtractor that extract the domain attribute
	 * and then further processes it to obtain the top private domain using
	 * InternetDomainName.
	 */
	final static class TopPrivateDomainExtractor extends AttributeExtractor {

		final private static TopPrivateDomainExtractor instance = new TopPrivateDomainExtractor();

		static TopPrivateDomainExtractor getInstance() {
			return instance;
		}

		TopPrivateDomainExtractor() {
			super(new BlackboardAttribute.Type(TSK_DOMAIN));
		}

		@Override
		public String apply(BlackboardArtifact artf) throws TskCoreException {
			String domainString = StringUtils.substringBefore(super.apply(artf), "/");
			if (InternetDomainName.isValid(domainString)) {
				InternetDomainName domain = InternetDomainName.from(domainString);
				return (domain.isUnderPublicSuffix())
						? domain.topPrivateDomain().toString()
						: domain.toString();
			} else {
				return domainString;
			}
		}
	}

	/**
	 * Functinal interface for a function from I to O that throws
	 * TskCoreException.
	 *
	 * @param <I> Input type.
	 * @param <O> Output type.
	 */
	@FunctionalInterface
	interface CheckedFunction<I, O> {

		O apply(I input) throws TskCoreException;
	}
}
