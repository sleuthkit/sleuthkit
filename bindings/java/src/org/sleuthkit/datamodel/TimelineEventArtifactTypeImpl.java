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
package org.sleuthkit.datamodel;

import com.google.common.net.InternetDomainName;
import java.text.MessageFormat;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.lang3.StringUtils;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DOMAIN;

/**
 * Version of TimelineEventType for events based on artifacts
 */
class TimelineEventArtifactTypeImpl extends TimelineEventTypeImpl { 

	private static final Logger logger = Logger.getLogger(TimelineEventArtifactTypeImpl.class.getName());

	private final BlackboardArtifact.Type artifactType;
	private final BlackboardAttribute.Type dateTimeAttributeType;
	private final TSKCoreCheckedFunction<BlackboardArtifact, String> fullExtractor;
	private final TSKCoreCheckedFunction<BlackboardArtifact, String> medExtractor;
	private final TSKCoreCheckedFunction<BlackboardArtifact, String> shortExtractor;
	private final TSKCoreCheckedFunction<BlackboardArtifact, TimelineEventDescriptionWithTime> artifactParsingFunction;

	TimelineEventArtifactTypeImpl(int typeID, String displayName,
			TimelineEventType superType,
			BlackboardArtifact.Type artifactType,
			BlackboardAttribute.Type dateTimeAttributeType,
			TSKCoreCheckedFunction<BlackboardArtifact, String> shortExtractor,
			TSKCoreCheckedFunction<BlackboardArtifact, String> medExtractor,
			TSKCoreCheckedFunction<BlackboardArtifact, String> fullExtractor) {
		this(typeID, displayName, superType, artifactType, dateTimeAttributeType, shortExtractor, medExtractor, fullExtractor, null);
	}

	TimelineEventArtifactTypeImpl(int typeID, String displayName,
			TimelineEventType superType,
			BlackboardArtifact.Type artifactType,
			BlackboardAttribute.Type dateTimeAttributeType,
			TSKCoreCheckedFunction<BlackboardArtifact, String> shortExtractor,
			TSKCoreCheckedFunction<BlackboardArtifact, String> medExtractor,
			TSKCoreCheckedFunction<BlackboardArtifact, String> fullExtractor,
			TSKCoreCheckedFunction<BlackboardArtifact, TimelineEventDescriptionWithTime> eventPayloadFunction) {

		super(typeID, displayName, TimelineEventType.TypeLevel.SUB_TYPE, superType);
		this.artifactType = artifactType;
		this.dateTimeAttributeType = dateTimeAttributeType;
		this.shortExtractor = shortExtractor;
		this.medExtractor = medExtractor;
		this.fullExtractor = fullExtractor;
		this.artifactParsingFunction = eventPayloadFunction;
	}

	int getArtifactTypeID() {
		return getArtifactType().getTypeID();
	}

	/**
	 * The attribute type this event type is associated with.
	 *
	 * @return The attribute type this event type is derived from.
	 */
	BlackboardAttribute.Type getDateTimeAttributeType() {
		return dateTimeAttributeType;
	}

	String extractFullDescription(BlackboardArtifact artf) throws TskCoreException {
		return fullExtractor.apply(artf);
	}

	String extractMedDescription(BlackboardArtifact artf) throws TskCoreException {
		return medExtractor.apply(artf);
	}

	String extractShortDescription(BlackboardArtifact artf) throws TskCoreException {
		return shortExtractor.apply(artf);
	}

	/**
	 * Get the artifact type this event type is derived from.
	 *
	 * @return The artifact type this event type is derived from.
	 */
	BlackboardArtifact.Type getArtifactType() {
		return artifactType;
	}

	
	/**
	 * Parses the artifact to create a triple description with a time.
	 * 
	 * @param artifact
	 * @return
	 * @throws TskCoreException 
	 */
	TimelineEventDescriptionWithTime makeEventDescription(BlackboardArtifact artifact) throws TskCoreException {
		//if we got passed an artifact that doesn't correspond to this event type, 
		//something went very wrong. throw an exception.
		if (this.getArtifactTypeID() != artifact.getArtifactTypeID()) {
			throw new IllegalArgumentException();
		}
		BlackboardAttribute timeAttribute = artifact.getAttribute(getDateTimeAttributeType());
		if (timeAttribute == null) {
			logger.log(Level.WARNING, "Artifact {0} has no date/time attribute, skipping it.", artifact.toString()); // NON-NLS
			return null;
		}

		/* Use the type-specific method */
		if (this.artifactParsingFunction != null) {
			//use the hook provided by this subtype implementation to build the descriptions.
			return this.artifactParsingFunction.apply(artifact);
		}

		//combine descriptions in standard way
		String shortDescription = extractShortDescription(artifact);
		String medDescription = shortDescription + " : " + extractMedDescription(artifact);
		String fullDescription = medDescription + " : " + extractFullDescription(artifact);
		return new TimelineEventDescriptionWithTime(timeAttribute.getValueLong(), shortDescription, medDescription, fullDescription);
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
	static class AttributeExtractor implements TSKCoreCheckedFunction<BlackboardArtifact, String> {

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
	interface TSKCoreCheckedFunction<I, O> {
		O apply(I input) throws TskCoreException;
	}
}
