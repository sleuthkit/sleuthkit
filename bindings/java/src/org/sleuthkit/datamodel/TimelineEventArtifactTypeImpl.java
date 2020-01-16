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
import java.util.List;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.lang3.StringUtils;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_TRACK;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DOMAIN;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_GEO_TRACKPOINTS;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TL_EVENT_TYPE;
import org.sleuthkit.datamodel.blackboardutils.attributes.GeoTrackPoints;
import org.sleuthkit.datamodel.blackboardutils.attributes.GeoWaypoint.GeoTrackPoint;

/**
 * Version of TimelineEventType for events based on artifacts
 */
class TimelineEventArtifactTypeImpl extends TimelineEventTypeImpl {

	private static final Logger logger = Logger.getLogger(TimelineEventArtifactTypeImpl.class.getName());

	static final int EMAIL_FULL_DESCRIPTION_LENGTH_MAX = 150;
	static final int EMAIL_TO_FROM_LENGTH_MAX = 75;

	private final BlackboardArtifact.Type artifactType;
	private final BlackboardAttribute.Type dateTimeAttributeType;
	private final TSKCoreCheckedFunction<BlackboardArtifact, String> fullExtractor;
	private final TSKCoreCheckedFunction<BlackboardArtifact, String> medExtractor;
	private final TSKCoreCheckedFunction<BlackboardArtifact, String> shortExtractor;
	private final TSKCoreCheckedFunction<BlackboardArtifact, TimelineEventDescriptionWithTime> artifactParsingFunction;

	private static final int MAX_SHORT_DESCRIPTION_LENGTH = 500;
	private static final int MAX_MED_DESCRIPTION_LENGTH = 500;
	private static final int MAX_FULL_DESCRIPTION_LENGTH = 1024;

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

		super(typeID, displayName, TimelineEventType.HierarchyLevel.EVENT, superType);
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
	 *
	 * @return
	 *
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
			if (artifact.getArtifactID() != TSK_GPS_TRACK.getTypeID()) {
				return makeRouteDescription(artifact);
			}

			/*
			 * This has the side effect of making sure that a TimelineEvent
			 * object is not created for this artifact.
			 */
			return null;
		}

		/*
		 * Use the type-specific method
		 */
		if (this.artifactParsingFunction != null) {
			//use the hook provided by this subtype implementation to build the descriptions.
			return this.artifactParsingFunction.apply(artifact);
		}

		//combine descriptions in standard way
		String shortDescription = extractShortDescription(artifact);
		if (shortDescription.length() > MAX_SHORT_DESCRIPTION_LENGTH) {
			shortDescription = shortDescription.substring(0, MAX_SHORT_DESCRIPTION_LENGTH);
		}

		String medDescription = shortDescription + " : " + extractMedDescription(artifact);
		if (medDescription.length() > MAX_MED_DESCRIPTION_LENGTH) {
			medDescription = medDescription.substring(0, MAX_MED_DESCRIPTION_LENGTH);
		}

		String fullDescription = medDescription + " : " + extractFullDescription(artifact);
		if (fullDescription.length() > MAX_FULL_DESCRIPTION_LENGTH) {
			fullDescription = fullDescription.substring(0, MAX_FULL_DESCRIPTION_LENGTH);
		}

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
	 * Parses a TSK_GPS_TRACK artifact to create a triple description with
	 * time extracted from the TSK_GEO_TRACKPOINTS attribute.
	 * 
	 * @param artifact
	 * 
	 * @return
	 * 
	 * @throws TskCoreException 
	 */
	private TimelineEventDescriptionWithTime makeRouteDescription(BlackboardArtifact artifact) throws TskCoreException {
		BlackboardAttribute attribute = artifact.getAttribute(new BlackboardAttribute.Type(TSK_GEO_TRACKPOINTS));
		if (attribute == null) {
			// Cannot create and event if there are no track points to extract time
			return null;
		}

		List<GeoTrackPoint> points = GeoTrackPoints.deserializePoints(attribute.getValueString());
		Long startTime = null;
		for (GeoTrackPoint point : points) {
			// Points are in time order so return the first non-null time stamp
			startTime = point.getTimeStamp();
			if (startTime != null) {
				break;
			}
		}

		// If we didn't find a startime do not create an event.
		if (startTime == null) {
			return null;
		}

		//combine descriptions in standard way
		String shortDescription = extractShortDescription(artifact);
		if (shortDescription.length() > MAX_SHORT_DESCRIPTION_LENGTH) {
			shortDescription = shortDescription.substring(0, MAX_SHORT_DESCRIPTION_LENGTH);
		}

		String medDescription = shortDescription + " : " + extractMedDescription(artifact);
		if (medDescription.length() > MAX_MED_DESCRIPTION_LENGTH) {
			medDescription = medDescription.substring(0, MAX_MED_DESCRIPTION_LENGTH);
		}

		String fullDescription = medDescription + " : " + extractFullDescription(artifact);
		if (fullDescription.length() > MAX_FULL_DESCRIPTION_LENGTH) {
			fullDescription = fullDescription.substring(0, MAX_FULL_DESCRIPTION_LENGTH);
		}

		return new TimelineEventDescriptionWithTime(startTime, shortDescription, medDescription, fullDescription);
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
