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

import com.google.common.net.InternetDomainName;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.commons.lang3.StringUtils;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_GEO_TRACKPOINTS;
import org.sleuthkit.datamodel.blackboardutils.attributes.BlackboardJsonAttrUtil;
import org.sleuthkit.datamodel.blackboardutils.attributes.GeoTrackPoints;

/**
 * Container class for various types of timeline events
 *
 */
class TimelineEventTypes {

	private TimelineEventTypes() {
	}

	/**
	 * Function that always returns the empty string no matter what it is
	 * applied to.
	 *
	 */
	final static class EmptyExtractor implements TimelineEventArtifactTypeImpl.TSKCoreCheckedFunction<BlackboardArtifact, String> {

		@Override
		public String apply(BlackboardArtifact ignored) throws TskCoreException {
			return "";
		}
	}

	static class URLArtifactEventType extends TimelineEventArtifactTypeSingleDescription {

		URLArtifactEventType(int typeID, String displayName, TimelineEventType superType, BlackboardArtifact.Type artifactType, BlackboardAttribute.Type timeAttribute, BlackboardAttribute.Type descriptionAttribute) {
			super(typeID, displayName, superType, artifactType, timeAttribute, descriptionAttribute);
		}

		@Override
		TimelineEventDescription parseDescription(String fullDescriptionRaw, String medDescriptionRaw, String shortDescriptionRaw) {
			/**
			 * Parses the full description from db, which is the full URL, to a
			 * EventDescription object with three levels of detail. Just ignores
			 * the passed in medium and short descriptions which should be
			 * empty/null anyways.
			 *
			 */
			String fullDescription = fullDescriptionRaw;
			try {
				URI uri = new URI(fullDescription);
				String host = uri.getHost();
				if (host == null) {
					host = StringUtils.strip(fullDescription, "./");

				}
				String shortDescription;
				if (InternetDomainName.isValid(host)) {
					InternetDomainName domain = InternetDomainName.from(host);
					shortDescription = (domain.isUnderPublicSuffix())
							? domain.topPrivateDomain().toString()
							: domain.toString();
				} else {
					shortDescription = host;
				}

				String mediumDescription = new URI(uri.getScheme(), uri.getUserInfo(), host, uri.getPort(), uri.getPath(), null, null).toString();

				return new TimelineEventDescription(fullDescription, mediumDescription, shortDescription);
			} catch (URISyntaxException ex) {
				//There was an error parsing the description as a URL, just ignore the description levels.
				return new TimelineEventDescription(fullDescription);
			}
		}
	}

	static class FilePathEventType extends TimelineEventTypeImpl {

		FilePathEventType(long typeID, String displayName, TimelineEventType.HierarchyLevel eventTypeZoomLevel, TimelineEventType superType) {
			super(typeID, displayName, eventTypeZoomLevel, superType);
		}

		@Override
		TimelineEventDescription parseDescription(String fullDescription, String medDescription, String shortDescription) {
			return parseFilePathDescription(fullDescription);
		}

	}

	static class FilePathArtifactEventType extends TimelineEventArtifactTypeSingleDescription {

		FilePathArtifactEventType(int typeID, String displayName, TimelineEventType superType, BlackboardArtifact.Type artifactType, BlackboardAttribute.Type timeAttribute, BlackboardAttribute.Type descriptionAttribute) {
			super(typeID, displayName, superType, artifactType, timeAttribute, descriptionAttribute);
		}

		@Override
		TimelineEventDescription parseDescription(String fullDescriptionRaw, String medDescriptionRaw, String shortDescriptionRaw) {
			return parseFilePathDescription(fullDescriptionRaw);
		}
	}
	
	/**
	 * Handle GPS_TRACK artifacts special. 
	 * GPS_TRACK artifacts do not have a time attribute, by they do have a 
	 * JSON list of waypoints from which a start time can be extracted.
	 */
	static class GPSTrackArtifactEventType extends TimelineEventArtifactTypeSingleDescription {
				
		GPSTrackArtifactEventType(int typeID, String displayName, TimelineEventType superType, BlackboardArtifact.Type artifactType, BlackboardAttribute.Type descriptionAttribute) {
			// Passing TSK_GEO_TRACKPOINTS as the "time attribute" as more of a place filler, to avoid any null issues
			super(typeID, displayName, superType, artifactType, new BlackboardAttribute.Type(TSK_GEO_TRACKPOINTS), descriptionAttribute);
		}
		
		@Override
		public TimelineEventDescriptionWithTime makeEventDescription(BlackboardArtifact artifact) throws TskCoreException {
			
			//If there is not a list if track points do not create an event.
			BlackboardAttribute attribute = artifact.getAttribute(new BlackboardAttribute.Type(TSK_GEO_TRACKPOINTS));
			if (attribute == null) {
				return null;
			}
			
			// Get the waypoint list "start time"
            GeoTrackPoints pointsList;
			try {
			pointsList = BlackboardJsonAttrUtil.fromAttribute(attribute, GeoTrackPoints.class);
            } catch (BlackboardJsonAttrUtil.InvalidJsonException ex) {
                throw new TskCoreException("Unable to parse track points in TSK_GEO_TRACKPOINTS attribute", ex);
            }			
			Long startTime = pointsList.getStartTime();
			
			// If we didn't find a startime do not create an event.
			if (startTime == null) {
				return null;
			}
			
			return new TimelineEventDescriptionWithTime(startTime, null, null, extractFullDescription(artifact));
		}
	}

	/**
	 * Parse the full description from the DB, which is just the file path, into
	 * three levels.
	 *
	 * @param fullDescription
	 *
	 * @return An TimelineEventDescription with three levels of detail.
	 */
	static TimelineEventDescription parseFilePathDescription(String fullDescription) {

		String[] split = fullDescription.split("/");
		String mediumDescription = Stream.of(split)
				.filter(StringUtils::isNotBlank)
				.limit(Math.max(1, split.length - 2))
				.collect(Collectors.joining("/", "/", ""))
				.replaceAll("//", "/");

		String shortDescription = Stream.of(split)
				.filter(StringUtils::isNotBlank)
				.limit(1)
				.collect(Collectors.joining("/", "/", ""))
				.replaceAll("//", "/");
		return new TimelineEventDescription(fullDescription, mediumDescription, shortDescription);

	}

}
