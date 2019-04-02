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
package org.sleuthkit.datamodel.timeline;

import com.google.common.net.InternetDomainName;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.commons.lang3.StringUtils;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.timeline.TimelineEvent.EventDescription;

/**
 *
 *
 */
class EventTypes {

	private EventTypes() {
	}

	/**
	 * Function that always returns the empty string no matter what it is
	 * applied to.
	 *
	 */
	final static class EmptyExtractor implements StandardArtifactEventType.TSKCoreCheckedFunction<BlackboardArtifact, String> {

		@Override
		public String apply(BlackboardArtifact ignored) throws TskCoreException {
			return "";
		}
	}

	static class URLArtifactEventType extends SingleDescriptionArtifactEventType {

		URLArtifactEventType(int typeID, String displayName, EventType superType, BlackboardArtifact.Type artifactType, BlackboardAttribute.Type timeAttribute, BlackboardAttribute.Type descriptionAttribute) {
			super(typeID, displayName, superType, artifactType, timeAttribute, descriptionAttribute);
		}

		@Override
		public EventDescription parseDescription(String fullDescriptionRaw, String medDescriptionRaw, String shortDescriptionRaw) {
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

				return TimelineEvent.EventDescription.create(fullDescription, mediumDescription, shortDescription);
			} catch (URISyntaxException ex) {
				//There was an error parsing the description as a URL, just ignore the description levels.
				return TimelineEvent.EventDescription.create(fullDescription);
			}
		}
	}

	static class FilePathEventType extends StandardEventType {

		FilePathEventType(long typeID, String displayName, EventTypeZoomLevel eventTypeZoomLevel, EventType superType) {
			super(typeID, displayName, eventTypeZoomLevel, superType);
		}

		@Override
		public EventDescription parseDescription(String fullDescription, String medDescription, String shortDescription) {
			return parseFilePathDescription(fullDescription);
		}

	}

	static class FilePathArtifactEventType extends SingleDescriptionArtifactEventType {

		FilePathArtifactEventType(int typeID, String displayName, EventType superType, BlackboardArtifact.Type artifactType, BlackboardAttribute.Type timeAttribute, BlackboardAttribute.Type descriptionAttribute) {
			super(typeID, displayName, superType, artifactType, timeAttribute, descriptionAttribute);
		}

		@Override
		public TimelineEvent.EventDescription parseDescription(String fullDescriptionRaw, String medDescriptionRaw, String shortDescriptionRaw) {
			return parseFilePathDescription(fullDescriptionRaw);
		}
	}

	/**
	 * Parse the full description from the DB, which is just the file path, into
	 * three levels.
	 *
	 * @param fullDescription
	 *
	 * @return An EventDescription with three levels of detail.
	 */
	static TimelineEvent.EventDescription parseFilePathDescription(String fullDescription) {

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
		return TimelineEvent.EventDescription.create(fullDescription, mediumDescription, shortDescription);

	}

}
