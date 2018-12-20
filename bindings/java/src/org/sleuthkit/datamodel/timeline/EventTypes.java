/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
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
		public EventDescription getDescription(String fullDescriptionRaw, String medDescriptionRaw, String shortDescriptionRaw) {
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
				//JMTODO: do we need to bother logging this?
				Logger.getLogger(EventType.class.getName()).log(Level.WARNING, "Error parsing {0} as a URL:  Ignoring description levels.", fullDescription);
				return TimelineEvent.EventDescription.create(fullDescription);
			}
		}
	}

	static class FilePathEventType extends StandardEventType {

		FilePathEventType(long typeID, String displayName, EventTypeZoomLevel eventTypeZoomLevel, EventType superType) {
			super(typeID, displayName, eventTypeZoomLevel, superType);
		}

		@Override
		public EventDescription getDescription(String fullDescription, String medDescription, String shortDescription) {
			return getFilePathDescription(fullDescription);
		}

	}

	static class FilePathArtifactEventType extends SingleDescriptionArtifactEventType {

		FilePathArtifactEventType(int typeID, String displayName, EventType superType, BlackboardArtifact.Type artifactType, BlackboardAttribute.Type timeAttribute, BlackboardAttribute.Type descriptionAttribute) {
			super(typeID, displayName, superType, artifactType, timeAttribute, descriptionAttribute);
		}

		@Override
		public TimelineEvent.EventDescription getDescription(String fullDescriptionRaw, String medDescriptionRaw, String shortDescriptionRaw) {
			return getFilePathDescription(fullDescriptionRaw);
		}
	}

	static TimelineEvent.EventDescription getFilePathDescription(String fullDescription) {

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

	private EventTypes() {
	}
}
