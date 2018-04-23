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

import com.google.common.base.MoreObjects;
import com.google.common.collect.ImmutableSortedSet;
import com.google.common.net.InternetDomainName;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.SortedSet;
import org.apache.commons.lang3.StringUtils;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.BlackboardArtifact;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_CALLLOG;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_DEVICE_ATTACHED;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_EMAIL_MSG;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_ROUTE;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_TRACKPOINT;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_INSTALLED_PROG;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_MESSAGE;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_METADATA_EXIF;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_RECENT_OBJECT;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_BOOKMARK;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_COOKIE;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_DOWNLOAD;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_HISTORY;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_SEARCH_QUERY;
import org.sleuthkit.datamodel.BlackboardAttribute;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_CREATED;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_SENT;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_START;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DEVICE_ID;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DEVICE_MAKE;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DEVICE_MODEL;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DIRECTION;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DOMAIN;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL_CONTENT_PLAIN;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL_FROM;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL_TO;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_GEO_LATITUDE;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_GEO_LATITUDE_END;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_GEO_LATITUDE_START;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_GEO_LONGITUDE;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_GEO_LONGITUDE_END;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_GEO_LONGITUDE_START;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_LOCATION;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_MESSAGE_TYPE;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PATH;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PHONE_NUMBER;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_READ_STATUS;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SUBJECT;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TEXT;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TITLE;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_VALUE;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.timeline.AbstractArtifactEventType.CheckedFunction;
import org.sleuthkit.datamodel.timeline.AbstractArtifactEventType.DefaultAttributeExtractor;
import static org.sleuthkit.datamodel.timeline.AbstractArtifactEventType.getAttributeSafe;
import org.sleuthkit.datamodel.timeline.ArtifactEventType.AttributeEventDescription;
import static org.sleuthkit.datamodel.timeline.BundleUtils.getBundle;

/**
 * An Event Type represents a distinct kind of event ie file system or web
 * activity. An EventType may have an optional super-type and 0 or more
 * subtypes, allowing events to be organized in a type hierarchy.
 */
public interface EventType extends Comparable<EventType> {

	default EventType getBaseType() {

		EventType superType = getSuperType();
		if (superType == ROOT_EVEN_TYPE) {
			return this;
		} else {
			return superType.getBaseType();
		}
	}

	default SortedSet<? extends EventType> getSiblingTypes() {
		return this.getSuperType().getSubTypes();
	}

	/**
	 * @return the super type of this event
	 */
	EventType getSuperType();

	EventTypeZoomLevel getZoomLevel();

	/**
	 * @return a list of event types, one for each subtype of this eventype, or
	 *         an empty list if this event type has no subtypes
	 */
	SortedSet<? extends EventType> getSubTypes();

	String getDisplayName();

	Optional<? extends EventType> getSubType(String string);

	int getTypeID();

	@Override
	public default int compareTo(EventType o) {
		return Comparator.comparing(EventType::getTypeID).compare(this, o);
	}

	/**
	 * A singleton EventType to represent the root type of all event types.
	 */
	public static EventType ROOT_EVEN_TYPE
			= new AbstractEventType(0, getBundle().getString("RootEventType.eventTypes.name"), EventTypeZoomLevel.ROOT_TYPE, null) {
	};

	public static EventType FILE_SYSTEM
			= new AbstractEventType(1, getBundle().getString("BaseTypes.fileSystem.name"), EventTypeZoomLevel.BASE_TYPE, ROOT_EVEN_TYPE) {
	};
	public static EventType WEB_ACTIVITY
			= new AbstractEventType(2, getBundle().getString("BaseTypes.webActivity.name"), EventTypeZoomLevel.BASE_TYPE, ROOT_EVEN_TYPE) {
	};
	public static EventType MISC_TYPES
			= new AbstractEventType(3, getBundle().getString("BaseTypes.miscTypes.name"), EventTypeZoomLevel.BASE_TYPE, ROOT_EVEN_TYPE) {
	};

	static final ImmutableSortedSet<EventType> BASE_TYPES
			= ImmutableSortedSet.of(FILE_SYSTEM, WEB_ACTIVITY, MISC_TYPES);

	public static EventType FILE_MODIFIED
			= new AbstractEventType(4, getBundle().getString("FileSystemTypes.fileModified.name"), EventTypeZoomLevel.SUB_TYPE, FILE_SYSTEM) {
	}; // NON-NLS
	public static EventType FILE_ACCESSED
			= new AbstractEventType(5, getBundle().getString("FileSystemTypes.fileAccessed.name"), EventTypeZoomLevel.SUB_TYPE, FILE_SYSTEM) {
	}; // NON-NLS
	public static EventType FILE_CREATED
			= new AbstractEventType(6, getBundle().getString("FileSystemTypes.fileCreated.name"), EventTypeZoomLevel.SUB_TYPE, FILE_SYSTEM) {
	}; // NON-NLS
	public static EventType FILE_CHANGED
			= new AbstractEventType(7, getBundle().getString("FileSystemTypes.fileChanged.name"), EventTypeZoomLevel.SUB_TYPE, FILE_SYSTEM) {
	}; // NON-NLS

	static final ImmutableSortedSet<EventType> FILE_SYSTEM_TYPES
			= ImmutableSortedSet.of(FILE_MODIFIED, FILE_ACCESSED, FILE_CREATED, FILE_CHANGED);

	public static ArtifactEventType WEB_DOWNLOADS = new AbstractArtifactEventType(8, getBundle().getString("WebTypes.webDownloads.name"), WEB_ACTIVITY,
			new BlackboardArtifact.Type(TSK_WEB_DOWNLOAD),
			new BlackboardAttribute.Type(TSK_DATETIME_ACCESSED),
			TopPrivateDomainExtractor.getInstance(),
			new DefaultAttributeExtractor(new BlackboardAttribute.Type(TSK_PATH)),
			new DefaultAttributeExtractor(new BlackboardAttribute.Type(TSK_URL)),
			new CheckedFunction<BlackboardArtifact, AttributeEventDescription>() {
		@Override
		public AttributeEventDescription apply(BlackboardArtifact artf) throws TskCoreException {
			long time = artf.getAttribute(WEB_DOWNLOADS.getDateTimeAttributeType()).getValueLong();
			String domain = WEB_DOWNLOADS.extractShortDescription(artf);
			String path = WEB_DOWNLOADS.extractMedDescription(artf);
			String fileName = StringUtils.substringAfterLast(path, "/");
			String url = WEB_DOWNLOADS.extractFullDescription(artf);

			//TODO: review non default description construction
			String shortDescription = fileName + " from " + domain; // NON-NLS
			String medDescription = fileName + " from " + url; // NON-NLS
			String fullDescription = path + " from " + url; // NON-NLS
			return new AttributeEventDescription(time, shortDescription, medDescription, fullDescription);
		}
	}) {
	};
	public static ArtifactEventType WEB_COOKIE = new AbstractArtifactEventType(9, getBundle().getString("WebTypes.webCookies.name"), WEB_ACTIVITY,
			new BlackboardArtifact.Type(TSK_WEB_COOKIE),
			new BlackboardAttribute.Type(TSK_DATETIME),
			TopPrivateDomainExtractor.getInstance(),
			new DefaultAttributeExtractor(new BlackboardAttribute.Type(TSK_NAME)),
			new DefaultAttributeExtractor(new BlackboardAttribute.Type(TSK_VALUE))) {
	};
	public static ArtifactEventType WEB_BOOKMARK = new AbstractArtifactEventType(10, getBundle().getString("WebTypes.webBookmarks.name"), WEB_ACTIVITY,
			new BlackboardArtifact.Type(TSK_WEB_BOOKMARK),
			new BlackboardAttribute.Type(TSK_DATETIME_CREATED),
			TopPrivateDomainExtractor.getInstance(),
			new DefaultAttributeExtractor(new BlackboardAttribute.Type(TSK_URL)),
			new DefaultAttributeExtractor(new BlackboardAttribute.Type(TSK_TITLE))) {
	};
	public static ArtifactEventType WEB_HISTORY = new AbstractArtifactEventType(11, getBundle().getString("WebTypes.webHistory.name"), WEB_ACTIVITY,
			new BlackboardArtifact.Type(TSK_WEB_HISTORY),
			new BlackboardAttribute.Type(TSK_DATETIME_ACCESSED),
			TopPrivateDomainExtractor.getInstance(),
			new DefaultAttributeExtractor(new BlackboardAttribute.Type(TSK_URL)),
			new DefaultAttributeExtractor(new BlackboardAttribute.Type(TSK_TITLE))) {
	};
	public static ArtifactEventType WEB_SEARCH = new AbstractArtifactEventType(12, getBundle().getString("WebTypes.webSearch.name"), WEB_ACTIVITY,
			new BlackboardArtifact.Type(TSK_WEB_SEARCH_QUERY),
			new BlackboardAttribute.Type(TSK_DATETIME_ACCESSED),
			new DefaultAttributeExtractor(new BlackboardAttribute.Type(TSK_TEXT)),
			TopPrivateDomainExtractor.getInstance(),
			new DefaultAttributeExtractor(new BlackboardAttribute.Type(TSK_PROG_NAME))) {
	};

	static final ImmutableSortedSet<? extends ArtifactEventType> WEB_ACTIVITY_TYPES
			= ImmutableSortedSet.of(WEB_DOWNLOADS, WEB_COOKIE, WEB_BOOKMARK, WEB_HISTORY, WEB_SEARCH);

	final static class TopPrivateDomainExtractor extends DefaultAttributeExtractor {

		final private static TopPrivateDomainExtractor instance = new TopPrivateDomainExtractor();

		static TopPrivateDomainExtractor getInstance() {
			return instance;
		}

		@Override
		public String extract(BlackboardArtifact artf) throws TskCoreException {
			String domainString = StringUtils.substringBefore(super.extract(artf), "/");
			if (InternetDomainName.isValid(domainString)) {
				InternetDomainName domain = InternetDomainName.from(domainString);
				return (domain.isUnderPublicSuffix())
						? domain.topPrivateDomain().toString()
						: domain.toString();
			} else {
				return domainString;
			}
		}

		TopPrivateDomainExtractor() {
			super(new BlackboardAttribute.Type(TSK_DOMAIN));
		}
	}

	public static ArtifactEventType MESSAGE = new AbstractArtifactEventType(13, getBundle().getString("MiscTypes.message.name"),// NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_MESSAGE),
			new BlackboardAttribute.Type(TSK_DATETIME),
			new AbstractArtifactEventType.DefaultAttributeExtractor(new BlackboardAttribute.Type(TSK_MESSAGE_TYPE)),
			(BlackboardArtifact artf) -> {
				final BlackboardAttribute dir = getAttributeSafe(artf, new BlackboardAttribute.Type(TSK_DIRECTION));
				final BlackboardAttribute readStatus = getAttributeSafe(artf, new BlackboardAttribute.Type(TSK_READ_STATUS));
				final BlackboardAttribute name = getAttributeSafe(artf, new BlackboardAttribute.Type(TSK_NAME));
				final BlackboardAttribute phoneNumber = getAttributeSafe(artf, new BlackboardAttribute.Type(TSK_PHONE_NUMBER));
				final BlackboardAttribute subject = getAttributeSafe(artf, new BlackboardAttribute.Type(TSK_SUBJECT));
				List<String> asList = Arrays.asList(stringValueOf(dir),
						stringValueOf(readStatus),
						name == null && phoneNumber == null ? "" : toFrom(dir),
						stringValueOf(MoreObjects.firstNonNull(name, phoneNumber)),
						stringValueOf(subject)
				);
				return StringUtils.join(asList, " ");
			},
			new DefaultAttributeExtractor(new BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TEXT))) {
	};
	public static ArtifactEventType GPS_ROUTE = new AbstractArtifactEventType(14, getBundle().getString("MiscTypes.GPSRoutes.name"), // NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_GPS_ROUTE),
			new BlackboardAttribute.Type(TSK_DATETIME),
			new DefaultAttributeExtractor(new BlackboardAttribute.Type(TSK_PROG_NAME)),
			new DefaultAttributeExtractor(new BlackboardAttribute.Type(TSK_LOCATION)),
			(BlackboardArtifact artf) -> {
				final BlackboardAttribute latStart = getAttributeSafe(artf, new BlackboardAttribute.Type(TSK_GEO_LATITUDE_START));
				final BlackboardAttribute longStart = getAttributeSafe(artf, new BlackboardAttribute.Type(TSK_GEO_LONGITUDE_START));
				final BlackboardAttribute latEnd = getAttributeSafe(artf, new BlackboardAttribute.Type(TSK_GEO_LATITUDE_END));
				final BlackboardAttribute longEnd = getAttributeSafe(artf, new BlackboardAttribute.Type(TSK_GEO_LONGITUDE_END));
				return String.format("from %1$s %2$s to %3$s %4$s", stringValueOf(latStart), stringValueOf(longStart), stringValueOf(latEnd), stringValueOf(longEnd)); // NON-NLS
			}) {
	};
	public static ArtifactEventType GPS_TRACKPOINT = new AbstractArtifactEventType(15, getBundle().getString("MiscTypes.GPSTrackpoint.name"), // NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_GPS_TRACKPOINT),
			new BlackboardAttribute.Type(TSK_DATETIME),
			new DefaultAttributeExtractor(new BlackboardAttribute.Type(TSK_PROG_NAME)),
			artf -> {
				final BlackboardAttribute longitude = getAttributeSafe(artf, new BlackboardAttribute.Type(TSK_GEO_LONGITUDE));
				final BlackboardAttribute latitude = getAttributeSafe(artf, new BlackboardAttribute.Type(TSK_GEO_LATITUDE));
				return stringValueOf(latitude) + " " + stringValueOf(longitude); // NON-NLS
			},
			new AbstractArtifactEventType.EmptyExtractor()) {
	};
	public static ArtifactEventType CALL_LOG = new AbstractArtifactEventType(16, getBundle().getString("MiscTypes.Calls.name"), // NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_CALLLOG),
			new BlackboardAttribute.Type(TSK_DATETIME_START),
			new DefaultAttributeExtractor(new BlackboardAttribute.Type(TSK_NAME)),
			new DefaultAttributeExtractor(new BlackboardAttribute.Type(TSK_PHONE_NUMBER)),
			new DefaultAttributeExtractor(new BlackboardAttribute.Type(TSK_DIRECTION))) {
	};
	public static ArtifactEventType EMAIL = new AbstractArtifactEventType(17, getBundle().getString("MiscTypes.Email.name"), // NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_EMAIL_MSG),
			new BlackboardAttribute.Type(TSK_DATETIME_SENT),
			(BlackboardArtifact artf) -> {
				final BlackboardAttribute emailFrom = getAttributeSafe(artf, new BlackboardAttribute.Type(TSK_EMAIL_FROM));
				final BlackboardAttribute emailTo = getAttributeSafe(artf, new BlackboardAttribute.Type(TSK_EMAIL_TO));
				return stringValueOf(emailFrom) + " to " + stringValueOf(emailTo); // NON-NLS
			},
			new DefaultAttributeExtractor(new BlackboardAttribute.Type(TSK_SUBJECT)),
			new DefaultAttributeExtractor(new BlackboardAttribute.Type(TSK_EMAIL_CONTENT_PLAIN))) {
	};
	public static ArtifactEventType RECENT_DOCUMENTS = new AbstractArtifactEventType(18, getBundle().getString("MiscTypes.recentDocuments.name"), // NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_RECENT_OBJECT),
			new BlackboardAttribute.Type(TSK_DATETIME),
			new DefaultAttributeExtractor(new BlackboardAttribute.Type(TSK_PATH)) {
		@Override
		public String extract(BlackboardArtifact artf) throws TskCoreException {
			String path = super.extract(artf);
			return StringUtils.substringBeforeLast(StringUtils.substringBeforeLast(path, "\\"), "\\");
		}
	},
			new DefaultAttributeExtractor(new BlackboardAttribute.Type(TSK_PATH)) {
		@Override
		public String extract(BlackboardArtifact artf) throws TskCoreException {

			return StringUtils.substringBeforeLast(super.extract(artf), "\\");

		}
	},
			new DefaultAttributeExtractor(new BlackboardAttribute.Type(TSK_PATH)),
			new CheckedFunction<BlackboardArtifact, AttributeEventDescription>() {
		@Override
		public AttributeEventDescription apply(BlackboardArtifact artf) throws TskCoreException {
			long time = artf.getAttribute(RECENT_DOCUMENTS.getDateTimeAttributeType()).getValueLong();
			//Non-default description construction
			String shortDescription = RECENT_DOCUMENTS.extractShortDescription(artf);
			String medDescription = RECENT_DOCUMENTS.extractMedDescription(artf);
			String fullDescription = RECENT_DOCUMENTS.extractFullDescription(artf);

			return new AttributeEventDescription(time, shortDescription, medDescription, fullDescription);
		}
	}
	) {
	};
	public static ArtifactEventType INSTALLED_PROGRAM = new AbstractArtifactEventType(19, getBundle().getString("MiscTypes.installedPrograms.name"), // NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_INSTALLED_PROG),
			new BlackboardAttribute.Type(TSK_DATETIME),
			new DefaultAttributeExtractor(new BlackboardAttribute.Type(TSK_PROG_NAME)),
			new AbstractArtifactEventType.EmptyExtractor(),
			new AbstractArtifactEventType.EmptyExtractor()) {
	};
	public static ArtifactEventType EXIF = new AbstractArtifactEventType(20, getBundle().getString("MiscTypes.exif.name"), // NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_METADATA_EXIF),
			new BlackboardAttribute.Type(TSK_DATETIME_CREATED),
			new DefaultAttributeExtractor(new BlackboardAttribute.Type(TSK_DEVICE_MAKE)),
			new DefaultAttributeExtractor(new BlackboardAttribute.Type(TSK_DEVICE_MODEL)),
			artf -> {
				AbstractFile file = artf.getSleuthkitCase().getAbstractFileById(artf.getObjectID());
				if (file != null) {
					return file.getName();
				}
				return "error loading file name";
			}) {
	};
	public static final ArtifactEventType DEVICES_ATTACHED = new AbstractArtifactEventType(21, getBundle().getString("MiscTypes.devicesAttached.name"), // NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_DEVICE_ATTACHED),
			new BlackboardAttribute.Type(TSK_DATETIME),
			new DefaultAttributeExtractor(new BlackboardAttribute.Type(TSK_DEVICE_MAKE)),
			new DefaultAttributeExtractor(new BlackboardAttribute.Type(TSK_DEVICE_MODEL)),
			new DefaultAttributeExtractor(new BlackboardAttribute.Type(TSK_DEVICE_ID))) {
	};

	static final ImmutableSortedSet<ArtifactEventType> MISC_EVENTS
			= ImmutableSortedSet.of(CALL_LOG,
					DEVICES_ATTACHED,
					EMAIL,
					EXIF,
					GPS_ROUTE,
					GPS_TRACKPOINT,
					INSTALLED_PROGRAM,
					MESSAGE,
					RECENT_DOCUMENTS);

	static public String stringValueOf(BlackboardAttribute attr) {
		return Optional.ofNullable(attr)
				.map(BlackboardAttribute::getDisplayString)
				.orElse("");
	}

	public static String toFrom(BlackboardAttribute dir) {
		if (dir == null) {
			return "";
		} else {
			switch (dir.getDisplayString()) {
				case "Incoming": // NON-NLS
					return "from"; // NON-NLS
				case "Outgoing": // NON-NLS
					return "to"; // NON-NLS
				default:
					return ""; // NON-NLS
				}
		}
	}

	interface CheckedFunction<I, O> {
		O apply(I input) throws TskCoreException;
	}
}
