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

import com.google.common.base.MoreObjects;
import com.google.common.collect.ImmutableSortedSet;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.SortedSet;
import org.sleuthkit.datamodel.BlackboardArtifact;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.*;
import org.sleuthkit.datamodel.BlackboardAttribute;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.*;
import org.sleuthkit.datamodel.BlackboardAttribute.Type;
import static org.sleuthkit.datamodel.timeline.BundleProvider.getBundle;
import static org.sleuthkit.datamodel.timeline.EventType.RECENT_DOCUMENTS;
import static org.sleuthkit.datamodel.timeline.EventTypeZoomLevel.BASE_TYPE;
import static org.sleuthkit.datamodel.timeline.EventTypeZoomLevel.ROOT_TYPE;
import static org.sleuthkit.datamodel.timeline.EventTypeZoomLevel.SUB_TYPE;
import org.sleuthkit.datamodel.timeline.EventTypes.EmptyExtractor;
import org.sleuthkit.datamodel.timeline.EventTypes.FilePathArtifactEventType;
import org.sleuthkit.datamodel.timeline.EventTypes.FilePathEventType;
import org.sleuthkit.datamodel.timeline.EventTypes.URLArtifactEventType;
import org.sleuthkit.datamodel.timeline.StandardArtifactEventType.AttributeExtractor;
import static org.sleuthkit.datamodel.timeline.StandardArtifactEventType.getAttributeSafe;
import org.sleuthkit.datamodel.timeline.TimelineEvent.EventDescription;

/**
 * An Event Type represents a distinct kind of event ie file system or web
 * activity. An EventType may have an optional super-type and 0 or more
 * subtypes, allowing events to be organized in a type hierarchy.
 */
public interface EventType extends Comparable<EventType> {

	String getDisplayName();

	long getTypeID();

	EventTypeZoomLevel getZoomLevel();

	/**
	 * @return A list of EventTypes, one for each subtype of this EventTYpe, or
	 *         an empty set if this EventType has no subtypes.
	 */
	SortedSet<? extends EventType> getSubTypes();

	Optional<? extends EventType> getSubType(String string);

	/**
	 * Parse the three raw descriptions from the DB into a EventDescription
	 * object.
	 *
	 * @param fullDescriptionRaw
	 * @param medDescriptionRaw
	 * @param shortDescriptionRaw
	 *
	 * @return
	 */
	EventDescription parseDescription(String fullDescriptionRaw, String medDescriptionRaw, String shortDescriptionRaw);

	/**
	 * @return the super type of this event
	 */
	EventType getSuperType();

	default EventType getBaseType() {
		EventType superType = getSuperType();

		return superType.equals(ROOT_EVENT_TYPE)
				? this
				: superType.getBaseType();

	}

	default SortedSet<? extends EventType> getSiblingTypes() {
		return this.equals(ROOT_EVENT_TYPE)
				? ImmutableSortedSet.of(ROOT_EVENT_TYPE)
				: this.getSuperType().getSubTypes();

	}

	@Override
	default int compareTo(EventType otherType) {
		return Comparator.comparing(EventType::getTypeID).compare(this, otherType);
	}

	/**
	 * The root type of all event types. No event should actually have this
	 * type.
	 */
	EventType ROOT_EVENT_TYPE = new StandardEventType(0,
			getBundle().getString("RootEventType.eventTypes.name"), // NON-NLS
			ROOT_TYPE, null) {
		@Override
		public SortedSet< EventType> getSubTypes() {
			return ImmutableSortedSet.of(FILE_SYSTEM, WEB_ACTIVITY, MISC_TYPES, CUSTOM_TYPES);
		}
	};

	EventType FILE_SYSTEM = new StandardEventType(1,
			getBundle().getString("BaseTypes.fileSystem.name"),// NON-NLS
			BASE_TYPE, ROOT_EVENT_TYPE) {
		@Override
		public SortedSet< EventType> getSubTypes() {
			return ImmutableSortedSet.of(FILE_MODIFIED, FILE_ACCESSED,
					FILE_CREATED, FILE_CHANGED);
		}
	};
	EventType WEB_ACTIVITY = new StandardEventType(2,
			getBundle().getString("BaseTypes.webActivity.name"), // NON-NLS
			BASE_TYPE, ROOT_EVENT_TYPE) {
		@Override
		public SortedSet< ArtifactEventType> getSubTypes() {
			return ImmutableSortedSet.of(WEB_DOWNLOADS, WEB_COOKIE, WEB_BOOKMARK,
					WEB_HISTORY, WEB_SEARCH);
		}
	};
	EventType MISC_TYPES = new StandardEventType(3,
			getBundle().getString("BaseTypes.miscTypes.name"), // NON-NLS
			BASE_TYPE, ROOT_EVENT_TYPE) {
		@Override
		public SortedSet<EventType> getSubTypes() {
			return ImmutableSortedSet.of(CALL_LOG, DEVICES_ATTACHED, EMAIL,
					EXIF, GPS_ROUTE, GPS_TRACKPOINT, INSTALLED_PROGRAM, MESSAGE,
					RECENT_DOCUMENTS, REGISTRY, LOG_ENTRY);
		}
	};

	EventType FILE_MODIFIED = new FilePathEventType(4,
			getBundle().getString("FileSystemTypes.fileModified.name"), // NON-NLS
			SUB_TYPE, FILE_SYSTEM);
	EventType FILE_ACCESSED = new FilePathEventType(5,
			getBundle().getString("FileSystemTypes.fileAccessed.name"), // NON-NLS
			SUB_TYPE, FILE_SYSTEM);
	EventType FILE_CREATED = new FilePathEventType(6,
			getBundle().getString("FileSystemTypes.fileCreated.name"), // NON-NLS
			SUB_TYPE, FILE_SYSTEM);
	EventType FILE_CHANGED = new FilePathEventType(7,
			getBundle().getString("FileSystemTypes.fileChanged.name"), // NON-NLS
			SUB_TYPE, FILE_SYSTEM);

	ArtifactEventType WEB_DOWNLOADS = new URLArtifactEventType(8,
			getBundle().getString("WebTypes.webDownloads.name"), // NON-NLS
			WEB_ACTIVITY,
			new BlackboardArtifact.Type(TSK_WEB_DOWNLOAD),
			new Type(TSK_DATETIME_ACCESSED),
			new Type(TSK_URL));
	ArtifactEventType WEB_COOKIE = new URLArtifactEventType(9,
			getBundle().getString("WebTypes.webCookies.name"),// NON-NLS
			WEB_ACTIVITY,
			new BlackboardArtifact.Type(TSK_WEB_COOKIE),
			new Type(TSK_DATETIME),
			new Type(TSK_URL));
	ArtifactEventType WEB_BOOKMARK = new URLArtifactEventType(10,
			getBundle().getString("WebTypes.webBookmarks.name"), // NON-NLS
			WEB_ACTIVITY,
			new BlackboardArtifact.Type(TSK_WEB_BOOKMARK),
			new Type(TSK_DATETIME_CREATED),
			new Type(TSK_URL));
	ArtifactEventType WEB_HISTORY = new URLArtifactEventType(11,
			getBundle().getString("WebTypes.webHistory.name"), // NON-NLS
			WEB_ACTIVITY,
			new BlackboardArtifact.Type(TSK_WEB_HISTORY),
			new Type(TSK_DATETIME_ACCESSED),
			new Type(TSK_URL));
	ArtifactEventType WEB_SEARCH = new URLArtifactEventType(12,
			getBundle().getString("WebTypes.webSearch.name"), // NON-NLS
			WEB_ACTIVITY,
			new BlackboardArtifact.Type(TSK_WEB_SEARCH_QUERY),
			new Type(TSK_DATETIME_ACCESSED),
			new Type(TSK_DOMAIN));

	ArtifactEventType MESSAGE = new StandardArtifactEventType(13,
			getBundle().getString("MiscTypes.message.name"),// NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_MESSAGE),
			new Type(TSK_DATETIME),
			new StandardArtifactEventType.AttributeExtractor(new Type(TSK_MESSAGE_TYPE)),
			artf -> {
				final BlackboardAttribute dir = getAttributeSafe(artf, new Type(TSK_DIRECTION));
				final BlackboardAttribute readStatus = getAttributeSafe(artf, new Type(TSK_READ_STATUS));
				final BlackboardAttribute name = getAttributeSafe(artf, new Type(TSK_NAME));
				final BlackboardAttribute phoneNumber = getAttributeSafe(artf, new Type(TSK_PHONE_NUMBER));
				final BlackboardAttribute subject = getAttributeSafe(artf, new Type(TSK_SUBJECT));
				List<String> asList = Arrays.asList(
						stringValueOf(dir),
						stringValueOf(readStatus),
						name == null && phoneNumber == null ? "" : toFrom(dir),
						stringValueOf(MoreObjects.firstNonNull(name, phoneNumber)),
						stringValueOf(subject)
				);
				return String.join(" ", asList);
			},
			new AttributeExtractor(new Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TEXT)));

	ArtifactEventType GPS_ROUTE = new StandardArtifactEventType(14,
			getBundle().getString("MiscTypes.GPSRoutes.name"), // NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_GPS_ROUTE),
			new Type(TSK_DATETIME),
			new AttributeExtractor(new Type(TSK_PROG_NAME)),
			new AttributeExtractor(new Type(TSK_LOCATION)),
			artf -> {
				final BlackboardAttribute latStart = getAttributeSafe(artf, new Type(TSK_GEO_LATITUDE_START));
				final BlackboardAttribute longStart = getAttributeSafe(artf, new Type(TSK_GEO_LONGITUDE_START));
				final BlackboardAttribute latEnd = getAttributeSafe(artf, new Type(TSK_GEO_LATITUDE_END));
				final BlackboardAttribute longEnd = getAttributeSafe(artf, new Type(TSK_GEO_LONGITUDE_END));
				return String.format("from %1$s %2$s to %3$s %4$s", stringValueOf(latStart), stringValueOf(longStart), stringValueOf(latEnd), stringValueOf(longEnd)); // NON-NLS
			});

	ArtifactEventType GPS_TRACKPOINT = new StandardArtifactEventType(15,
			getBundle().getString("MiscTypes.GPSTrackpoint.name"), // NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_GPS_TRACKPOINT),
			new Type(TSK_DATETIME),
			new AttributeExtractor(new Type(TSK_PROG_NAME)),
			artf -> {
				final BlackboardAttribute longitude = getAttributeSafe(artf, new Type(TSK_GEO_LONGITUDE));
				final BlackboardAttribute latitude = getAttributeSafe(artf, new Type(TSK_GEO_LATITUDE));
				return stringValueOf(latitude) + " " + stringValueOf(longitude); // NON-NLS
			},
			new EmptyExtractor());

	ArtifactEventType CALL_LOG = new StandardArtifactEventType(16,
			getBundle().getString("MiscTypes.Calls.name"), // NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_CALLLOG),
			new Type(TSK_DATETIME_START),
			new AttributeExtractor(new Type(TSK_NAME)),
			new AttributeExtractor(new Type(TSK_PHONE_NUMBER)),
			new AttributeExtractor(new Type(TSK_DIRECTION)));

	ArtifactEventType EMAIL = new StandardArtifactEventType(17,
			getBundle().getString("MiscTypes.Email.name"), // NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_EMAIL_MSG),
			new Type(TSK_DATETIME_SENT),
			artf -> {
				final BlackboardAttribute emailFrom = getAttributeSafe(artf, new Type(TSK_EMAIL_FROM));
				final BlackboardAttribute emailTo = getAttributeSafe(artf, new Type(TSK_EMAIL_TO));
				return stringValueOf(emailFrom) + " to " + stringValueOf(emailTo); // NON-NLS
			},
			new AttributeExtractor(new Type(TSK_SUBJECT)),
			new AttributeExtractor(new Type(TSK_EMAIL_CONTENT_PLAIN)));

	ArtifactEventType RECENT_DOCUMENTS = new FilePathArtifactEventType(18,
			getBundle().getString("MiscTypes.recentDocuments.name"), // NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_RECENT_OBJECT),
			new Type(TSK_DATETIME),
			new Type(TSK_PATH));

	ArtifactEventType INSTALLED_PROGRAM = new StandardArtifactEventType(19,
			getBundle().getString("MiscTypes.installedPrograms.name"), // NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_INSTALLED_PROG),
			new Type(TSK_DATETIME),
			new AttributeExtractor(new Type(TSK_PROG_NAME)),
			new EmptyExtractor(),
			new EmptyExtractor());

	ArtifactEventType EXIF = new StandardArtifactEventType(20,
			getBundle().getString("MiscTypes.exif.name"), // NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_METADATA_EXIF),
			new Type(TSK_DATETIME_CREATED),
			new AttributeExtractor(new Type(TSK_DEVICE_MAKE)),
			new AttributeExtractor(new Type(TSK_DEVICE_MODEL)),
			artf -> artf.getSleuthkitCase().getAbstractFileById(artf.getObjectID()).getName()
	);

	ArtifactEventType DEVICES_ATTACHED = new StandardArtifactEventType(21,
			getBundle().getString("MiscTypes.devicesAttached.name"), // NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_DEVICE_ATTACHED),
			new Type(TSK_DATETIME),
			new AttributeExtractor(new Type(TSK_DEVICE_MAKE)),
			new AttributeExtractor(new Type(TSK_DEVICE_MODEL)),
			new AttributeExtractor(new Type(TSK_DEVICE_ID)));

	//custom event type base type
	EventType CUSTOM_TYPES = new StandardEventType(22,
			getBundle().getString("BaseTypes.customTypes.name"), // NON-NLS
			BASE_TYPE, ROOT_EVENT_TYPE) {
		@Override
		public SortedSet< EventType> getSubTypes() {
			return ImmutableSortedSet.of(OTHER, USER_CREATED);
		}
	};

	//generic catch all other event
	ArtifactEventType OTHER = new SingleDescriptionArtifactEventType(23,
			getBundle().getString("CustomTypes.other.name"), //NON-NLS
			CUSTOM_TYPES,
			new BlackboardArtifact.Type(TSK_TL_EVENT),
			new BlackboardAttribute.Type(TSK_DATETIME),
			new BlackboardAttribute.Type(TSK_DESCRIPTION));

	//new misc types
	ArtifactEventType LOG_ENTRY = new SingleDescriptionArtifactEventType(24,
			getBundle().getString("MiscTypes.LogEntry.name"), //NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_TL_EVENT),
			new BlackboardAttribute.Type(TSK_DATETIME),
			new BlackboardAttribute.Type(TSK_DESCRIPTION));

	ArtifactEventType REGISTRY = new SingleDescriptionArtifactEventType(25,
			getBundle().getString("MiscTypes.Registry.name"), //NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_TL_EVENT),
			new BlackboardAttribute.Type(TSK_DATETIME),
			new BlackboardAttribute.Type(TSK_DESCRIPTION));

	//generic catch all other event
	ArtifactEventType USER_CREATED = new SingleDescriptionArtifactEventType(26,
			getBundle().getString("CustomTypes.userCreated.name"),//NON-NLS
			CUSTOM_TYPES,
			new BlackboardArtifact.Type(TSK_TL_EVENT),
			new BlackboardAttribute.Type(TSK_DATETIME),
			new BlackboardAttribute.Type(TSK_DESCRIPTION));

	static SortedSet<? extends EventType> getBaseTypes() {
		return ROOT_EVENT_TYPE.getSubTypes();
	}

	static SortedSet<? extends EventType> getFileSystemTypes() {
		return FILE_SYSTEM.getSubTypes();
	}

	static SortedSet<? extends EventType> getWebActivityTypes() {
		return WEB_ACTIVITY.getSubTypes();
	}

	static SortedSet<? extends EventType> getMiscTypes() {
		return MISC_TYPES.getSubTypes();
	}

	static String stringValueOf(BlackboardAttribute attr) {
		return Optional.ofNullable(attr)
				.map(BlackboardAttribute::getDisplayString)
				.orElse("");
	}

	static String toFrom(BlackboardAttribute dir) {
		if (dir == null) {
			return "";
		} else {
			switch (dir.getDisplayString()) {
				case "Incoming": // NON-NLS
					return "from"; // NON-NLS
				case "Outgoing": // NON-NLS
					return "to"; // NON-NLS
				default:
					return " "; // NON-NLS

			}
		}
	}
}
