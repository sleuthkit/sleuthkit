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
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.SortedSet;
import java.util.function.Function;
import java.util.function.Supplier;
import org.apache.commons.lang3.StringUtils;
import static org.apache.commons.lang3.StringUtils.substringBeforeLast;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.BlackboardArtifact;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.*;
import org.sleuthkit.datamodel.BlackboardAttribute;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.*;
import org.sleuthkit.datamodel.BlackboardAttribute.Type;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.timeline.ArtifactEventType.AttributeEventDescription;
import static org.sleuthkit.datamodel.timeline.BundleUtils.getBundle;
import static org.sleuthkit.datamodel.timeline.EventTypeZoomLevel.*;
import org.sleuthkit.datamodel.timeline.StandardArtifactEventType.AttributeExtractor;
import org.sleuthkit.datamodel.timeline.StandardArtifactEventType.TopPrivateDomainExtractor;
import static org.sleuthkit.datamodel.timeline.StandardArtifactEventType.getAttributeSafe;

/**
 * An Event Type represents a distinct kind of event ie file system or web
 * activity. An EventType may have an optional super-type and 0 or more
 * subtypes, allowing events to be organized in a type hierarchy.
 */
public interface EventType extends Comparable<EventType> {

	String getDisplayName();

	int getTypeID();

	EventTypeZoomLevel getZoomLevel();

	/**
	 * @return A list of EventTypes, one for each subtype of this EventTYpe, or
	 *         an empty set if this EventType has no subtypes.
	 */
	SortedSet<? extends EventType> getSubTypes();

	Optional<? extends EventType> getSubType(String string);

	/**
	 * @return the super type of this event
	 */
	EventType getSuperType();

	default EventType getBaseType() {
		EventType superType = getSuperType();

		return superType.equals(ROOT_EVEN_TYPE)
				? EventType.this
				: superType.getBaseType();

	}

	default SortedSet<? extends EventType> getSiblingTypes() {
		return this.equals(ROOT_EVEN_TYPE)
				? ImmutableSortedSet.of( ROOT_EVEN_TYPE)
				: this.getSuperType().getSubTypes();

	}

	@Override
	public default int compareTo(EventType o) {
		return Comparator.comparing(EventType::getTypeID).compare(this, o);
	}

	/**
	 * The root type of all event types. No event should actually have this
	 * type.
	 */
	public static EventType ROOT_EVEN_TYPE = new StandardEventType(0,
			getBundle().getString("RootEventType.eventTypes.name"), // NON-NLS
			ROOT_TYPE, null) {
		@Override
		public SortedSet< EventType> getSubTypes() {
			return ImmutableSortedSet.of(FILE_SYSTEM, WEB_ACTIVITY, MISC_TYPES);
		}
	};

	public static EventType FILE_SYSTEM = new StandardEventType(1,
			getBundle().getString("BaseTypes.fileSystem.name"),// NON-NLS
			BASE_TYPE, ROOT_EVEN_TYPE) {
		@Override
		public SortedSet< EventType> getSubTypes() {
			return ImmutableSortedSet.of(FILE_MODIFIED, FILE_ACCESSED,
					FILE_CREATED, FILE_CHANGED);
		}
	};
	public static EventType WEB_ACTIVITY = new StandardEventType(2,
			getBundle().getString("BaseTypes.webActivity.name"), // NON-NLS
			BASE_TYPE, ROOT_EVEN_TYPE) {
		@Override
		public SortedSet< ArtifactEventType> getSubTypes() {
			return ImmutableSortedSet.of(WEB_DOWNLOADS, WEB_COOKIE, WEB_BOOKMARK,
					WEB_HISTORY, WEB_SEARCH);
		}
	};
	public static EventType MISC_TYPES = new StandardEventType(3,
			getBundle().getString("BaseTypes.miscTypes.name"), // NON-NLS
			BASE_TYPE, ROOT_EVEN_TYPE) {
		@Override
		public SortedSet< ArtifactEventType> getSubTypes() {
			return ImmutableSortedSet.of(CALL_LOG, DEVICES_ATTACHED, EMAIL,
					EXIF, GPS_ROUTE, GPS_TRACKPOINT, INSTALLED_PROGRAM, MESSAGE,
					RECENT_DOCUMENTS);
		}
	};

	public static EventType FILE_MODIFIED = new StandardEventType(4,
			getBundle().getString("FileSystemTypes.fileModified.name"), // NON-NLS
			SUB_TYPE, FILE_SYSTEM);
	public static EventType FILE_ACCESSED = new StandardEventType(5,
			getBundle().getString("FileSystemTypes.fileAccessed.name"), // NON-NLS
			SUB_TYPE, FILE_SYSTEM);
	public static EventType FILE_CREATED = new StandardEventType(6,
			getBundle().getString("FileSystemTypes.fileCreated.name"), // NON-NLS
			SUB_TYPE, FILE_SYSTEM);
	public static EventType FILE_CHANGED = new StandardEventType(7,
			getBundle().getString("FileSystemTypes.fileChanged.name"), // NON-NLS
			SUB_TYPE, FILE_SYSTEM);

	public static ArtifactEventType WEB_DOWNLOADS = new StandardArtifactEventType(8,
			getBundle().getString("WebTypes.webDownloads.name"), // NON-NLS
			WEB_ACTIVITY,
			new BlackboardArtifact.Type(TSK_WEB_DOWNLOAD),
			new Type(TSK_DATETIME_ACCESSED),
			StandardArtifactEventType.TopPrivateDomainExtractor.getInstance(),
			new AttributeExtractor(new Type(TSK_PATH)),
			new AttributeExtractor(new Type(TSK_URL)),
			artf -> {
				long time = artf.getAttribute(EventType.WEB_DOWNLOADS.getDateTimeAttributeType()).getValueLong();
				String domain = EventType.WEB_DOWNLOADS.extractShortDescription(artf);
				String path = EventType.WEB_DOWNLOADS.extractMedDescription(artf);
				String fileName = StringUtils.substringAfterLast(path, "/");
				String url = EventType.WEB_DOWNLOADS.extractFullDescription(artf);

				//TODO: review non default description construction
				String shortDescription = fileName + " from " + domain; // NON-NLS
				String medDescription = fileName + " from " + url; // NON-NLS
				String fullDescription = path + " from " + url; // NON-NLS
				return new AttributeEventDescription(time, shortDescription, medDescription, fullDescription);
			});
	public static ArtifactEventType WEB_COOKIE = new StandardArtifactEventType(9,
			getBundle().getString("WebTypes.webCookies.name"),// NON-NLS
			WEB_ACTIVITY,
			new BlackboardArtifact.Type(TSK_WEB_COOKIE),
			new Type(TSK_DATETIME),
			TopPrivateDomainExtractor.getInstance(),
			new AttributeExtractor(new Type(TSK_NAME)),
			new AttributeExtractor(new Type(TSK_VALUE)));
	public static ArtifactEventType WEB_BOOKMARK = new StandardArtifactEventType(10,
			getBundle().getString("WebTypes.webBookmarks.name"), // NON-NLS
			WEB_ACTIVITY,
			new BlackboardArtifact.Type(TSK_WEB_BOOKMARK),
			new Type(TSK_DATETIME_CREATED),
			TopPrivateDomainExtractor.getInstance(),
			new AttributeExtractor(new Type(TSK_URL)),
			new AttributeExtractor(new Type(TSK_TITLE)));
	public static ArtifactEventType WEB_HISTORY = new StandardArtifactEventType(11,
			getBundle().getString("WebTypes.webHistory.name"), // NON-NLS
			WEB_ACTIVITY,
			new BlackboardArtifact.Type(TSK_WEB_HISTORY),
			new Type(TSK_DATETIME_ACCESSED),
			TopPrivateDomainExtractor.getInstance(),
			new AttributeExtractor(new Type(TSK_URL)),
			new AttributeExtractor(new Type(TSK_TITLE)));
	public static ArtifactEventType WEB_SEARCH = new StandardArtifactEventType(12,
			getBundle().getString("WebTypes.webSearch.name"), // NON-NLS
			WEB_ACTIVITY,
			new BlackboardArtifact.Type(TSK_WEB_SEARCH_QUERY),
			new Type(TSK_DATETIME_ACCESSED),
			new AttributeExtractor(new Type(TSK_TEXT)),
			TopPrivateDomainExtractor.getInstance(),
			new AttributeExtractor(new Type(TSK_PROG_NAME)));

	public static ArtifactEventType MESSAGE = new StandardArtifactEventType(13,
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
				List<String> asList = Arrays.asList(stringValueOf(dir),
						stringValueOf(readStatus),
						name == null && phoneNumber == null ? "" : toFrom(dir),
						stringValueOf(MoreObjects.firstNonNull(name, phoneNumber)),
						stringValueOf(subject)
				);
				return String.join(" ", asList);
			},
			new AttributeExtractor(new Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TEXT)));

	public static ArtifactEventType GPS_ROUTE = new StandardArtifactEventType(14,
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

	public static ArtifactEventType GPS_TRACKPOINT = new StandardArtifactEventType(15,
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
			new StandardArtifactEventType.EmptyExtractor<>());

	public static ArtifactEventType CALL_LOG = new StandardArtifactEventType(16,
			getBundle().getString("MiscTypes.Calls.name"), // NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_CALLLOG),
			new Type(TSK_DATETIME_START),
			new AttributeExtractor(new Type(TSK_NAME)),
			new AttributeExtractor(new Type(TSK_PHONE_NUMBER)),
			new AttributeExtractor(new Type(TSK_DIRECTION)));

	public static ArtifactEventType EMAIL = new StandardArtifactEventType(17,
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

	public static ArtifactEventType RECENT_DOCUMENTS = new StandardArtifactEventType(18,
			getBundle().getString("MiscTypes.recentDocuments.name"), // NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_RECENT_OBJECT),
			new Type(TSK_DATETIME),
			new AttributeExtractor(new Type(TSK_PATH)) {
		@Override
		public String apply(BlackboardArtifact artf) throws TskCoreException {
			return substringBeforeLast(substringBeforeLast(super.apply(artf), "\\"), "\\");
		}
	},
			new AttributeExtractor(new Type(TSK_PATH)) {
		@Override
		public String apply(BlackboardArtifact artf) throws TskCoreException {

			return substringBeforeLast(super.apply(artf), "\\");

		}
	},
			new AttributeExtractor(new Type(TSK_PATH)),
			artf -> {
				long time = artf.getAttribute(EventType.RECENT_DOCUMENTS.getDateTimeAttributeType()).getValueLong();
				//Non-default description construction
				String shortDescription = EventType.RECENT_DOCUMENTS.extractShortDescription(artf);
				String medDescription = EventType.RECENT_DOCUMENTS.extractMedDescription(artf);
				String fullDescription = EventType.RECENT_DOCUMENTS.extractFullDescription(artf);

				return new AttributeEventDescription(time, shortDescription, medDescription, fullDescription);
			});

	public static ArtifactEventType INSTALLED_PROGRAM = new StandardArtifactEventType(19,
			getBundle().getString("MiscTypes.installedPrograms.name"), // NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_INSTALLED_PROG),
			new Type(TSK_DATETIME),
			new AttributeExtractor(new Type(TSK_PROG_NAME)),
			new StandardArtifactEventType.EmptyExtractor<>(),
			new StandardArtifactEventType.EmptyExtractor<>());

	public static ArtifactEventType EXIF = new StandardArtifactEventType(20,
			getBundle().getString("MiscTypes.exif.name"), // NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_METADATA_EXIF),
			new Type(TSK_DATETIME_CREATED),
			new AttributeExtractor(new Type(TSK_DEVICE_MAKE)),
			new AttributeExtractor(new Type(TSK_DEVICE_MODEL)),
			artf -> {
				AbstractFile file = artf.getSleuthkitCase().getAbstractFileById(artf.getObjectID());
				if (file != null) {
					return file.getName();
				}
				return "error loading file name";
			});

	public static final ArtifactEventType DEVICES_ATTACHED = new StandardArtifactEventType(21,
			getBundle().getString("MiscTypes.devicesAttached.name"), // NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_DEVICE_ATTACHED),
			new Type(TSK_DATETIME),
			new AttributeExtractor(new Type(TSK_DEVICE_MAKE)),
			new AttributeExtractor(new Type(TSK_DEVICE_MODEL)),
			new AttributeExtractor(new Type(TSK_DEVICE_ID)));

	public static SortedSet<? extends EventType> getBaseTypes() {
		return ROOT_EVEN_TYPE.getSubTypes();
	}

	public static SortedSet<? extends EventType> getFileSystemTypes() {
		return FILE_SYSTEM.getSubTypes();
	}

	public static SortedSet<? extends EventType> getWebActivityTypes() {
		return WEB_ACTIVITY.getSubTypes();
	}

	public static SortedSet<? extends EventType> getMiscTypes() {
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

	interface CheckedFunction<I, O> {

		O apply(I input) throws TskCoreException;
	}

}
