/*
 * Sleuth Kit Data Model
 *
 * Copyright 2018-2021 Basis Technology Corp.
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

import com.google.common.annotations.Beta;
import com.google.common.base.MoreObjects;
import com.google.common.collect.ImmutableSortedSet;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.SortedSet;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.*;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.*;
import org.sleuthkit.datamodel.BlackboardAttribute.Type;
import static org.sleuthkit.datamodel.BundleProvider.getBundle;
import org.sleuthkit.datamodel.TimelineEventTypes.EmptyExtractor;
import org.sleuthkit.datamodel.TimelineEventTypes.FilePathArtifactEventType;
import org.sleuthkit.datamodel.TimelineEventTypes.FilePathEventType;
import org.sleuthkit.datamodel.TimelineEventTypes.URLArtifactEventType;
import org.sleuthkit.datamodel.TimelineEventTypes.GPSTrackArtifactEventType;
import org.sleuthkit.datamodel.TimelineEventArtifactTypeImpl.AttributeExtractor;
import static org.sleuthkit.datamodel.TimelineEventArtifactTypeImpl.getAttributeSafe;

/**
 * An interface implemented by timeline event types. Timeline event types are
 * organized into a type hierarchy. This type hierarchy has three levels: the
 * root level, the category level (e.g, file system events, web activity
 * events), and the actual event level (e.g., file modified events, web download
 * events).
 *
 * Currently (9/20/19), all supported timeline event types are defined as
 * members of this interface.
 *
 * WARNING: THIS INTERFACE IS A "BETA" INTERFACE AND IS SUBJECT TO CHANGE AT ANY
 * TIME.
 */
@Beta
public interface TimelineEventType extends Comparable<TimelineEventType> {

	/**
	 * Gets the display name of this event type.
	 *
	 * @return The event type display name.
	 */
	String getDisplayName();

	/**
	 * Gets the unique ID of this event type in the case database.
	 *
	 * @return The event type ID.
	 */
	long getTypeID();

	/**
	 * Gets the type hierarchy level of this event type.
	 *
	 * @return The type hierarchy level.
	 */
	TimelineEventType.HierarchyLevel getTypeHierarchyLevel();

	/**
	 * Gets the child event types of this event type in the type hierarchy.
	 *
	 * @return A sorted set of the child event types.
	 */
	SortedSet<? extends TimelineEventType> getChildren();

	/**
	 * Gets a specific child event type of this event type in the type
	 * hierarchy.
	 *
	 * @param displayName The display name of the desired child event type.
	 *
	 * @return The child event type in an Optional object, may be empty.
	 */
	Optional<? extends TimelineEventType> getChild(String displayName);

	/**
	 * Gets the parent event type of this event type in the type hierarchy.
	 *
	 * @return The parent event type.
	 */
	TimelineEventType getParent();

	/**
	 * Gets the category level event type for this event type in the type
	 * hierarchy.
	 *
	 * @return The category event type.
	 */
	default TimelineEventType getCategory() {
		TimelineEventType parentType = getParent();
		return parentType.equals(ROOT_EVENT_TYPE)
				? this
				: parentType.getCategory();
	}

	/**
	 * Gets the sibling event types of this event type in the type hierarchy.
	 *
	 * @return The sibling event types.
	 */
	default SortedSet<? extends TimelineEventType> getSiblings() {
		return this.equals(ROOT_EVENT_TYPE)
				? ImmutableSortedSet.of(ROOT_EVENT_TYPE)
				: this.getParent().getChildren();
	}

	@Override
	default int compareTo(TimelineEventType otherType) {
		return Comparator.comparing(TimelineEventType::getDisplayName).compare(this, otherType);
	}

	/**
	 * An enumeration of the levels in the event type hierarchy.
	 */
	public enum HierarchyLevel {

		/**
		 * The root level of the event types hierarchy.
		 */
		ROOT(getBundle().getString("EventTypeHierarchyLevel.root")),
		/**
		 * The category level of the event types hierarchy. Event types at this
		 * level represent event categories such as file system events and web
		 * activity events.
		 */
		CATEGORY(getBundle().getString("EventTypeHierarchyLevel.category")),
		/**
		 * The actual events level of the event types hierarchy. Event types at
		 * this level represent actual events such as file modified time events
		 * and web download events.
		 */
		EVENT(getBundle().getString("EventTypeHierarchyLevel.event"));

		private final String displayName;

		/**
		 * Gets the display name of this element of the enumeration of the
		 * levels in the event type hierarchy.
		 *
		 * @return The display name.
		 */
		public String getDisplayName() {
			return displayName;
		}

		/**
		 * Constructs an element of the enumeration of the levels in the event
		 * type hierarchy.
		 *
		 * @param displayName The display name of this hierarchy level.
		 */
		private HierarchyLevel(String displayName) {
			this.displayName = displayName;
		}

	}

	/**
	 * The root type of all event types. No event should actually have this
	 * type.
	 */
	TimelineEventType ROOT_EVENT_TYPE = new TimelineEventTypeImpl(0,
			getBundle().getString("RootEventType.eventTypes.name"), // NON-NLS
			HierarchyLevel.ROOT, null) {
				
		@Override
		public SortedSet< TimelineEventType> getChildren() {
			ImmutableSortedSet.Builder<TimelineEventType> builder = ImmutableSortedSet.orderedBy(new Comparator<TimelineEventType>() {
				@Override
				public int compare(TimelineEventType o1, TimelineEventType o2) {
					return ((Long) o1.getTypeID()).compareTo(o2.getTypeID());
				}
			});

			builder.add(FILE_SYSTEM, WEB_ACTIVITY, MISC_TYPES);
			return builder.build();
		}
	};

	TimelineEventType FILE_SYSTEM = new TimelineEventTypeImpl(1,
			getBundle().getString("BaseTypes.fileSystem.name"),// NON-NLS
			HierarchyLevel.CATEGORY, ROOT_EVENT_TYPE) {
		@Override
		public SortedSet< TimelineEventType> getChildren() {
			return ImmutableSortedSet.of(FILE_MODIFIED, FILE_ACCESSED,
					FILE_CREATED, FILE_CHANGED);
		}
	};

	TimelineEventType WEB_ACTIVITY = new TimelineEventTypeImpl(2,
			getBundle().getString("BaseTypes.webActivity.name"), // NON-NLS
			HierarchyLevel.CATEGORY, ROOT_EVENT_TYPE) {
		@Override
		public SortedSet< TimelineEventType> getChildren() {
			return ImmutableSortedSet.of(WEB_DOWNLOADS, WEB_COOKIE,
					WEB_COOKIE_ACCESSED,
					WEB_COOKIE_END, WEB_BOOKMARK,
					WEB_HISTORY, WEB_SEARCH, WEB_FORM_AUTOFILL,
					WEB_FORM_ADDRESSES, WEB_FORM_ADDRESSES_MODIFIED,
					WEB_FORM_AUTOFILL_ACCESSED, WEB_CACHE, WEB_HISTORY_CREATED);
		}
	};

	// The MISC_TYPE events are sorted alphebetically by their display name instead of their 
	// "natural order" which is by their event ID.
	TimelineEventType MISC_TYPES = new TimelineEventTypeImpl(3,
			getBundle().getString("BaseTypes.miscTypes.name"), // NON-NLS
			HierarchyLevel.CATEGORY, ROOT_EVENT_TYPE) {
		@Override
		public SortedSet<TimelineEventType> getChildren() {
			return ImmutableSortedSet.of(CALL_LOG, CALL_LOG_END, DEVICES_ATTACHED, EMAIL, EMAIL_RCVD,
					EXIF, GPS_BOOKMARK, GPS_LAST_KNOWN_LOCATION, GPS_TRACKPOINT,
					GPS_ROUTE, GPS_SEARCH, GPS_TRACK, INSTALLED_PROGRAM, LOG_ENTRY, MESSAGE,
					METADATA_LAST_PRINTED, METADATA_LAST_SAVED, METADATA_CREATED, PROGRAM_EXECUTION,
					RECENT_DOCUMENTS, REGISTRY, BACKUP_EVENT_START, BACKUP_EVENT_END,
					BLUETOOTH_PAIRING, CALENDAR_ENTRY_START, CALENDAR_ENTRY_END,
					PROGRAM_DELETED,
					OS_INFO, WIFI_NETWORK, USER_DEVICE_EVENT_START, USER_DEVICE_EVENT_END,
					SERVICE_ACCOUNT, SCREEN_SHOT, PROGRAM_NOTIFICATION,
					BLUETOOTH_PAIRING_ACCESSED, BLUETOOTH_ADAPTER, CUSTOM_ARTIFACT_CATCH_ALL, STANDARD_ARTIFACT_CATCH_ALL, USER_CREATED);

		}
	};

	TimelineEventType FILE_MODIFIED = new FilePathEventType(4,
			getBundle().getString("FileSystemTypes.fileModified.name"), // NON-NLS
			HierarchyLevel.EVENT, FILE_SYSTEM);

	TimelineEventType FILE_ACCESSED = new FilePathEventType(5,
			getBundle().getString("FileSystemTypes.fileAccessed.name"), // NON-NLS
			HierarchyLevel.EVENT, FILE_SYSTEM);

	TimelineEventType FILE_CREATED = new FilePathEventType(6,
			getBundle().getString("FileSystemTypes.fileCreated.name"), // NON-NLS
			HierarchyLevel.EVENT, FILE_SYSTEM);

	TimelineEventType FILE_CHANGED = new FilePathEventType(7,
			getBundle().getString("FileSystemTypes.fileChanged.name"), // NON-NLS
			HierarchyLevel.EVENT, FILE_SYSTEM);

	TimelineEventType WEB_DOWNLOADS = new URLArtifactEventType(8,
			getBundle().getString("WebTypes.webDownloads.name"), // NON-NLS
			WEB_ACTIVITY,
			new BlackboardArtifact.Type(TSK_WEB_DOWNLOAD),
			new Type(TSK_DATETIME_ACCESSED),
			new Type(TSK_URL));

	TimelineEventType WEB_COOKIE = new URLArtifactEventType(9,
			getBundle().getString("WebTypes.webCookies.name"),// NON-NLS
			WEB_ACTIVITY,
			new BlackboardArtifact.Type(TSK_WEB_COOKIE),
			new Type(TSK_DATETIME_CREATED),
			new Type(TSK_URL));

	TimelineEventType WEB_BOOKMARK = new URLArtifactEventType(10,
			getBundle().getString("WebTypes.webBookmarks.name"), // NON-NLS
			WEB_ACTIVITY,
			new BlackboardArtifact.Type(TSK_WEB_BOOKMARK),
			new Type(TSK_DATETIME_CREATED),
			new Type(TSK_URL));

	TimelineEventType WEB_HISTORY = new URLArtifactEventType(11,
			getBundle().getString("WebTypes.webHistory.name"), // NON-NLS
			WEB_ACTIVITY,
			new BlackboardArtifact.Type(TSK_WEB_HISTORY),
			new Type(TSK_DATETIME_ACCESSED),
			new Type(TSK_URL));

	TimelineEventType WEB_SEARCH = new URLArtifactEventType(12,
			getBundle().getString("WebTypes.webSearch.name"), // NON-NLS
			WEB_ACTIVITY,
			new BlackboardArtifact.Type(TSK_WEB_SEARCH_QUERY),
			new Type(TSK_DATETIME_ACCESSED),
			new Type(TSK_DOMAIN));

	TimelineEventType MESSAGE = new TimelineEventArtifactTypeImpl(13,
			getBundle().getString("MiscTypes.message.name"),// NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_MESSAGE),
			new Type(TSK_DATETIME),
			new TimelineEventArtifactTypeImpl.AttributeExtractor(new Type(TSK_MESSAGE_TYPE)),
			artf -> {
				final BlackboardAttribute dir = getAttributeSafe(artf, new Type(TSK_DIRECTION));
				final BlackboardAttribute readStatus = getAttributeSafe(artf, new Type(TSK_READ_STATUS));
				final BlackboardAttribute name = getAttributeSafe(artf, new Type(TSK_NAME));
				final BlackboardAttribute subject = getAttributeSafe(artf, new Type(TSK_SUBJECT));
				BlackboardAttribute phoneNumber = getAttributeSafe(artf, new Type(TSK_PHONE_NUMBER));
				// Make our best effort to find a valid phoneNumber for the description
				if (phoneNumber == null) {
					phoneNumber = getAttributeSafe(artf, new Type(TSK_PHONE_NUMBER_TO));
				}

				if (phoneNumber == null) {
					phoneNumber = getAttributeSafe(artf, new Type(TSK_PHONE_NUMBER_FROM));
				}

				List<String> asList = Arrays.asList(
						stringValueOf(dir),
						stringValueOf(readStatus),
						name == null && phoneNumber == null ? "" : toFrom(dir),
						name != null || phoneNumber != null ? stringValueOf(MoreObjects.firstNonNull(name, phoneNumber)) : "",
						stringValueOf(subject)
				);
				return String.join(" ", asList);
			},
			new AttributeExtractor(new Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TEXT)));

	TimelineEventType GPS_ROUTE = new TimelineEventArtifactTypeImpl(14,
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
				return String.format("From latitude: %1$s longitude: %2$s To latitude: %3$s longitude: %4$s", stringValueOf(latStart), stringValueOf(longStart), stringValueOf(latEnd), stringValueOf(longEnd)); // NON-NLS
			});

	@SuppressWarnings("deprecation")
	TimelineEventType GPS_TRACKPOINT = new TimelineEventArtifactTypeImpl(15,
			getBundle().getString("MiscTypes.GPSTrackpoint.name"), // NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_GPS_TRACKPOINT),
			new Type(TSK_DATETIME),
			new AttributeExtractor(new Type(TSK_PROG_NAME)),
			artf -> {
				final BlackboardAttribute longitude = getAttributeSafe(artf, new Type(TSK_GEO_LONGITUDE));
				final BlackboardAttribute latitude = getAttributeSafe(artf, new Type(TSK_GEO_LATITUDE));
				return "Latitude: " + stringValueOf(latitude) + " Longitude: " + stringValueOf(longitude); // NON-NLS
			},
			new EmptyExtractor());

	TimelineEventType CALL_LOG = new TimelineEventArtifactTypeImpl(16,
			getBundle().getString("MiscTypes.Calls.name"), // NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_CALLLOG),
			new Type(TSK_DATETIME_START),
			new AttributeExtractor(new Type(TSK_NAME)),
			artf -> {
				BlackboardAttribute phoneNumber = getAttributeSafe(artf, new Type(TSK_PHONE_NUMBER));
				if (phoneNumber == null) {
					phoneNumber = getAttributeSafe(artf, new Type(TSK_PHONE_NUMBER_TO));
				}
				if (phoneNumber == null) {
					phoneNumber = getAttributeSafe(artf, new Type(TSK_PHONE_NUMBER_FROM));
				}

				return "Phone Number: " + stringValueOf(phoneNumber);
			},
			new AttributeExtractor(new Type(TSK_DIRECTION)));

	TimelineEventType EMAIL = new TimelineEventArtifactTypeImpl(17,
			getBundle().getString("MiscTypes.Email.name"), // NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_EMAIL_MSG),
			new Type(TSK_DATETIME_SENT),
			artf -> {
				String emailFrom = stringValueOf(getAttributeSafe(artf, new Type(TSK_EMAIL_FROM)));
				if (emailFrom.length() > TimelineEventArtifactTypeImpl.EMAIL_TO_FROM_LENGTH_MAX) {
					emailFrom = emailFrom.substring(0, TimelineEventArtifactTypeImpl.EMAIL_TO_FROM_LENGTH_MAX);
				}
				String emailTo = stringValueOf(getAttributeSafe(artf, new Type(TSK_EMAIL_TO)));
				if (emailTo.length() > TimelineEventArtifactTypeImpl.EMAIL_TO_FROM_LENGTH_MAX) {
					emailTo = emailTo.substring(0, TimelineEventArtifactTypeImpl.EMAIL_TO_FROM_LENGTH_MAX);
				}
				return "Sent from: " + emailFrom + "Sent to: " + emailTo; // NON-NLS
			},
			new AttributeExtractor(new Type(TSK_SUBJECT)),
			artf -> {
				final BlackboardAttribute msgAttribute = getAttributeSafe(artf, new Type(TSK_EMAIL_CONTENT_PLAIN));
				String msg = stringValueOf(msgAttribute);
				if (msg.length() > TimelineEventArtifactTypeImpl.EMAIL_FULL_DESCRIPTION_LENGTH_MAX) {
					msg = msg.substring(0, TimelineEventArtifactTypeImpl.EMAIL_FULL_DESCRIPTION_LENGTH_MAX);
				}
				return msg;
			});

	TimelineEventType RECENT_DOCUMENTS = new FilePathArtifactEventType(18,
			getBundle().getString("MiscTypes.recentDocuments.name"), // NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_RECENT_OBJECT),
			new Type(TSK_DATETIME_ACCESSED),
			new Type(TSK_PATH));

	TimelineEventType INSTALLED_PROGRAM = new TimelineEventArtifactTypeImpl(19,
			getBundle().getString("MiscTypes.installedPrograms.name"), // NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_INSTALLED_PROG),
			new Type(TSK_DATETIME),
			new AttributeExtractor(new Type(TSK_PROG_NAME)),
			new EmptyExtractor(),
			new EmptyExtractor());

	TimelineEventType EXIF = new TimelineEventArtifactTypeImpl(20,
			getBundle().getString("MiscTypes.exif.name"), // NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_METADATA_EXIF),
			new Type(TSK_DATETIME_CREATED),
			new AttributeExtractor(new Type(TSK_DEVICE_MAKE)),
			new AttributeExtractor(new Type(TSK_DEVICE_MODEL)),
			artf -> artf.getSleuthkitCase().getAbstractFileById(artf.getObjectID()).getName()
	);

	TimelineEventType DEVICES_ATTACHED = new TimelineEventArtifactTypeImpl(21,
			getBundle().getString("MiscTypes.devicesAttached.name"), // NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_DEVICE_ATTACHED),
			new Type(TSK_DATETIME),
			new AttributeExtractor(new Type(TSK_DEVICE_MAKE)),
			new AttributeExtractor(new Type(TSK_DEVICE_MODEL)),
			new AttributeExtractor(new Type(TSK_DEVICE_ID)));
	
	// TimelineEventType with id 22 has been deprecated. Trying to reuse 22
	// may cause backwards combatibility issues and is not recommened. If 22
	// is reused create upgrade code to reassign event 22 to MISC_TYPE id = 3.
	int DEPRECATED_OTHER_EVENT_ID = 22;

	// Event for any artifact event with an artifact type for which we don't have
	// a hard-corded event type. In other words, we recognize the artifact type
	// as a standard artifact type, but we have not updated the Timeline code
	// to have a corresponding inner TimelineEventType
	TimelineEventType STANDARD_ARTIFACT_CATCH_ALL = new TimelineEventArtifactTypeSingleDescription(23,
			getBundle().getString("CustomTypes.other.name"), //NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_TL_EVENT),
			new BlackboardAttribute.Type(TSK_DATETIME),
			new BlackboardAttribute.Type(TSK_DESCRIPTION));

	//new misc types
	TimelineEventType LOG_ENTRY = new TimelineEventArtifactTypeSingleDescription(24,
			getBundle().getString("MiscTypes.LogEntry.name"), //NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_TL_EVENT),
			new BlackboardAttribute.Type(TSK_DATETIME),
			new BlackboardAttribute.Type(TSK_DESCRIPTION));

	TimelineEventType REGISTRY = new TimelineEventArtifactTypeSingleDescription(25,
			getBundle().getString("MiscTypes.Registry.name"), //NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_TL_EVENT),
			new BlackboardAttribute.Type(TSK_DATETIME),
			new BlackboardAttribute.Type(TSK_DESCRIPTION));

	// Event for any artifact event with a custom artifact type (e.g. shell bag
	// artifact)
	
	TimelineEventType CUSTOM_ARTIFACT_CATCH_ALL = new TimelineEventArtifactTypeSingleDescription(26,
			getBundle().getString("CustomTypes.customArtifact.name"),//NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_TL_EVENT),
			new BlackboardAttribute.Type(TSK_DATETIME),
			new BlackboardAttribute.Type(TSK_DESCRIPTION));

	TimelineEventType WEB_FORM_AUTOFILL = new TimelineEventArtifactTypeImpl(27,
			getBundle().getString("WebTypes.webFormAutoFill.name"),//NON-NLS
			WEB_ACTIVITY,
			new BlackboardArtifact.Type(TSK_WEB_FORM_AUTOFILL),
			new Type(TSK_DATETIME_CREATED),
			artf -> {
				final BlackboardAttribute name = getAttributeSafe(artf, new Type(TSK_NAME));
				final BlackboardAttribute value = getAttributeSafe(artf, new Type(TSK_VALUE));
				final BlackboardAttribute count = getAttributeSafe(artf, new Type(TSK_COUNT));
				return stringValueOf(name) + ":" + stringValueOf(value); // NON-NLS
			}, new EmptyExtractor(), new EmptyExtractor());

	TimelineEventType WEB_FORM_ADDRESSES = new URLArtifactEventType(28,
			getBundle().getString("WebTypes.webFormAddress.name"),//NON-NLS
			WEB_ACTIVITY,
			new BlackboardArtifact.Type(TSK_WEB_FORM_ADDRESS),
			new Type(TSK_DATETIME_ACCESSED),
			new Type(TSK_EMAIL));

	TimelineEventType GPS_BOOKMARK = new TimelineEventArtifactTypeImpl(29,
			getBundle().getString("MiscTypes.GPSBookmark.name"), // NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_GPS_BOOKMARK),
			new Type(TSK_DATETIME),
			new AttributeExtractor(new Type(TSK_NAME)),
			artf -> {
				final BlackboardAttribute longitude = getAttributeSafe(artf, new Type(TSK_GEO_LONGITUDE));
				final BlackboardAttribute latitude = getAttributeSafe(artf, new Type(TSK_GEO_LATITUDE));
				return "Latitude: " + stringValueOf(latitude) + " Longitude: " + stringValueOf(longitude); // NON-NLS
			},
			new EmptyExtractor());

	TimelineEventType GPS_LAST_KNOWN_LOCATION = new TimelineEventArtifactTypeImpl(30,
			getBundle().getString("MiscTypes.GPSLastknown.name"), // NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_GPS_LAST_KNOWN_LOCATION),
			new Type(TSK_DATETIME),
			new AttributeExtractor(new Type(TSK_NAME)),
			artf -> {
				final BlackboardAttribute longitude = getAttributeSafe(artf, new Type(TSK_GEO_LONGITUDE));
				final BlackboardAttribute latitude = getAttributeSafe(artf, new Type(TSK_GEO_LATITUDE));
				return "Latitude: " + stringValueOf(latitude) + " Longitude: " + stringValueOf(longitude); // NON-NLS
			},
			new EmptyExtractor());

	TimelineEventType GPS_SEARCH = new TimelineEventArtifactTypeImpl(31,
			getBundle().getString("MiscTypes.GPSearch.name"), // NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_GPS_SEARCH),
			new Type(TSK_DATETIME),
			new AttributeExtractor(new Type(TSK_NAME)),
			artf -> {
				final BlackboardAttribute longitude = getAttributeSafe(artf, new Type(TSK_GEO_LONGITUDE));
				final BlackboardAttribute latitude = getAttributeSafe(artf, new Type(TSK_GEO_LATITUDE));
				return "Latitude: " + stringValueOf(latitude) + " Longitude: " + stringValueOf(longitude); // NON-NLS
			},
			new EmptyExtractor());

	TimelineEventType GPS_TRACK = new GPSTrackArtifactEventType(32,
			getBundle().getString("MiscTypes.GPSTrack.name"), // NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_GPS_TRACK),
			new Type(TSK_NAME));

	TimelineEventType METADATA_LAST_PRINTED = new TimelineEventArtifactTypeImpl(33,
			getBundle().getString("MiscTypes.metadataLastPrinted.name"),// NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_METADATA),
			new BlackboardAttribute.Type(TSK_LAST_PRINTED_DATETIME),
			artf -> {
				return getBundle().getString("MiscTypes.metadataLastPrinted.name");
			},
			new EmptyExtractor(),
			new EmptyExtractor());

	TimelineEventType METADATA_LAST_SAVED = new TimelineEventArtifactTypeImpl(34,
			getBundle().getString("MiscTypes.metadataLastSaved.name"),// NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_METADATA),
			new BlackboardAttribute.Type(TSK_DATETIME_MODIFIED),
			artf -> {
				return getBundle().getString("MiscTypes.metadataLastSaved.name");
			},
			new EmptyExtractor(),
			new EmptyExtractor());

	TimelineEventType METADATA_CREATED = new TimelineEventArtifactTypeImpl(35,
			getBundle().getString("MiscTypes.metadataCreated.name"),// NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_METADATA),
			new BlackboardAttribute.Type(TSK_DATETIME_CREATED),
			artf -> {
				return getBundle().getString("MiscTypes.metadataCreated.name");
			},
			new EmptyExtractor(),
			new EmptyExtractor());

	TimelineEventType PROGRAM_EXECUTION = new TimelineEventArtifactTypeImpl(36,
			getBundle().getString("MiscTypes.programexecuted.name"),// NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_PROG_RUN),
			new Type(TSK_DATETIME),
			new AttributeExtractor(new Type(TSK_PROG_NAME)),
			artf -> {
				String userName = stringValueOf(getAttributeSafe(artf, new Type(TSK_USER_NAME)));
				if (userName != null) {
					return userName;
				}
				return "";
			},
			new AttributeExtractor(new Type(TSK_COMMENT)));

	TimelineEventType WEB_FORM_AUTOFILL_ACCESSED = new TimelineEventArtifactTypeImpl(37,
			getBundle().getString("WebTypes.webFormAutofillAccessed.name"),
			WEB_ACTIVITY,
			new BlackboardArtifact.Type(TSK_WEB_FORM_AUTOFILL),
			new Type(TSK_DATETIME_ACCESSED),
			artf -> {
				final BlackboardAttribute name = getAttributeSafe(artf, new Type(TSK_NAME));
				final BlackboardAttribute value = getAttributeSafe(artf, new Type(TSK_VALUE));
				final BlackboardAttribute count = getAttributeSafe(artf, new Type(TSK_COUNT));
				return stringValueOf(name) + ":" + stringValueOf(value) + " Access count: " + stringValueOf(count); // NON-NLS
			}, new EmptyExtractor(), new EmptyExtractor());

	TimelineEventType CALL_LOG_END = new TimelineEventArtifactTypeImpl(38,
			getBundle().getString("MiscTypes.CallsEnd.name"), // NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_CALLLOG),
			new Type(TSK_DATETIME_END),
			new AttributeExtractor(new Type(TSK_NAME)),
			artf -> {
				BlackboardAttribute phoneNumber = getAttributeSafe(artf, new Type(TSK_PHONE_NUMBER));
				if (phoneNumber == null) {
					phoneNumber = getAttributeSafe(artf, new Type(TSK_PHONE_NUMBER_TO));
				}
				if (phoneNumber == null) {
					phoneNumber = getAttributeSafe(artf, new Type(TSK_PHONE_NUMBER_FROM));
				}

				return "Phone number: " + stringValueOf(phoneNumber);
			},
			new AttributeExtractor(new Type(TSK_DIRECTION)));

	TimelineEventType EMAIL_RCVD = new TimelineEventArtifactTypeImpl(39,
			getBundle().getString("MiscTypes.EmailRcvd.name"), // NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_EMAIL_MSG),
			new Type(TSK_DATETIME_RCVD),
			artf -> {
				String emailFrom = stringValueOf(getAttributeSafe(artf, new Type(TSK_EMAIL_FROM)));
				if (emailFrom.length() > TimelineEventArtifactTypeImpl.EMAIL_TO_FROM_LENGTH_MAX) {
					emailFrom = emailFrom.substring(0, TimelineEventArtifactTypeImpl.EMAIL_TO_FROM_LENGTH_MAX);
				}
				String emailTo = stringValueOf(getAttributeSafe(artf, new Type(TSK_EMAIL_TO)));
				if (emailTo.length() > TimelineEventArtifactTypeImpl.EMAIL_TO_FROM_LENGTH_MAX) {
					emailTo = emailTo.substring(0, TimelineEventArtifactTypeImpl.EMAIL_TO_FROM_LENGTH_MAX);
				}
				return "Message from: " + emailFrom + " To: " + emailTo; // NON-NLS
			},
			new AttributeExtractor(new Type(TSK_SUBJECT)),
			artf -> {
				final BlackboardAttribute msgAttribute = getAttributeSafe(artf, new Type(TSK_EMAIL_CONTENT_PLAIN));
				String msg = stringValueOf(msgAttribute);
				if (msg.length() > TimelineEventArtifactTypeImpl.EMAIL_FULL_DESCRIPTION_LENGTH_MAX) {
					msg = msg.substring(0, TimelineEventArtifactTypeImpl.EMAIL_FULL_DESCRIPTION_LENGTH_MAX);
				}
				return msg;
			});

	TimelineEventType WEB_FORM_ADDRESSES_MODIFIED = new URLArtifactEventType(40,
			getBundle().getString("WebTypes.webFormAddressModified.name"),//NON-NLS
			WEB_ACTIVITY,
			new BlackboardArtifact.Type(TSK_WEB_FORM_ADDRESS),
			new Type(TSK_DATETIME_MODIFIED),
			new Type(TSK_EMAIL));

	TimelineEventType WEB_COOKIE_ACCESSED = new URLArtifactEventType(41,
			getBundle().getString("WebTypes.webCookiesAccessed.name"),// NON-NLS
			WEB_ACTIVITY,
			new BlackboardArtifact.Type(TSK_WEB_COOKIE),
			new Type(TSK_DATETIME_ACCESSED),
			new Type(TSK_URL));

	TimelineEventType WEB_COOKIE_END = new URLArtifactEventType(42,
			getBundle().getString("WebTypes.webCookiesEnd.name"),// NON-NLS
			WEB_ACTIVITY,
			new BlackboardArtifact.Type(TSK_WEB_COOKIE),
			new Type(TSK_DATETIME_END),
			new Type(TSK_URL));
	
	TimelineEventType BACKUP_EVENT_START = new TimelineEventArtifactTypeImpl(43,
			getBundle().getString("TimelineEventType.BackupEventStart.txt"),// NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_BACKUP_EVENT),
			new BlackboardAttribute.Type(TSK_DATETIME_START),
			artf -> {
				return getBundle().getString("TimelineEventType.BackupEvent.description.start");
			},
			new EmptyExtractor(),
			new EmptyExtractor());
	
	TimelineEventType BACKUP_EVENT_END = new TimelineEventArtifactTypeImpl(44,
			getBundle().getString("TimelineEventType.BackupEventEnd.txt"),// NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_BACKUP_EVENT),
			new BlackboardAttribute.Type(TSK_DATETIME_END),
			artf -> {
				return getBundle().getString("TimelineEventType.BackupEvent.description.end");
			},
			new EmptyExtractor(),
			new EmptyExtractor());
	
	TimelineEventType BLUETOOTH_PAIRING = new TimelineEventArtifactTypeSingleDescription(45,
			getBundle().getString("TimelineEventType.BluetoothPairing.txt"),//NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_BLUETOOTH_PAIRING),
			new BlackboardAttribute.Type(TSK_DATETIME),
			new BlackboardAttribute.Type(TSK_DEVICE_NAME));
	
	TimelineEventType CALENDAR_ENTRY_START = new TimelineEventArtifactTypeSingleDescription(46,
			getBundle().getString("TimelineEventType.CalendarEntryStart.txt"),//NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_CALENDAR_ENTRY),
			new BlackboardAttribute.Type(TSK_DATETIME_START),
			new BlackboardAttribute.Type(TSK_DESCRIPTION));
	
	TimelineEventType CALENDAR_ENTRY_END = new TimelineEventArtifactTypeSingleDescription(47,
			getBundle().getString("TimelineEventType.CalendarEntryEnd.txt"),//NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_CALENDAR_ENTRY),
			new BlackboardAttribute.Type(TSK_DATETIME_END),
			new BlackboardAttribute.Type(TSK_DESCRIPTION));
	
	TimelineEventType PROGRAM_DELETED = new TimelineEventArtifactTypeSingleDescription(48,
			getBundle().getString("TimelineEventType.DeletedProgram.txt"),//NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_DELETED_PROG),
			new BlackboardAttribute.Type(TSK_DATETIME),
			new BlackboardAttribute.Type(TSK_PROG_NAME));	
	
	TimelineEventType OS_INFO = new TimelineEventArtifactTypeSingleDescription(49,
			getBundle().getString("TimelineEventType.OSInfo.txt"),//NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_OS_INFO),
			new BlackboardAttribute.Type(TSK_DATETIME),
			new BlackboardAttribute.Type(TSK_PROG_NAME));

	TimelineEventType PROGRAM_NOTIFICATION = new TimelineEventArtifactTypeSingleDescription(50,
			getBundle().getString("TimelineEventType.ProgramNotification.txt"),//NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_PROG_NOTIFICATIONS),
			new BlackboardAttribute.Type(TSK_DATETIME),
			new BlackboardAttribute.Type(TSK_PROG_NAME));
	
	TimelineEventType SCREEN_SHOT = new TimelineEventArtifactTypeSingleDescription(51,
			getBundle().getString("TimelineEventType.ScreenShot.txt"),//NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_SCREEN_SHOTS),
			new BlackboardAttribute.Type(TSK_DATETIME),
			new BlackboardAttribute.Type(TSK_PROG_NAME));
		
	TimelineEventType SERVICE_ACCOUNT = new TimelineEventArtifactTypeImpl(52,
			getBundle().getString("TimelineEventType.ServiceAccount.txt"),// NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_SERVICE_ACCOUNT),
			new BlackboardAttribute.Type(TSK_DATETIME_CREATED),
			artf -> {
				String progName = stringValueOf(getAttributeSafe(artf, new Type(TSK_PROG_NAME)));
				String userId = stringValueOf(getAttributeSafe(artf, new Type(TSK_USER_ID)));
				return String.format("Program Name: %s User ID: %s", progName, userId);
			},
			new EmptyExtractor(),
			new EmptyExtractor());
	
	TimelineEventType USER_DEVICE_EVENT_START = new TimelineEventArtifactTypeImpl(53,
			getBundle().getString("TimelineEventType.UserDeviceEventStart.txt"),// NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_USER_DEVICE_EVENT),
			new BlackboardAttribute.Type(TSK_DATETIME_START),
			artf -> {
				String progName = stringValueOf(getAttributeSafe(artf, new Type(TSK_PROG_NAME)));
				String activityType = stringValueOf(getAttributeSafe(artf, new Type(TSK_ACTIVITY_TYPE)));
				String connectionType = stringValueOf(getAttributeSafe(artf, new Type(TSK_VALUE)));
				return String.format("Program Name: %s Activity Type: %s Connection Type: %s", progName, activityType, connectionType);
			},
			new EmptyExtractor(),
			new EmptyExtractor());
	
	TimelineEventType USER_DEVICE_EVENT_END = new TimelineEventArtifactTypeImpl(54,
			getBundle().getString("TimelineEventType.UserDeviceEventEnd.txt"),// NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_USER_DEVICE_EVENT),
			new BlackboardAttribute.Type(TSK_DATETIME_END),
			artf -> {
				String progName = stringValueOf(getAttributeSafe(artf, new Type(TSK_PROG_NAME)));
				String activityType = stringValueOf(getAttributeSafe(artf, new Type(TSK_ACTIVITY_TYPE)));
				String connectionType = stringValueOf(getAttributeSafe(artf, new Type(TSK_VALUE)));
				return String.format("Program Name: %s Activity Type: %s Connection Type: %s", progName, activityType, connectionType);
			},
			new EmptyExtractor(),
			new EmptyExtractor());
	
	TimelineEventType WEB_CACHE = new URLArtifactEventType(55,
			getBundle().getString("TimelineEventType.WebCache.text"),// NON-NLS
			WEB_ACTIVITY,
			new BlackboardArtifact.Type(TSK_WEB_CACHE),
			new Type(TSK_DATETIME_CREATED),
			new Type(TSK_URL));
	
	TimelineEventType WIFI_NETWORK = new TimelineEventArtifactTypeSingleDescription(56,
			getBundle().getString("TimelineEventType.WIFINetwork.txt"),//NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_WIFI_NETWORK),
			new BlackboardAttribute.Type(TSK_DATETIME),
			new BlackboardAttribute.Type(TSK_SSID));
	
	TimelineEventType WEB_HISTORY_CREATED = new URLArtifactEventType(57,
			getBundle().getString("WebTypes.webHistoryCreated.name"),// NON-NLS
			WEB_ACTIVITY,
			new BlackboardArtifact.Type(TSK_WEB_HISTORY),
			new Type(TSK_DATETIME_CREATED),
			new Type(TSK_URL));
	
	TimelineEventType BLUETOOTH_ADAPTER = new TimelineEventArtifactTypeSingleDescription(58,
			getBundle().getString("TimelineEventType.BluetoothAdapter.txt"),//NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_BLUETOOTH_ADAPTER),
			new BlackboardAttribute.Type(TSK_DATETIME),
			new BlackboardAttribute.Type(TSK_NAME));
	
	TimelineEventType BLUETOOTH_PAIRING_ACCESSED = new TimelineEventArtifactTypeSingleDescription(59,
			getBundle().getString("TimelineEventType.BluetoothPairingLastConnection.txt"),//NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_BLUETOOTH_PAIRING),
			new BlackboardAttribute.Type(TSK_DATETIME_ACCESSED),
			new BlackboardAttribute.Type(TSK_DEVICE_NAME));
	
	//User manually created events, created with the "Add Event" button in the 
	// timeline UI.
	TimelineEventType USER_CREATED = new TimelineEventArtifactTypeSingleDescription(60,
			getBundle().getString("CustomTypes.userCreated.name"),//NON-NLS
			MISC_TYPES,
			new BlackboardArtifact.Type(TSK_TL_EVENT),
			new BlackboardAttribute.Type(TSK_DATETIME),
			new BlackboardAttribute.Type(TSK_DESCRIPTION));

	static SortedSet<? extends TimelineEventType> getCategoryTypes() {
		return ROOT_EVENT_TYPE.getChildren();
	}

	static SortedSet<? extends TimelineEventType> getFileSystemTypes() {
		return FILE_SYSTEM.getChildren();
	}

	static SortedSet<? extends TimelineEventType> getWebActivityTypes() {
		return WEB_ACTIVITY.getChildren();
	}

	static SortedSet<? extends TimelineEventType> getMiscTypes() {
		return MISC_TYPES.getChildren();
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
