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

import com.google.common.collect.ImmutableSortedSet;
import java.util.Optional;
import java.util.SortedSet;
import static org.sleuthkit.datamodel.timeline.EventType.FILE_SYSTEM;
import static org.sleuthkit.datamodel.timeline.EventType.MISC_TYPES;
import static org.sleuthkit.datamodel.timeline.EventType.WEB_ACTIVITY;

/**
 *
 */
class StandardEventType implements EventType {

	static final ImmutableSortedSet<EventType> BASE_TYPES
			= ImmutableSortedSet.of(FILE_SYSTEM, WEB_ACTIVITY, MISC_TYPES);

	static final ImmutableSortedSet<EventType> FILE_SYSTEM_TYPES
			= ImmutableSortedSet.of(FILE_MODIFIED, FILE_ACCESSED, FILE_CREATED, FILE_CHANGED);

	static final ImmutableSortedSet<? extends ArtifactEventType> WEB_ACTIVITY_TYPES
			= ImmutableSortedSet.of(WEB_DOWNLOADS, WEB_COOKIE, WEB_BOOKMARK, WEB_HISTORY, WEB_SEARCH);

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

	@Override
	public SortedSet<? extends EventType> getSubTypes() {
		return subtypes;
	}

	@Override
	public Optional<? extends EventType> getSubType(String string) {
		return subtypes.stream()
				.filter(type -> type.getDisplayName().equalsIgnoreCase(displayName))
				.findFirst();
	}

	private final int id;
	private final String displayName;

	private final EventType superType;
	private final EventTypeZoomLevel eventTypeZoomLevel;
	private final SortedSet<? extends EventType> subtypes;

	StandardEventType(int id, String displayName, EventTypeZoomLevel eventTypeZoomLevel, EventType superType) {
		this(id, displayName, eventTypeZoomLevel, superType, ImmutableSortedSet.of());
	}

	StandardEventType(int id, String displayName, EventTypeZoomLevel eventTypeZoomLevel, EventType superType, SortedSet<? extends EventType> subtypes) {
		this.superType = superType;
		this.id = id;
		this.displayName = displayName;
		this.eventTypeZoomLevel = eventTypeZoomLevel;
		this.subtypes = subtypes;
	}

	@Override
	public String getDisplayName() {
		return displayName;
	}

	@Override
	public EventType getSuperType() {
		return superType;
	}

	@Override
	public EventTypeZoomLevel getZoomLevel() {
		return eventTypeZoomLevel;
	}

	@Override
	public int getTypeID() {
		return id;
	}

	@Override
	public int hashCode() {
		int hash = 5;
		hash = 79 * hash + this.getTypeID();
		return hash;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		final EventType other = (EventType) obj;
		return this.getTypeID() == other.getTypeID();
	}

	@Override
	public String toString() {
		return "StandardEventType{" + "id=" + getTypeID() + ", displayName=" + getDisplayName() + '}';
	}
}
