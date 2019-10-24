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

import com.google.common.collect.ImmutableSortedSet;
import java.util.Optional;
import java.util.SortedSet;
import org.apache.commons.lang3.ObjectUtils;

/**
 * Implementation of TimelineEventType for the standard predefined event types.
 */
class TimelineEventTypeImpl implements TimelineEventType {

	private final long typeID;
	private final String displayName;
	private final TimelineEventType superType;
	private final TimelineEventType.HierarchyLevel eventTypeZoomLevel;

	/**
	 *
	 * @param typeID             ID (from the Database)
	 * @param displayName
	 * @param eventTypeZoomLevel Where it is in the type hierarchy
	 * @param superType
	 */
	TimelineEventTypeImpl(long typeID, String displayName, TimelineEventType.HierarchyLevel eventTypeZoomLevel, TimelineEventType superType) {
		this.superType = superType;
		this.typeID = typeID;
		this.displayName = displayName;
		this.eventTypeZoomLevel = eventTypeZoomLevel;
	}

	TimelineEventDescription parseDescription(String fullDescriptionRaw, String medDescriptionRaw, String shortDescriptionRaw) {
		// The standard/default implementation:  Just bundle the three description levels into one object.
		return new TimelineEventDescription(fullDescriptionRaw, medDescriptionRaw, shortDescriptionRaw);
	}

	@Override
	public SortedSet<? extends TimelineEventType> getChildren() {
		return ImmutableSortedSet.of();
	}

	@Override
	public Optional<? extends TimelineEventType> getChild(String string) {
		return getChildren().stream()
				.filter(type -> type.getDisplayName().equalsIgnoreCase(displayName))
				.findFirst();
	}

	@Override
	public String getDisplayName() {
		return displayName;
	}

	@Override
	public TimelineEventType getParent() {
		return ObjectUtils.defaultIfNull(superType, ROOT_EVENT_TYPE);

	}

	@Override
	public TimelineEventType.HierarchyLevel getTypeHierarchyLevel() {
		return eventTypeZoomLevel;
	}

	@Override
	public long getTypeID() {
		return typeID;
	}

	@Override
	public int hashCode() {
		int hash = 5;
		hash = 17 * hash + (int) (this.typeID ^ (this.typeID >>> 32));
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
		final TimelineEventType other = (TimelineEventType) obj;
		return this.getTypeID() == other.getTypeID();
	}

	@Override
	public String toString() {
		return "StandardEventType{" + "id=" + getTypeID() + ", displayName=" + getDisplayName() + '}';
	}
}
