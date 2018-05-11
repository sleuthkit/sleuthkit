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
import org.apache.commons.lang3.ObjectUtils;

/**
 * Implementation of EventType for the standard predefined event types.
 */
class StandardEventType implements EventType {

	@Override
	public SortedSet<? extends EventType> getSubTypes() {
		return ImmutableSortedSet.of();
	}

	@Override
	public Optional<? extends EventType> getSubType(String string) {
		return getSubTypes().stream()
				.filter(type -> type.getDisplayName().equalsIgnoreCase(displayName))
				.findFirst();
	}

	private final int typeID;
	private final String displayName;

	private final EventType superType;
	private final EventTypeZoomLevel eventTypeZoomLevel;

	StandardEventType(int typeID, String displayName, EventTypeZoomLevel eventTypeZoomLevel, EventType superType) {
		this.superType = superType;
		this.typeID = typeID;
		this.displayName = displayName;
		this.eventTypeZoomLevel = eventTypeZoomLevel;
	}

	@Override
	public String getDisplayName() {
		return displayName;
	}

	@Override
	public EventType getSuperType() {
		return ObjectUtils.defaultIfNull(superType, ROOT_EVEN_TYPE);

	}

	@Override
	public EventTypeZoomLevel getZoomLevel() {
		return eventTypeZoomLevel;
	}

	@Override
	public int getTypeID() {
		return typeID;
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
