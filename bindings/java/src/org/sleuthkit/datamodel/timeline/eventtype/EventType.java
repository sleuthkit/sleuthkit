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
package org.sleuthkit.datamodel.timeline.eventtype;

import java.util.Comparator;
import java.util.Optional;
import java.util.SortedSet;
import org.sleuthkit.datamodel.timeline.EventTypeZoomLevel;

/**
 * An Event Type represents a distinct kind of event ie file system or web
 * activity. An EventType may have an optional super-type and 0 or more
 * subtypes, allowing events to be organized in a type hierarchy.
 */
public interface EventType extends Comparable<EventType> {

	default BaseType getBaseType() {
		if (this instanceof BaseType) {
			return (BaseType) this;
		} else {
			return getSuperType().getBaseType();
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
}
