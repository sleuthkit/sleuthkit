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

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import org.sleuthkit.datamodel.timeline.EventTypeZoomLevel;

/**
 * An Event Type represents a distinct kind of event ie file system or web
 * activity. An EventType may have an optional super-type and 0 or more
 * subtypes, allowing events to be organized in a type hierarchy.
 */
public interface EventType {

	final List<? extends EventType> allTypes = RootEventType.getInstance().getSubTypesRecusive();

	static Comparator<EventType> getComparator() {
		return Comparator.comparing(EventType.allTypes::indexOf);

	}

	default BaseType getBaseType() {
		if (this instanceof BaseType) {
			return (BaseType) this;
		} else {
			return getSuperType().getBaseType();
		}
	}

	default List<? extends EventType> getSubTypesRecusive() {
		ArrayList<EventType> flatList = new ArrayList<>();

		for (EventType et : getSubTypes()) {
			flatList.add(et);
			flatList.addAll(et.getSubTypesRecusive());
		}
		return flatList;
	}

	default List<? extends EventType> getSiblingTypes() {
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
	List<EventType> getSubTypes();

	String getDisplayName();

	Optional<? extends EventType> getSubType(String string);

	int getTypeID();

}
