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
package org.sleuthkit.datamodel;

import java.util.Collections;
import java.util.Optional;
import java.util.SortedSet;
import org.sleuthkit.datamodel.timeline.EventType;
import org.sleuthkit.datamodel.timeline.EventTypeZoomLevel;

/**
 * Implementation of custom, user defined EventTypes
 *
 */
final class CustomEventType implements EventType {

	private final String displayName;
	private final long typeID;

	CustomEventType(long typeID, String displayName) {
		this.displayName = displayName;
		this.typeID = typeID;
	}

	@Override
	public String getDisplayName() {
		return displayName;
	}

	@Override
	public long getTypeID() {
		return typeID;
	}

	@Override
	public EventTypeZoomLevel getZoomLevel() {
		return EventTypeZoomLevel.BASE_TYPE;
	}

	@Override
	public SortedSet<? extends EventType> getSubTypes() {
		return Collections.emptySortedSet();
	}

	@Override
	public Optional<? extends EventType> getSubType(String string) {
		return Optional.empty();
	}

	@Override
	public EventType getSuperType() {
		return ROOT_EVEN_TYPE;
	}
}
