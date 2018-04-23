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

import java.util.Optional;
import java.util.SortedSet;

/**
 *
 */
abstract class AbstractEventType implements EventType {

	@Override
	public SortedSet<? extends EventType> getSubTypes() {
		throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
	}

	@Override
	public Optional<? extends EventType> getSubType(String string) {
		throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
	}

	private final int id;
	private final String displayName;

	private final EventType superType;
	private final EventTypeZoomLevel eventTypeZoomLevel;

	AbstractEventType(int id, String displayName, EventTypeZoomLevel eventTypeZoomLevel, EventType superType) {
		this.superType = superType;
		this.id = id;
		this.displayName = displayName;
		this.eventTypeZoomLevel = eventTypeZoomLevel;
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
}
