/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.datamodel.timeline.eventtype;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import org.sleuthkit.datamodel.timeline.EventTypeZoomLevel;

/**
 *
 */
abstract class AbstractEventType implements EventType {

	private final String displayName;

	private final EventType superType;
	private final EventTypeZoomLevel eventTypeZoomLevel;
	private final List<? extends EventType> subTypes;

	AbstractEventType(String displayName, EventTypeZoomLevel eventTypeZoomLevel, EventType superType, List<? extends EventType> subTypes) {
		this.superType = superType;
		this.displayName = displayName;
		this.eventTypeZoomLevel = eventTypeZoomLevel;
		this.subTypes = subTypes;
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
	public List< EventType> getSubTypes() {
		return Collections.unmodifiableList(subTypes);
	}

	@Override
	public EventTypeZoomLevel getZoomLevel() {
		return eventTypeZoomLevel;
	}

	@Override
	public Optional<? extends EventType> getSubType(String string) {
		return subTypes.stream().filter(type -> type.getDisplayName().equalsIgnoreCase(string))
				.findFirst();
	}
}
