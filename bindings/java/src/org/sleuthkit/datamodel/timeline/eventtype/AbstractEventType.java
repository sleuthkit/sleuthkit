/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.datamodel.timeline.eventtype;

import com.google.common.collect.ImmutableSortedSet;
import java.util.Optional;
import java.util.SortedSet;
import org.sleuthkit.datamodel.timeline.EventTypeZoomLevel;

/**
 *
 */
abstract class AbstractEventType implements EventType {

	private final int id;
	private final String displayName;

	private final EventType superType;
	private final EventTypeZoomLevel eventTypeZoomLevel;
	private final SortedSet<? extends EventType> subTypes;

	AbstractEventType(int id, String displayName, EventTypeZoomLevel eventTypeZoomLevel, EventType superType, SortedSet<? extends EventType> subTypes) {
		this.superType = superType;
		this.id = id;
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
	public ImmutableSortedSet< EventType> getSubTypes() {
		return ImmutableSortedSet.copyOf(subTypes);
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

	@Override
	public int getTypeID() {
		return id;
	}
}
