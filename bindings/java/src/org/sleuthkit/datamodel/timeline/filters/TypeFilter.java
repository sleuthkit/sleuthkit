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
package org.sleuthkit.datamodel.timeline.filters;

import java.util.Comparator;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javafx.collections.FXCollections;
import org.sleuthkit.datamodel.timeline.TimelineManager;
import org.sleuthkit.datamodel.timeline.EventType;

/**
 * Event Type Filter. An instance of TypeFilter is usually a tree that parallels
 * the event type hierarchy with one filter/node for each event type.
 */
public class TypeFilter extends AbstractUnionFilter<TypeFilter> {

	static private final Comparator<TypeFilter> comparator = Comparator.comparing(TypeFilter::getEventType);

	/**
	 * the event type this filter passes
	 */
	private final EventType eventType;

	/**
	 * private constructor that enables non recursive/tree construction of the
	 * filter hierarchy for use in {@link TypeFilter#copyOf()}.
	 *
	 * @param et        the event type this filter passes
	 * @param recursive true if subfilters should be added for each subtype.
	 *                  False if no subfilters should be added.
	 */
	private TypeFilter(EventType et, boolean recursive) {
		super(FXCollections.observableArrayList());
		this.eventType = et;

		if (recursive) { // add subfilters for each subtype
			for (EventType subType : et.getSubTypes()) {
				addSubFilter(new TypeFilter(subType), comparator);
			}
		}
	}

	/**
	 * public constructor. creates a subfilter for each subtype of the given
	 * event type
	 *
	 * @param et the event type this filter will pass
	 */
	public TypeFilter(EventType et) {
		this(et, true);
	}

	public EventType getEventType() {
		return eventType;
	}

	@Override
	public String getDisplayName() {
		return (EventType.ROOT_EVEN_TYPE.equals(eventType))
				? BundleUtils.getBundle().getString("TypeFilter.displayName.text")
				: eventType.getDisplayName();
	}

	@Override
	public TypeFilter copyOf() {
		//make a nonrecursive copy of this filter
		final TypeFilter filterCopy = new TypeFilter(eventType, false);
		//add a copy of each subfilter
		getSubFilters().forEach(typeFilter -> filterCopy.addSubFilter(typeFilter.copyOf(), comparator));

		return filterCopy;
	}

	@Override
	public int hashCode() {
		int hash = 7;
		hash = 17 * hash + Objects.hashCode(this.eventType);
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
		final TypeFilter other = (TypeFilter) obj;
		if (!Objects.equals(this.eventType, other.eventType)) {
			return false;
		}
		return areSubFiltersEqual(this, other);
	}

	@Override
	public String getSQLWhere(TimelineManager manager) {
		return "(sub_type IN (" + getActiveSubTypeIDs().collect(Collectors.joining(",")) + "))"; //NON-NLS
	}

	private Stream<String> getActiveSubTypeIDs() {
		if (this.getSubFilters().isEmpty()) {
			return Stream.of(String.valueOf(getEventType().getTypeID()));
		} else {
			return this.getSubFilters().stream()
					.flatMap(TypeFilter::getActiveSubTypeIDs);
		}
	}
}
