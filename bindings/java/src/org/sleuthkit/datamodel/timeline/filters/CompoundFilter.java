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

import java.util.List;
import java.util.Objects;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;

/**
 * A Filter with a collection of sub-filters. Concrete implementations can
 * decide how to combine the sub-filters.
 *
 * @param <SubFilterType> The type of the subfilters.
 */
 public abstract class CompoundFilter<SubFilterType extends TimelineFilter> implements TimelineFilter {

	/**
	 * The list of sub-filters that make up this filter
	 */
	private final ObservableList<SubFilterType> subFilters = FXCollections.observableArrayList();

	public final ObservableList<SubFilterType> getSubFilters() {
		return subFilters;
	}

	public boolean hasSubFilters() {
		return getSubFilters().isEmpty() == false;
	}

	/**
	 * construct a compound filter from a list of other filters to combine.
	 *
	 * @param subFilters
	 */
	public CompoundFilter(List<SubFilterType> subFilters) {
		super();
		this.subFilters.setAll(subFilters);
	}

	static boolean areSubFiltersEqual(final CompoundFilter<?> oneFilter, final CompoundFilter<?> otherFilter) {
		if (oneFilter.getSubFilters().size() != otherFilter.getSubFilters().size()) {
			return false;
		}
		for (int i = 0; i < oneFilter.getSubFilters().size(); i++) {
			TimelineFilter subFilter = oneFilter.getSubFilters().get(i);
			TimelineFilter otherSubFilter = otherFilter.getSubFilters().get(i);
			if (subFilter.equals(otherSubFilter) == false) {
				return false;
			}
		}
		return true;
	}

	@Override
	public abstract CompoundFilter<SubFilterType> copyOf();

	@Override
	public int hashCode() {
		int hash = 3;
		hash = 23 * hash + Objects.hashCode(this.subFilters);
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

		final CompoundFilter<?> other = (CompoundFilter<?>) obj;
		return areSubFiltersEqual(this, other);
	}
}
