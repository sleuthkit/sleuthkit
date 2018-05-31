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

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import org.sleuthkit.datamodel.TimelineManager;

/**
 * Intersection (And) filter
 *
 * @param <S> The type of sub Filters in this IntersectionFilter.
 */
class IntersectionFilter<S extends TimelineFilter> extends CompoundFilter<S> {
	
	IntersectionFilter(List<S> subFilters) {
		super(subFilters);
	}
	
	IntersectionFilter() {
		super(Collections.emptyList());
	}
	
	@Override
	public IntersectionFilter<S> copyOf() {
		@SuppressWarnings("unchecked")
		IntersectionFilter<S> filter = new IntersectionFilter<>(
				(List<S>) this.getSubFilters().stream()
						.map(TimelineFilter::copyOf)
						.collect(Collectors.toList()));
		return filter;
	}
	
	@Override
	public String getDisplayName() {
		String collect = getSubFilters().stream()
				.map(TimelineFilter::getDisplayName)
				.collect(Collectors.joining(",", "[", "]"));
		return BundleUtils.getBundle().getString("IntersectionFilter.displayName.text") + collect;
	}
	
	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		@SuppressWarnings("unchecked")
		final IntersectionFilter<S> other = (IntersectionFilter<S>) obj;
		
		for (int i = 0; i < getSubFilters().size(); i++) {
			if (getSubFilters().get(i).equals(other.getSubFilters().get(i)) == false) {
				return false;
			}
		}
		return true;
	}
	
	@Override
	public String getSQLWhere(TimelineManager manager) {
		String join = this.getSubFilters().stream()
				.filter(Objects::nonNull)
				.map(filter -> filter.getSQLWhere(manager))
				.filter( sql -> sql.equals("1") ==false)
				.collect(Collectors.joining(" AND "));
		
		return join.isEmpty()
				? manager.getTrueLiteral()
				: "(" + join + ")";
	}
}
