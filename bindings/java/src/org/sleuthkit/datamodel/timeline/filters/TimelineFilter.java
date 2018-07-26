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

import java.util.Arrays;
import java.util.List;
import org.sleuthkit.datamodel.timeline.TimelineManager;

/**
 * Interface for timeline event filters. Filters are given to the
 * TimelineManager who interpretes them appropriately for all db queries. Since
 * the filters are primarily configured in the UI, this interface provides
 * selected, disabled and active (selected and not disabled) properties.
 */
public interface TimelineFilter {

	/**
	 * Get a filter that is the intersection of the given filters
	 *
	 * @param filters a set of filters to intersect
	 *
	 * @return a filter that is the intersection of the given filters
	 */
	static TimelineFilter intersect(List<TimelineFilter> filters) {
		return new IntersectionFilter<>(filters);
	}

	/**
	 * Get a filter that is the intersection of the given filters
	 *
	 * @param filters a set of filters to intersect
	 *
	 * @return a filter that is the intersection of the given filters
	 */
	static TimelineFilter intersect(TimelineFilter[] filters) {
		return intersect(Arrays.asList(filters));
	}

	/**
	 * get the display name of this filter
	 *
	 * @return a name for this filter to show in the UI
	 */
	String getDisplayName();

	/**
	 * Get the SQL where clause corresponding to this filter.
	 *
	 * @param manager The TimelineManager to use for DB spevific parts of the
	 *                query.
	 *
	 * @return an SQL where clause (without the "where") corresponding to this
	 *         filter
	 */
	String getSQLWhere(TimelineManager manager);

	TimelineFilter copyOf();
}
