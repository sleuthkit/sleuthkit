/*
 * Sleuth Kit Data Model
 *
 * Copyright 2019 Basis Technology Corp.
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

import java.util.Collections;
import java.util.List;
import static org.junit.Assert.*;
import org.junit.Test;
import org.sleuthkit.datamodel.PublicTagName;
import org.sleuthkit.datamodel.TagName;
import org.sleuthkit.datamodel.TimelineFilter;
import org.sleuthkit.datamodel.TimelineFilter.EventTypeFilter;
import org.sleuthkit.datamodel.TimelineEventType;
import org.sleuthkit.datamodel.TskData;

/**
 * Test class for RootFilter
 */
public class RootFilterTest {

	/**
	 * Test of copyOf method, of class TimelineFilter.
	 */
	@Test
	public void testCopyOf() {
		System.out.println("copyOf");
		
		testCopyOfEqual(new TimelineFilter.TagsFilter());
		testCopyOfEqual(new TimelineFilter.HashHitsFilter());
		testCopyOfEqual(new TimelineFilter.TextFilter());
		testCopyOfEqual(new EventTypeFilter(TimelineEventType.ROOT_EVENT_TYPE));
		testCopyOfEqual(new TimelineFilter.DataSourcesFilter());
		testCopyOfEqual(new TimelineFilter.HideKnownFilter());
		testCopyOfEqual(new TimelineFilter.FileTypesFilter());
		
		testCopyOfEqual(getNewRootFilter());
	}
	
	private void testCopyOfEqual(TimelineFilter filter) {
		assertEquals(filter, filter.copyOf());
	}
	

	TimelineFilter.RootFilter getNewRootFilter() {
		TimelineFilter.TagsFilter tagsFilter = new TimelineFilter.TagsFilter();
		TimelineFilter.HashHitsFilter hashHitsFilter = new TimelineFilter.HashHitsFilter();
		TimelineFilter.TextFilter textFilter = new TimelineFilter.TextFilter();
		EventTypeFilter eventTypeFilter = new EventTypeFilter(TimelineEventType.ROOT_EVENT_TYPE);
		TimelineFilter.DataSourcesFilter dataSourcesFilter = new TimelineFilter.DataSourcesFilter();
		TimelineFilter.HideKnownFilter hideKnownFilter = new TimelineFilter.HideKnownFilter();
		TimelineFilter.FileTypesFilter fileTypesFilter = new TimelineFilter.FileTypesFilter();
		List<TimelineFilter> emptyList = Collections.emptyList();
		return new TimelineFilter.RootFilter(
				hideKnownFilter,
				tagsFilter,
				hashHitsFilter,
				textFilter,
				eventTypeFilter,
				dataSourcesFilter,
				fileTypesFilter,
				emptyList);

	}

}
