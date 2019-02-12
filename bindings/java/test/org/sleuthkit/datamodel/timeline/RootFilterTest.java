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
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.sleuthkit.datamodel.PublicTagName;
import org.sleuthkit.datamodel.TagName;
import org.sleuthkit.datamodel.TskData;
import org.sleuthkit.datamodel.timeline.TimelineFilter.EventTypeFilter;

/**
 * Test class for RootFilter
 */
public class RootFilterTest {

	public RootFilterTest() {
	}

	@BeforeClass
	public static void setUpClass() {
	}

	@AfterClass
	public static void tearDownClass() {
	}

	@Before
	public void setUp() {
	}

	@After
	public void tearDown() {
	}

	/**
	 * Test of copyOf method, of class TimelineFilter.
	 */
	@Test
	public void testCopyOf() {
		System.out.println("copyOf");
		TimelineFilter instance = getInstance();
		assertEquals(instance, instance.copyOf());
	}

	TimelineFilter.RootFilter getInstance() {
		TimelineFilter.TagsFilter tagsFilter = new TimelineFilter.TagsFilter();
		tagsFilter.addSubFilter(new TimelineFilter.TagNameFilter(new PublicTagName(0, "test tagName", "test tag name description", TagName.HTML_COLOR.NONE, TskData.FileKnown.KNOWN)));
		TimelineFilter.HashHitsFilter hashHitsFilter = new TimelineFilter.HashHitsFilter();
		TimelineFilter.TextFilter textFilter = new TimelineFilter.TextFilter();
		EventTypeFilter eventTypeFilter = new EventTypeFilter(EventType.ROOT_EVENT_TYPE);
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
