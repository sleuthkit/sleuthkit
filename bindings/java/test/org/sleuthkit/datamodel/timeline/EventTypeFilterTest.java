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
 */package org.sleuthkit.datamodel.timeline;

import static java.util.Objects.isNull;
import static org.junit.Assert.*;
import org.junit.Test;
import org.sleuthkit.datamodel.TimelineEventType;
import org.sleuthkit.datamodel.TimelineFilter.EventTypesFilter;

/**
 * Test class for EventTypeFilter
 */
public class EventTypeFilterTest {

	/**
	 * Test of getEventType method, of class EventTypeFilter.
	 */
	@Test
	public void testGetEventType() {
		System.out.println("getEventType");
		EventTypesFilter instance = new EventTypesFilter(TimelineEventType.ROOT_EVENT_TYPE);
		assertEquals(TimelineEventType.ROOT_EVENT_TYPE, instance.getRootEventType());
		instance = new EventTypesFilter(TimelineEventType.FILE_SYSTEM);
		assertEquals(TimelineEventType.FILE_SYSTEM, instance.getRootEventType());
		instance = new EventTypesFilter(TimelineEventType.MESSAGE);
		assertEquals(TimelineEventType.MESSAGE, instance.getRootEventType());
	}

	/**
	 * Test of getDisplayName method, of class EventTypeFilter.
	 */
	@Test
	public void testGetDisplayName() {
		System.out.println("getDisplayName");
		EventTypesFilter instance = new EventTypesFilter(TimelineEventType.EMAIL);
		assertEquals(TimelineEventType.EMAIL.getDisplayName(), instance.getDisplayName());
		instance = new EventTypesFilter(TimelineEventType.ROOT_EVENT_TYPE);
		assertEquals("Event Type", instance.getDisplayName());
	}

	/**
	 * Test of copyOf method, of class EventTypeFilter.
	 */
	@Test
	public void testCopyOf() {
		System.out.println("copyOf");

		EventTypesFilter instance = new EventTypesFilter(TimelineEventType.EMAIL);
		EventTypesFilter result = instance.copyOf();
		assertEquals(instance, result);
		assertNotSame(instance, result);

		instance = new EventTypesFilter(TimelineEventType.MISC_TYPES);
		result = instance.copyOf();
		assertEquals(instance, result);
		assertNotSame(instance, result);

		instance = new EventTypesFilter(TimelineEventType.ROOT_EVENT_TYPE);
		result = instance.copyOf();
		assertEquals(instance, result);
		assertNotSame(instance, result);

	}

	/**
	 * Test of equals method, of class EventTypeFilter.
	 */
	@Test
	public void testEquals() {
		System.out.println("equals");
		EventTypesFilter root = new EventTypesFilter(TimelineEventType.ROOT_EVENT_TYPE);
		EventTypesFilter root2 = new EventTypesFilter(TimelineEventType.ROOT_EVENT_TYPE);

		assertFalse(isNull(root));
		assertTrue(root.equals(root));
		assertTrue(root.equals(root2));
		assertTrue(root2.equals(root));

		EventTypesFilter fileSystem = new EventTypesFilter(TimelineEventType.FILE_SYSTEM);
		assertTrue(fileSystem.equals(fileSystem));
		assertFalse(root.equals(fileSystem));
		assertFalse(fileSystem.equals(root2));

		EventTypesFilter exif = new EventTypesFilter(TimelineEventType.EXIF);
		EventTypesFilter deviceAttached = new EventTypesFilter(TimelineEventType.DEVICES_ATTACHED);
		assertTrue(exif.equals(exif));
		assertTrue(deviceAttached.equals(deviceAttached));
		assertFalse(root.equals(exif));
		assertFalse(root2.equals(exif));
		assertFalse(fileSystem.equals(exif));
		assertFalse(fileSystem.equals(deviceAttached));
		assertFalse(exif.equals(deviceAttached));
	}

}
