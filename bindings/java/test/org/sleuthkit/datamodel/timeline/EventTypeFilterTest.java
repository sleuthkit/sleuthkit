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

import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.sleuthkit.datamodel.timeline.TimelineFilter.EventTypeFilter;

/**
 * Test class for EventTypeFilter
 */
public class EventTypeFilterTest {

	public EventTypeFilterTest() {
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

	// @Test
	public void testDisplayName() {

	}

	/**
	 * Test of getEventType method, of class EventTypeFilter.
	 */
	@Test
	public void testGetEventType() {
		System.out.println("getEventType");
		EventTypeFilter instance = new EventTypeFilter(EventType.ROOT_EVENT_TYPE);
		assertEquals(EventType.ROOT_EVENT_TYPE, instance.getEventType());
		instance = new EventTypeFilter(EventType.FILE_SYSTEM);
		assertEquals(EventType.FILE_SYSTEM, instance.getEventType());
		instance = new EventTypeFilter(EventType.MESSAGE);
		assertEquals(EventType.MESSAGE, instance.getEventType());
	}

	/**
	 * Test of getDisplayName method, of class EventTypeFilter.
	 */
	@Test
	public void testGetDisplayName() {
		System.out.println("getDisplayName");
		EventTypeFilter instance = new EventTypeFilter(EventType.EMAIL);
		assertEquals(EventType.EMAIL.getDisplayName(), instance.getDisplayName());
		instance = new EventTypeFilter(EventType.ROOT_EVENT_TYPE);
		assertEquals("Event Type", instance.getDisplayName());
	}

	/**
	 * Test of copyOf method, of class EventTypeFilter.
	 */
	@Test
	public void testCopyOf() {
		System.out.println("copyOf");

		EventTypeFilter instance = new EventTypeFilter(EventType.EMAIL);
		EventTypeFilter result = instance.copyOf();
		assertEquals(instance, result);
		assertNotSame(instance, result);

		instance = new EventTypeFilter(EventType.MISC_TYPES);
		result = instance.copyOf();
		assertEquals(instance, result);
		assertNotSame(instance, result);

		instance = new EventTypeFilter(EventType.ROOT_EVENT_TYPE);
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
		EventTypeFilter root = new EventTypeFilter(EventType.ROOT_EVENT_TYPE);
		EventTypeFilter root2 = new EventTypeFilter(EventType.ROOT_EVENT_TYPE);

		assertFalse(root.equals(null));
		assertTrue(root.equals(root));
		assertTrue(root.equals(root2));
		assertTrue(root2.equals(root));

		EventTypeFilter fileSystem = new EventTypeFilter(EventType.FILE_SYSTEM);
		assertTrue(fileSystem.equals(fileSystem));
		assertFalse(root.equals(fileSystem));
		assertFalse(fileSystem.equals(root2));

		EventTypeFilter exif = new EventTypeFilter(EventType.EXIF);
		EventTypeFilter deviceAttached = new EventTypeFilter(EventType.DEVICES_ATTACHED);
		assertTrue(exif.equals(exif));
		assertTrue(deviceAttached.equals(deviceAttached));
		assertFalse(root.equals(exif));
		assertFalse(root2.equals(exif));
		assertFalse(fileSystem.equals(exif));
		assertFalse(fileSystem.equals(deviceAttached));
		assertFalse(exif.equals(deviceAttached));
	}

}
