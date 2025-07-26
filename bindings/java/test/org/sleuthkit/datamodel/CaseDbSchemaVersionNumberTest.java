/*
 * Sleuth Kit Data Model
 *
 * Copyright 2011-2017 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	 http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.datamodel;

import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class CaseDbSchemaVersionNumberTest {

	public CaseDbSchemaVersionNumberTest() {
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
	 * Test of isCompatible method, of class CaseDbSchemaVersionNumber.
	 */
	@Test
	public void testIsCompatible() {
		System.out.println("isCompatible");
		CaseDbSchemaVersionNumber instance = new CaseDbSchemaVersionNumber(7, 2);
		assertEquals(true, instance.isCompatible(new CaseDbSchemaVersionNumber(6, 1)));
		assertEquals(true, instance.isCompatible(new CaseDbSchemaVersionNumber(7, 16)));
		assertEquals(true, instance.isCompatible(new CaseDbSchemaVersionNumber(7, 1)));
		assertEquals(true, instance.isCompatible(new CaseDbSchemaVersionNumber(7, 2)));
		assertEquals(false, instance.isCompatible(new CaseDbSchemaVersionNumber(8, 1)));
		assertEquals(false, instance.isCompatible(new CaseDbSchemaVersionNumber(1, 1)));
	}

	/**
	 * Test of toString method, of class CaseDbSchemaVersionNumber.
	 */
	@Test
	public void testToString() {
		System.out.println("toString");
		assertEquals("7.1", new CaseDbSchemaVersionNumber(7, 1).toString());
		assertEquals("0.1", new CaseDbSchemaVersionNumber(0, 1).toString());
		assertEquals("7.0", new CaseDbSchemaVersionNumber(7, 0).toString());
		assertEquals("7000213.132130", new CaseDbSchemaVersionNumber(7000213, 132130).toString());
	}
	
}
