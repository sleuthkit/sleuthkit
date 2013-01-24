/*
 * Sleuth Kit Data Model
 *
 * Copyright 2011 Basis Technology Corp.
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
package org.sleuthkit.datamodel;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;
/**
 *
 * Runs all regression tests.
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({org.sleuthkit.datamodel.TopDownTraversal.class,org.sleuthkit.datamodel.BottomUpTest.class,org.sleuthkit.datamodel.SequentialTest.class,org.sleuthkit.datamodel.CrossCompare.class})
public class DataModelTestSuite {
	@BeforeClass
	public static void setUpClass() throws Exception{
		java.io.File results = new java.io.File(System.getProperty(DiffUtil.RSLT,"test"+java.io.File.separator+"Output"+java.io.File.separator+"Results"));
		for(java.io.File del: results.listFiles())
		{
			del.delete();
		}
	}
	@AfterClass
	public static void tearDownClass() throws Exception {
	}
}
