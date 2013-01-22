/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.datamodel;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;
/**
 *
 * @author smoss
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({org.sleuthkit.datamodel.TopDownTraversal.class,org.sleuthkit.datamodel.BottomUpTest.class,org.sleuthkit.datamodel.SequentialTest.class,org.sleuthkit.datamodel.CrossCompare.class})
public class DatamodeltestSuite {
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
