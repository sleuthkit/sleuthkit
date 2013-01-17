/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.datamodel;

import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import org.junit.AfterClass;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.BeforeClass;
/**
 *
 * @author smoss
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({org.sleuthkit.datamodel.TopDownTraversal.class})
public class DatamodeltestSuite {
	@BeforeClass
	public static void setUpClass() throws Exception{
		java.io.File results = new java.io.File("test"+java.io.File.separator+"Output"+java.io.File.separator+"Results");
		for(java.io.File del: results.listFiles())
		{
			del.delete();
		}
	}
	@AfterClass
	public static void tearDownClass() throws Exception {
	}
}
