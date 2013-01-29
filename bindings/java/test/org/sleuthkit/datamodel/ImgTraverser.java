/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.datamodel;

import java.util.ArrayList;
import java.util.List;

/**
 * A basic implementation of traverser, has a standard test that allows for easy modification of the way tests are run
 */
public abstract class ImgTraverser implements Traverser
{
	protected List<String> imagePaths;
	protected String exFile;
	protected String testStandardPath;
	protected String oldStandardPath;
	protected String oldExceptionsPath;
	
	public List<Boolean> basicTest(){
		String title = DataModelTestSuite.getImgName(imagePaths.get(0));
		java.io.File testFolder=new java.io.File(DataModelTestSuite.getRsltPath());
		java.io.File testStandard = new java.io.File(DataModelTestSuite.buildPath(testFolder.getAbsolutePath(), title, this.getClass().getSimpleName(), ".txt"));
		testStandardPath = testStandard.getPath();
		exFile = testStandardPath.replace(".txt", DataModelTestSuite.EX+".txt");
		oldStandardPath = DataModelTestSuite.standardPath(imagePaths, this.getClass().getSimpleName());
		DataModelTestSuite.createStandard(testStandardPath, testFolder.getAbsolutePath(), imagePaths, this, exFile);
		oldExceptionsPath = oldStandardPath.replace(".txt", DataModelTestSuite.EX+".txt");
		List<Boolean> ret = new ArrayList<>(2);
		ret.add(DataModelTestSuite.comparecontent(oldExceptionsPath, exFile));
		ret.add(DataModelTestSuite.comparecontent(oldStandardPath, testStandardPath));
		return ret;
	}
	public List<Boolean> sortedTest()
	{
		basicTest();
		List<Boolean> ret = new ArrayList<>(1);
		ret.add(DataModelTestSuite.comparecontent(DataModelTestSuite.sortedFlPth(oldStandardPath), DataModelTestSuite.sortedFlPth(testStandardPath)));
		return ret;
	}
}
