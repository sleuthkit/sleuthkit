/*
 * Sleuth Kit Data Model
 *
 * Copyright 2013 Basis Technology Corp.
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

import java.io.OutputStreamWriter;
import java.util.ArrayList;
import java.util.List;
import static org.junit.Assert.*;

/**
 * A basic implementation of traverser, has a standard test that allows for easy
 * modification of the way tests are run
 */
public abstract class ImgTraverser {

	protected List<String> imagePaths;
	protected String outputFilePath;	// where output of current test is being stored
	protected String outputExceptionsPath; // exceptions of current test
	protected String goldFilePath;	// gold paths for test and exception data
	protected String goldExceptionsPath;
	protected String testName;

	/**
	 * Run a test and compare the unsorted results.
	 *
	 * @return List of test results. Entry 0 is exceptions and 1 is for content.
	 * True if test passed.
	 */
	public List<Boolean> basicTest() {
		// get paths to store output of test and exceptions
		java.io.File outputFolder = new java.io.File(DataModelTestSuite.getRsltDirPath());
		java.io.File outputFile = new java.io.File(DataModelTestSuite.resultFilePath(imagePaths, this.testName));
		outputFile.delete();

		outputFilePath = outputFile.getPath();
		outputExceptionsPath = DataModelTestSuite.exceptionPath(outputFilePath);
		goldFilePath = DataModelTestSuite.standardFilePath(imagePaths, this.testName);
		goldExceptionsPath = DataModelTestSuite.exceptionPath(goldFilePath);

		// Generate the sorted and unsorted output needed for the test
		DataModelTestSuite.createOutput(outputFilePath, outputFolder.getAbsolutePath(), imagePaths, this);

		// verify there is output
		assertTrue("Output file is zero sized (" + outputFilePath + ")", outputFile.length() > 0);

		// compare the unsorted results
		List<Boolean> ret = new ArrayList<Boolean>(2);
		ret.add(DataModelTestSuite.comparecontent(goldExceptionsPath, outputExceptionsPath));
		ret.add(DataModelTestSuite.comparecontent(goldFilePath, outputFilePath));
		return ret;
	}

	abstract public OutputStreamWriter traverse(SleuthkitCase sk, String path);
}
