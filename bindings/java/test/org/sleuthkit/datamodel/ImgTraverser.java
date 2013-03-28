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

/**
 * A basic implementation of traverser, has a standard test that allows for easy
 * modification of the way tests are run
 */
public abstract class ImgTraverser{

	protected List<String> imagePaths;
	protected String exFile;
	protected String testStandardPath;
	protected String oldStandardPath;
	protected String oldExceptionsPath;
	protected String testName;

	/**
	 * sets up the variables for a basic test, method can be called for any
	 * traversal test
	 *
	 * @return
	 */
	public List<Boolean> basicTest() {
		String title = DataModelTestSuite.getImgName(imagePaths.get(0));
		java.io.File testFolder = new java.io.File(DataModelTestSuite.getRsltPath());
		java.io.File testStandard = new java.io.File(DataModelTestSuite.buildPath(testFolder.getAbsolutePath(), title, this.testName, ".txt"));
		testStandardPath = testStandard.getPath();
		exFile = testStandardPath.replace(".txt", DataModelTestSuite.EX + ".txt");
		oldStandardPath = DataModelTestSuite.standardPath(imagePaths, this.testName);
		DataModelTestSuite.createStandard(testStandardPath, testFolder.getAbsolutePath(), imagePaths, this);
		oldExceptionsPath = oldStandardPath.replace(".txt", DataModelTestSuite.EX + ".txt");
		List<Boolean> ret = new ArrayList<Boolean>(2);
		ret.add(DataModelTestSuite.comparecontent(oldExceptionsPath, exFile));
		ret.add(DataModelTestSuite.comparecontent(oldStandardPath, testStandardPath));
		return ret;
	}
	abstract public OutputStreamWriter traverse(SleuthkitCase sk, String path);
}
