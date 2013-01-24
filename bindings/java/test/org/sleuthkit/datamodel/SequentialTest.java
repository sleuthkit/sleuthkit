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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * Traverses an image by running through item Ids ascending.
 */
@RunWith(Parameterized.class)
public class SequentialTest {
		

	private List<String> imagePaths;

	
	public SequentialTest(List<String> imagePaths) {
		this.imagePaths = imagePaths;
	}
	/**
	 * Get the sets of filenames for each test image, they should be located in 
	 * the folder specified by the build.xml
	 * @return A Collection of one-element Object arrays, where that one element
	 * is a List<String> containing the image file paths (the type is weird
	 * because that's what JUnit wants for parameters).
	 */
	@Parameterized.Parameters
	public static Collection<Object[]> testImageData() {
		Collection<Object[]> data = new ArrayList<Object[]>();
		
		for (Object imagePaths : DataModelTestSuite.getImagePaths()) {
			data.add(new Object[]{imagePaths});
		}
		return data;
	}

	
	@Test
	public void testSequentialDiff() {
		try {
			String title = DataModelTestSuite.getImgName(imagePaths.get(0));
			java.io.File testFolder=new java.io.File(DataModelTestSuite.getRsltPath());
			title = DataModelTestSuite.stripExtension(title);
			java.io.File testStandard = new java.io.File(DataModelTestSuite.buildPath(testFolder.getAbsolutePath(), title, DataModelTestSuite.SEQ, ".txt"));
			String testStandardPath = testStandard.getPath();
			String oldStandardPath = DataModelTestSuite.standardPath(imagePaths, DataModelTestSuite.SEQ);
			DataModelTestSuite.createStandard(testStandardPath, testFolder.getAbsolutePath(), imagePaths, DataModelTestSuite.SEQ);
			String testExceptionsPath = testStandardPath.replace(".txt", DataModelTestSuite.EX+".txt");
			String oldExceptionsPath = oldStandardPath.replace(".txt", DataModelTestSuite.EX+".txt");
			assertEquals("Generated results ("+testExceptionsPath+") differ with gold standard ("+oldExceptionsPath+") .", DiffUtil.comparecontent(oldExceptionsPath, testExceptionsPath),true);
			assertEquals("Generated results ("+testStandardPath+") differ with gold standard ("+oldStandardPath+") .", DiffUtil.comparecontent(oldStandardPath, testStandardPath),true);
		} catch (Exception ex) {
			fail("Couldn't open gold standard file.");
		}
	}
	
}
