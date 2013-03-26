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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * Ensures that a sequential traversal of a given image produces the same result
 * as a Top Down depth first traversal.
 */
@RunWith(Parameterized.class)
public class CrossCompare {

	private List<String> imagePaths;
	private String Seq, TD;

	public CrossCompare(List<String> imagePaths, String Seq, String TD) {
		this.imagePaths = imagePaths;
		this.Seq = Seq;
		this.TD = TD;
	}

	/**
	 * Get the sets of filenames for each test image, they should be located in
	 * the folder specified by the build.xml
	 *
	 * @return A Collection of one-element Object arrays, where that one element
	 * is a List<String> containing the image file paths (the type is weird
	 * because that's what JUnit wants for parameters).
	 */
	@Parameterized.Parameters
	public static Collection<Object[]> testImageData() {
		Collection<Object[]> data = new ArrayList<Object[]>();

		for (Object imagePaths : DataModelTestSuite.getImagePaths()) {
			data.add(new Object[]{imagePaths, DataModelTestSuite.SEQ, DataModelTestSuite.TD});
		}
		return data;
	}

	/**
	 * Compares the sorted results of the different traversals against each
	 * other
	 */
	@Test
	public void CrossCompare() {
		try {
			String title = DataModelTestSuite.getImgName(imagePaths.get(0));
			java.io.File testFolder = new java.io.File(DataModelTestSuite.getRsltPath());
			java.io.File testStandard1 = new java.io.File(DataModelTestSuite.buildPath(testFolder.getAbsolutePath(), title, Seq, "_SRT.txt"));
			java.io.File testStandard2 = new java.io.File(DataModelTestSuite.buildPath(testFolder.getAbsolutePath(), title, TD, "_SRT.txt"));
			String testStandardPath1 = testStandard1.getPath();
			String testStandardPath2 = testStandard2.getPath();
			assertEquals("Generated results (" + testStandardPath1 + ") differ with gold standard (" + testStandardPath2 + ") .", DataModelTestSuite.comparecontent(testStandardPath1, testStandardPath2), true);
		} catch (Exception ex) {
			fail("Couldn't open gold standard file.");
		}
	}
}
