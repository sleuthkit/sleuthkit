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
 * as a Top Down traversal. Does not use gold standard files. It compares the
 * outputs from the two test runs.
 */
@RunWith(Parameterized.class)
public class CrossCompare {

	private List<String> imagePaths;

	public CrossCompare(List<String> imagePaths) {
		this.imagePaths = imagePaths;
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
			data.add(new Object[]{imagePaths});
		}
		return data;
	}

	/**
	 * Compares the sorted results of the different traversals against each
	 * other
	 */
	@Test
	public void testCrossCompareDiff() {
		try {
			String seqSortedOutputFile = DataModelTestSuite.sortedFlPth(DataModelTestSuite.resultFilePath(imagePaths, DataModelTestSuite.SEQ));
			String tdSortedOutputFile = DataModelTestSuite.sortedFlPth(DataModelTestSuite.resultFilePath(imagePaths, DataModelTestSuite.TD));

			assertEquals("Sequential test results (" + seqSortedOutputFile + ") differ with Top Dow (" + tdSortedOutputFile + ") .", DataModelTestSuite.comparecontent(seqSortedOutputFile, tdSortedOutputFile), true);
		} catch (Exception ex) {
			fail("SequentialTest error: " + ex.getMessage());
		}
	}
}
