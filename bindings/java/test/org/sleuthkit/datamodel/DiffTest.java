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

import java.io.FileFilter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.junit.rules.TemporaryFolder;
import static org.junit.Assert.*;

/**
 * Tests the DataModel by printing 
 * @author pmartel
 */
@RunWith(Parameterized.class)
public class DiffTest {
	
	static final String TEST_IMAGE_DIR_NAME = "testimages";
	

	@Rule
	public TemporaryFolder testFolder = new TemporaryFolder();
	private List<String> imagePaths;

	
	public DiffTest(List<String> imagePaths) {
		this.imagePaths = imagePaths;
	}
	/**
	 * Gets the paths to the test image files by looking for a test image
	 * directory above the local SVN trunk/branch.
	 * @return A list of lists of paths to image parts
	 */
	static List<List<String>> getImagePaths() {
		FileFilter imageDirFilter = new FileFilter() {
			@Override
			public boolean accept(java.io.File f) {
				return f.isDirectory() && f.getName().equalsIgnoreCase(TEST_IMAGE_DIR_NAME);
			}
		};
		
		
		// needs to be absolute file because we're going to walk up its path
		java.io.File dir = (new java.io.File(".")).getAbsoluteFile();
		dir = dir.getParentFile().getParentFile().getParentFile().getParentFile();
		
		// image dir is either one level above trunk/ or in tags/
		if (dir.listFiles(imageDirFilter).length == 1) {
			// above trunk/
			dir = dir.listFiles(imageDirFilter)[0];
		} else {
			// in tags/, go up one more level
			dir = dir.getParentFile().listFiles(imageDirFilter)[0];
		}
		
		List<List<String>> images = new ArrayList<List<String>>();
		for (java.io.File imageSet : dir.listFiles()) {
			List<String> absolutePaths = new ArrayList();
			for (String filename : imageSet.list()) {
				absolutePaths.add(imageSet.getAbsolutePath() + java.io.File.separator + filename);
			}
			
			images.add(absolutePaths);
		}
		return images;
	}
	/**
	 * Get the sets of filenames for each test image
	 * @return A Collection of one-element Object arrays, where that one element
	 * is a List<String> containing the image file paths (the type is weird
	 * because that's what JUnit wants for parameters).
	 */
	@Parameters
	public static Collection<Object[]> testImageData() {
		Collection<Object[]> data = new ArrayList<Object[]>();
		
		for (Object imagePaths : getImagePaths()) {
			data.add(new Object[]{imagePaths});
		}
		return data;
	}

	/**
	 * Get the path for a standard corresponding to the given image path.
	 * @param imagePaths path of the image to get a standard for
	 * @return path to put/find the standard at
	 */
	static String standardPath(List<String> imagePaths) {
		java.io.File firstImage = new java.io.File(imagePaths.get(0));
		String standardPath = "teststandards" + java.io.File.separator + firstImage.getName().split("\\.")[0] + "_standard.txt";
		return standardPath;
	}

	
	@Test
	public void testDataModelDiff() {
		try {
			java.io.File testStandard = testFolder.newFile("test_standard.txt");

			String testStandardPath = testStandard.getPath();
			String oldStandardPath = standardPath(imagePaths);

			DiffUtil.createStandard(testStandardPath, testFolder.getRoot().getPath(), imagePaths);
			String diff = DiffUtil.getDiff(oldStandardPath, testStandardPath);

			assertEquals("Generated results ("+testStandardPath+") differ with gold standard ("+oldStandardPath+") .", "", diff);
		} catch (IOException ex) {
			fail("Couldn't open gold standard file.");
		}
	}
}
