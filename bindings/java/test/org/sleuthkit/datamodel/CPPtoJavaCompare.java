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

import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * Compares the Java test output to the C++ test output
 */
@RunWith(Parameterized.class)
public class CPPtoJavaCompare extends ImgTraverser {
	private static final Logger logg = Logger.getLogger(CPPtoJavaCompare.class.getName());
	public CPPtoJavaCompare(List<String> imagePaths) {
		this.imagePaths = imagePaths;
	}
	/**
	 * Get the sets of filenames for each test image
	 * @return A Collection of one-element Object arrays, where that one element
	 * is a List<String> containing the image file paths (the type is weird
	 * because that's what JUnit wants for parameters).
	 */
	@Parameterized.Parameters
	public static Collection<Object[]> testImageData() {
		Collection<Object[]> data = new ArrayList<>();
		
		for (Object imagePaths : DataModelTestSuite.getImagePaths()) {
			data.add(new Object[]{imagePaths});
		}
		return data;
	}

	/**
	 * Runs the test
	 */
	@Test
	public void CPPtoJavaCompare() {
		try {
			List<Boolean> test = basicTest();
			assertEquals("Generated results ("+oldStandardPath +") differ with gold standard ("+testStandardPath+") .", test.get(0),true);
		} catch (Exception ex) {
			fail("Couldn't open gold standard file.");
		}
	}
	/**
	 * Extends basicTest to compare the sorted files and not the output files
	 */
	@Override
	public List<Boolean> basicTest()
	{
		super.basicTest();
		oldStandardPath = DataModelTestSuite.sortedFlPth(oldStandardPath);
		testStandardPath = DataModelTestSuite.sortedFlPth(testStandardPath);
		List<Boolean> ret = new ArrayList<>(1);
		ret.add(DataModelTestSuite.comparecontent(oldStandardPath,testStandardPath));
		return ret;
	}
	/**
	 * Traverses through an image and generates a TSK gettimes like representation
	 * @param sk the sleuthkit case used for the traversal
	 * @param path the location of the output file
	 * @return the file writer to be closed by testStandard
	 */
	@Override
	public FileWriter traverse(SleuthkitCase sk, String path){
		FileWriter reslt;
		try {
			reslt = new FileWriter(path);
			try {
				tskTraverse(sk.getRootObjects(), reslt);
					return reslt;
			} catch (TskCoreException ex) {
				DataModelTestSuite.writeExceptions(testStandardPath, ex);
			}
		} catch (IOException ex) {
			logg.log(Level.SEVERE, "Failed to Traverse", ex);
		}
		return null;
	}
	/**
	 * Traverses through an image and generates a TSK gettimes like representation
	 * @param lc the list of content to be traversed
	 * @param reslt the filewriter to append output to
	 */
	private void tskTraverse(List<Content> lc, Appendable reslt){
		for(Content c : lc) {
			try {
				if(c instanceof FsContent){
					try {
						reslt.append(DataModelTestSuite.getFsCData((FsContent) c));
						reslt.append("\n");
					} catch (IOException ex) {
						logg.log(Level.SEVERE, "Failed to Traverse", ex);
					}
				}
				tskTraverse(c.getChildren(), reslt);
			} catch (TskCoreException ex) {
				DataModelTestSuite.writeExceptions(testStandardPath, ex);
			}
		}
	}
}
