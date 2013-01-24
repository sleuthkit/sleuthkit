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
import org.junit.runners.Parameterized.Parameters;

/**
 *
 * Verifies that the current version of TSK produces the same output of previous versions by doing a TopDown Depth first traversal of the given images.
 */
@RunWith(Parameterized.class)
public class TopDownTraversal implements  ImgTraverser{
		

	private List<String> imagePaths;
	private String exFile;

	
	public TopDownTraversal(List<String> imagePaths) {
		this.imagePaths = imagePaths;
	}
	/**
	 * Get the sets of filenames for each test image, they should be located in 
	 * the folder specified by the build.xml
	 * @return A Collection of one-element Object arrays, where that one element
	 * is a List<String> containing the image file paths (the type is weird
	 * because that's what JUnit wants for parameters).
	 */
	@Parameters
	public static Collection<Object[]> testImageData() {
		Collection<Object[]> data = new ArrayList<Object[]>();
		
		for (Object imagePaths : DataModelTestSuite.getImagePaths()) {
			data.add(new Object[]{imagePaths});
		}
		return data;
	}

	
	@Test
	public void testTopDownDiff() {
		try {
			String title = DataModelTestSuite.getImgName(imagePaths.get(0));
			java.io.File testFolder=new java.io.File(DataModelTestSuite.getRsltPath());
			java.io.File testStandard = new java.io.File(DataModelTestSuite.buildPath(testFolder.getAbsolutePath(), title, this.getClass().getSimpleName(), ".txt"));
			String testStandardPath = testStandard.getPath();
			this.exFile = testStandardPath.replace(".txt", DataModelTestSuite.EX+".txt");
			String oldStandardPath = DataModelTestSuite.standardPath(imagePaths, this.getClass().getSimpleName());
			DataModelTestSuite.createStandard(testStandardPath, testFolder.getAbsolutePath(), imagePaths, this, exFile);
			String oldExceptionsPath = oldStandardPath.replace(".txt", DataModelTestSuite.EX+".txt");
			assertEquals("Generated results ("+exFile+") differ with gold standard ("+oldExceptionsPath+") .", DiffUtil.comparecontent(oldExceptionsPath, exFile),true);
			assertEquals("Generated results ("+testStandardPath+") differ with gold standard ("+oldStandardPath+") .", DiffUtil.comparecontent(oldStandardPath, testStandardPath),true);
		} catch (Exception ex) {
			fail("Couldn't open gold standard file.");
		}
	}
	/**
	 * Entry point to represent a Content object and it's children, sets up the 
	 * topDownDF method
	 * @param c the root Content object
	 */
	public void traverse(SleuthkitCase sk, String path, String exFile) {
		List<Content> lc=null;
		try {
			lc = sk.getRootObjects();
		} catch (TskCoreException ex) {
			DataModelTestSuite.writeExceptions(exFile, ex);
		}
		List<Long> lp=new ArrayList<Long>();
		try {
			FileWriter reslt = new FileWriter(path);
			FileWriter levs = new FileWriter(path.replace("_" + this.getClass().getSimpleName() + ".txt", DataModelTestSuite.LVS+".txt"));
			topDownDF(lc,lp, exFile, reslt, levs);
			reslt.flush();
			levs.flush();
		} catch (IOException ex) {
			DataModelTestSuite.writeExceptions(exFile, ex);
		}
	}
	/**
	 * Creates a top down representation of a database
	 * @param lc a list of content to be read
	 * @param lp that lc's list of parents in most recent first order
	 */
	private void topDownDF(List<Content> lc, List<Long> lp, String exFile, Appendable reslt, Appendable levs)
	{
			for(Content c : lc) {
				try {
					reslt.append(((AbstractContent)c).toString(false));
				} catch (IOException ex) {
					DataModelTestSuite.writeExceptions(exFile, ex);
				}
				if(c instanceof File)
				{
					DataModelTestSuite.readContent(c, reslt, exFile);
				}
				try {
					reslt.append("\n");
				} catch (IOException ex) {
					DataModelTestSuite.writeExceptions(exFile, ex);
				}
				lp.add(0,c.getId());
				try {
					if (c.getChildren().isEmpty())
					{
						levs.append(lp.toString() + "\n");
					}
					else
					{
						topDownDF(c.getChildren(),new ArrayList<Long>(lp), exFile, reslt, levs);
					}
				} catch (IOException ex) {
					DataModelTestSuite.writeExceptions(exFile, ex);
				} catch (TskCoreException ex) {
					DataModelTestSuite.writeExceptions(exFile, ex);
				}
				lp.remove(0);
			}
	}
}