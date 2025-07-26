/*
 * Sleuth Kit Data Model
 *
 * Copyright 2013-2017 Basis Technology Corp.
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

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.Charset;
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
 * Verifies that the current version of TSK produces the same output of previous
 * versions by doing a TopDown Depth first traversal of the given images.
 * Compares data to gold standards. Also generates the leaf file that is used by
 * the BottomUp Test
 */
@RunWith(Parameterized.class)
public class TopDownTraversal extends ImgTraverser {

	private static final Logger logg = Logger.getLogger(TopDownTraversal.class.getName());

	public TopDownTraversal(List<String> imagePaths) {
		testName = DataModelTestSuite.TD;
		this.imagePaths = imagePaths;
	}

	/**
	 * Get the sets of filenames for each test image, they should be located in
	 * the folder specified by the build.xml
	 *
	 * @return A Collection of one-element Object arrays, where that one element
	 *         is a List<String> containing the image file paths (the type is
	 *         weird because that's what JUnit wants for parameters).
	 */
	@Parameters
	public static Collection<Object[]> testImageData() {
		Collection<Object[]> data = new ArrayList<Object[]>();

		for (Object imagePaths : DataModelTestSuite.getImagePaths()) {
			data.add(new Object[]{imagePaths});
		}
		return data;
	}

	/**
	 * Runs the test
	 */
	@Test
	public void testTopDownDiff() {
		try {
			List<Boolean> test = basicTest();
			assertEquals("Generated results (" + outputExceptionsPath + ") differ with gold standard (" + goldExceptionsPath + ") .", test.get(0), true);
			assertEquals("Generated results (" + outputFilePath + ") differ with gold standard (" + goldFilePath + ") .", test.get(1), true);
		} catch (Exception ex) {
			fail("Couldn't open gold standard file. " + ex.getMessage());
		}
	}

	/**
	 * Traverses through an image and generates a top down representation the
	 * image and generates the leaf files for BU Testing
	 *
	 * @param sk                   the sleuthkit case used for the traversal
	 * @param path                 the location of the output file
	 * @param outputExceptionsPath the outputExceptionsPath to store exceptions
	 *
	 * @return the file writer to be closed by testStandard
	 */
	@Override
	public OutputStreamWriter traverse(SleuthkitCase sk, String path) {
		List<Content> lc = null;
		try {
			lc = sk.getRootObjects();
		} catch (TskCoreException ex) {
			List<Exception> inp = new ArrayList<Exception>();
			inp.add(ex);
			DataModelTestSuite.writeExceptions(outputFilePath, inp);
		}
		List<Long> lp = new ArrayList<Long>();
		try {
			Charset chr = Charset.forName("UTF-8");
			// file to save the per-file info to.
			OutputStreamWriter reslt = new OutputStreamWriter(new BufferedOutputStream(new FileOutputStream(path), 8192 * 4), chr);

			// file to save the leaf into, which will be used by the BottomUp Test
			OutputStreamWriter levs = new OutputStreamWriter(new BufferedOutputStream(new FileOutputStream(path.replace(this.testName + ".txt", DataModelTestSuite.BTTMUP + ".txt")), 8192 * 4), chr);

			List<Exception> inp = topDownDF(lc, lp, reslt, levs);
			levs.flush();
			DataModelTestSuite.writeExceptions(path, inp);
			return reslt;
		} catch (IOException ex) {
			logg.log(Level.SEVERE, "Failed to Traverse", ex);
			return null;
		}
	}

	/**
	 * Traverses through an image and generates a TSK gettimes like
	 * representation
	 *
	 * @param lc             the list of content to be traversed
	 * @param lp             the list of a content's parents
	 * @param resultOutput   the filewriter to append output to
	 * @param leafListOutput the filewriter to append leaves to (trace of each
	 *                       leaf to root dir)
	 *
	 * @returns list of exceptions
	 */
	private List<Exception> topDownDF(List<Content> lc, List<Long> lp, Appendable resultOutput, Appendable leafListOutput) {
		List<Exception> exceptionList = new ArrayList<Exception>();
		for (Content c : lc) {

			// write data about this object to resultOutput
			// string version of this object
			if (c instanceof AbstractContent) {
				try {
					resultOutput.append(((AbstractContent) c).toString(false).replaceAll("paths \\[([A-z]:)?.+?\\]", ""));
				} catch (IOException ex) {
					logg.log(Level.SEVERE, "Failed to Traverse", ex);
				}

				// calculate the hash value for the output -- writes the output to resultOutput
				if (c instanceof File) {
					DataModelTestSuite.hashContent(c, resultOutput, outputFilePath);
				}
				try {
					resultOutput.append("\n");
				} catch (IOException ex) {
					logg.log(Level.SEVERE, "Failed to Traverse", ex);
				}

				// add this node to the bottom of the parent list
				lp.add(0, c.getId());

				try {
					// if we are a leaf, write out the path to the node
					List<Content> children = c.getChildren();
					if (children.isEmpty()) {
						leafListOutput.append(lp.toString() + "\n");
					} // recurse into the children
					else {
						exceptionList.addAll(topDownDF(children, new ArrayList<Long>(lp), resultOutput, leafListOutput));
					}
				} catch (IOException ex) {
					logg.log(Level.SEVERE, "Failed to Traverse", ex);
				} catch (TskCoreException ex) {
					exceptionList.add(ex);
				}
				// pop it off the list
				lp.remove(0);
			}
		}
		return exceptionList;
	}
}
