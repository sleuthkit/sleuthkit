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

/**
 *
 * Traverses an image by running through item Ids ascending.
 */
@RunWith(Parameterized.class)
public class SequentialTraversal extends ImgTraverser {

	private static final Logger logg = Logger.getLogger(SequentialTraversal.class.getName());

	public SequentialTraversal(List<String> imagePaths) {
		testName = DataModelTestSuite.SEQ;
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
	 * Runs the test
	 */
	@Test
	public void testSequentialDiff() {
		try {
			List<Boolean> test = basicTest();
			assertEquals("Generated results (" + exFile + ") differ with gold standard (" + oldExceptionsPath + ") .", test.get(0), true);
			assertEquals("Generated results (" + testStandardPath + ") differ with gold standard (" + oldStandardPath + ") .", test.get(1), true);
		} catch (Exception ex) {
			fail("Couldn't open gold standard file.");
		}
	}

	/**
	 * Traverses through an image and generates a sequential representation of
	 * the image
	 *
	 * @param sk the sleuthkit case used for the traversal
	 * @param path the location of the output file
	 * @param exFile the exFile to store exceptions, is only used for
	 * compatability with basic test
	 * @return the file writer to be closed by testStandard
	 */
	@Override
	public OutputStreamWriter traverse(SleuthkitCase sk, String path) {
		List<Exception> inp = new ArrayList<Exception>();
		try {
			Charset chr = Charset.forName("UTF-8");
			OutputStreamWriter reslt = new OutputStreamWriter(new BufferedOutputStream(new FileOutputStream(path), 8192*4), chr);
			int x = 1;
			Content c;
			try {
				while ((c = sk.getContentById(x)) != null) {
					reslt.append(((AbstractContent) c).toString(false).replaceAll("paths \\[([A-z]:)?.+?\\]", ""));
					if (c instanceof File) {
						DataModelTestSuite.readContent(c, reslt, exFile);
					}
					reslt.append("\n");
					x++;
				}
			} catch (TskCoreException ex) {
				inp.add(ex);
			}
			DataModelTestSuite.writeExceptions(path, inp);
			return reslt;
		} catch (IOException ex) {
			logg.log(Level.SEVERE, "Failed to Traverse", ex);
			return null;
		}
	}
}
