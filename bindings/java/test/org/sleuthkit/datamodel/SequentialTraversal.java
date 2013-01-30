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
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * Traverses an image by running through item Ids ascending.
 */
@RunWith(Parameterized.class)
public class SequentialTraversal extends ImgTraverser{
	
	public SequentialTraversal(List<String> imagePaths) {
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
		Collection<Object[]> data = new ArrayList<>();
		
		for (Object imagePaths : DataModelTestSuite.getImagePaths()) {
			data.add(new Object[]{imagePaths});
		}
		return data;
	}

	
	@Test
	public void testSequentialDiff() {
		try {
			List<Boolean> test = basicTest();
			assertEquals("Generated results ("+exFile+") differ with gold standard ("+oldExceptionsPath+") .", test.get(0),true);
			assertEquals("Generated results ("+testStandardPath+") differ with gold standard ("+oldStandardPath+") .", test.get(1),true);
		} catch (Exception ex) {
			fail("Couldn't open gold standard file.");
		}
	}
		/**
	 * Creates a sequential representation of a database
	 * @param lc a list of content to be read
	 * @param lp that lc's list of parents in most recent first order
	 */
	@Override
	public FileWriter traverse(SleuthkitCase sk, String path, String exFile){
		FileWriter reslt;
		try {
			reslt = new FileWriter(path);
			int x = 1;
			Content c;
			try {
				while ((c = sk.getContentById(x))!=null)
				{
					reslt.append(((AbstractContent)c).toString(false));
					if(c instanceof File)
					{
						DataModelTestSuite.readContent(c, reslt, exFile);
					}
					reslt.append("\n");
					x++;
				}
			} catch (TskCoreException ex) {
				DataModelTestSuite.writeExceptions(exFile, ex);
			}
			return reslt;
		} catch (IOException ex) {
			DataModelTestSuite.writeExceptions(exFile, ex);
			return null;
		}
	}
}
