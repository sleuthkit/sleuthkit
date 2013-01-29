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
 * @author smoss
 */
@RunWith(Parameterized.class)
public class CPPtoJavaCompare extends ImgTraverser {
			
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

	
	@Test
	public void CPPtoJavaCompare() {
		try {
			List<Boolean> test = basicTest();
			assertEquals("Generated results ("+testStandardPath+") differ with gold standard ("+oldStandardPath+") .", test.get(1),true);
		} catch (Exception ex) {
			fail("Couldn't open gold standard file.");
		}
	}
	@Override
	public FileWriter traverse(SleuthkitCase sk, String path, String exFile)
	{
		FileWriter reslt;
		try {
			reslt = new FileWriter(path);
			try {
				topDownDF(sk.getRootObjects(), reslt, exFile);
					return reslt;
			} catch (TskCoreException ex) {
				Logger.getLogger(CPPtoJavaCompare.class.getName()).log(Level.SEVERE, null, ex);
			}
		} catch (IOException ex) {
			Logger.getLogger(CPPtoJavaCompare.class.getName()).log(Level.SEVERE, null, ex);
		}
		return null;
	}
	public void topDownDF(List<Content> lc, Appendable reslt, String exFile){
		for(Content c : lc) {
			try {
				if(c instanceof File)
				{
					try {
						reslt.append(DataModelTestSuite.getFileData((File) c));
					} catch (IOException ex) {
						Logger.getLogger(CPPtoJavaCompare.class.getName()).log(Level.SEVERE, null, ex);
					}
				}
				topDownDF(c.getChildren(), reslt, exFile);
			} catch (TskCoreException ex) {
				DataModelTestSuite.writeExceptions(exFile, ex);
			}
		}
	}
}
