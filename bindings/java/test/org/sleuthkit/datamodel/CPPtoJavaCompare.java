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
import java.util.Scanner;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * @author smoss
 */
@RunWith(Parameterized.class)
public class CPPtoJavaCompare {
		

	private List<String> imagePaths;
	private String TD;
	
	public CPPtoJavaCompare(List<String> imagePaths, String TD) {
		this.imagePaths = imagePaths;
		this.TD = TD;
	}
	/**
	 * Get the sets of filenames for each test image
	 * @return A Collection of one-element Object arrays, where that one element
	 * is a List<String> containing the image file paths (the type is weird
	 * because that's what JUnit wants for parameters).
	 */
	@Parameterized.Parameters
	public static Collection<Object[]> testImageData() {
		Collection<Object[]> data = new ArrayList<Object[]>();
		
		for (Object imagePaths : DataModelTestSuite.getImagePaths()) {
			data.add(new Object[]{imagePaths, "_TD"});
		}
		return data;
	}

	
	//@Ignore@Test
	public void CrossCompare() {
		try {
			String title = (new java.io.File(imagePaths.get(0))).getName();
			java.io.File testFolder=new java.io.File(System.getProperty(DataModelTestSuite.RSLT, "test"+java.io.File.separator+"Output"+java.io.File.separator+"Results"));
			title = DataModelTestSuite.stripExtension(title);
			java.io.File testStandard1 = new java.io.File(testFolder.getAbsolutePath()+java.io.File.separator+title+"_CPP.txt");
			java.io.File testStandard2 = new java.io.File(testFolder.getAbsolutePath()+java.io.File.separator+title+TD+".txt");
			String testStandardPath1 = testStandard1.getPath();
			String testStandardPath2 = testStandard2.getPath();
			Scanner read1 = new Scanner(testStandard1);
			DataModelTestSuite.getTSKData(testStandardPath1, imagePaths);
			Scanner read2 = new Scanner(testStandard2);
			while(read1.hasNextLine()||read2.hasNextLine())
			{
				//assertEquals("CPP results (" + testStandardPath1 + ") differ from ("+testStandardPath2") .",,true);
			}
		} catch (Exception ex) {
			fail("Couldn't open gold standard file.");
		}
	}
	
}
