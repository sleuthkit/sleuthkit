/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
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
 * @author smoss
 */
@RunWith(Parameterized.class)
public class CrossCompare {
		

	private List<String> imagePaths;
	private String Seq , TD;
	
	public CrossCompare(List<String> imagePaths, String Seq, String TD) {
		this.imagePaths = imagePaths;
		this.Seq = Seq;
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
		
		for (Object imagePaths : DiffUtil.getImagePaths()) {
			data.add(new Object[]{imagePaths, "_Seq", "_TD"});
		}
		return data;
	}

	
	@Test
	public void CrossCompare() {
		try {
			String title = (new java.io.File(imagePaths.get(0))).getName();
			java.io.File testFolder=new java.io.File(System.getProperty(DiffUtil.RSLT, "test"+java.io.File.separator+"Output"+java.io.File.separator+"Results"));
			String out = title.replace(".001", "").replace(".img","").replace(".dd", "").replace(".E01", "").replace(".raw","");
			java.io.File testStandard1 = new java.io.File(testFolder.getAbsolutePath()+java.io.File.separator+out+Seq+"_sorted.txt");
			java.io.File testStandard2 = new java.io.File(testFolder.getAbsolutePath()+java.io.File.separator+out+TD+"_sorted.txt");
			String testStandardPath1 = testStandard1.getPath();
			String testStandardPath2 = testStandard2.getPath();
			assertEquals("Generated results ("+testStandardPath1+") differ with gold standard ("+testStandardPath2+") .", DiffUtil.comparecontent(testStandardPath1, testStandardPath2),true);
		} catch (Exception ex) {
			fail("Couldn't open gold standard file.");
		}
	}
	
}
