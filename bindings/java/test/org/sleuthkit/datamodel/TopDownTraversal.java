/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.datamodel;

import java.io.FileFilter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Scanner;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.junit.rules.TemporaryFolder;
import static org.junit.Assert.*;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Ignore;

/**
 *
 * @author smoss
 */
@RunWith(Parameterized.class)
public class TopDownTraversal {
		

	private List<String> imagePaths;

	
	public TopDownTraversal(List<String> imagePaths) {
		this.imagePaths = imagePaths;
	}
	/**
	 * Get the sets of filenames for each test image, they should be located in 
	 * the folder specified by the 
	 * @return A Collection of one-element Object arrays, where that one element
	 * is a List<String> containing the image file paths (the type is weird
	 * because that's what JUnit wants for parameters).
	 */
	@Parameters
	public static Collection<Object[]> testImageData() {
		Collection<Object[]> data = new ArrayList<Object[]>();
		
		for (Object imagePaths : DiffUtil.getImagePaths()) {
			data.add(new Object[]{imagePaths});
		}
		return data;
	}

	
	@Test
	public void testTopDownDiff() {
		try {
			String title = (new java.io.File(imagePaths.get(0))).getName();
			java.io.File testFolder=new java.io.File(System.getProperty(DiffUtil.RSLT, "test"+java.io.File.separator+"Output"+java.io.File.separator+"Results"));
			String out = title.replace(".001", "").replace(".img","").replace(".dd", "").replace(".E01", "").replace(".raw", "");
			java.io.File testStandard = new java.io.File(testFolder.getAbsolutePath()+java.io.File.separator+out+DiffUtil.TD+".txt");
			String testStandardPath = testStandard.getPath();
			String oldStandardPath = DiffUtil.standardPath(imagePaths, DiffUtil.TD);
			DiffUtil.createStandard(testStandardPath, testFolder.getAbsolutePath(), imagePaths, DiffUtil.TD);
			String testExceptionsPath = testStandardPath.replace(".txt", DiffUtil.EX+".txt");
			String oldExceptionsPath = oldStandardPath.replace(".txt", DiffUtil.EX+".txt");
			assertEquals("Generated results ("+testExceptionsPath+") differ with gold standard ("+oldExceptionsPath+") .", DiffUtil.comparecontent(oldExceptionsPath, testExceptionsPath),true);
			assertEquals("Generated results ("+testStandardPath+") differ with gold standard ("+oldStandardPath+") .", DiffUtil.comparecontent(oldStandardPath, testStandardPath),true);
		} catch (Exception ex) {
			fail("Couldn't open gold standard file.");
		}
	}
	
	@Ignore @Test
	public void testBottomUpDiff() {
		try{
			String title = (new java.io.File(imagePaths.get(0))).getName();
			java.io.File testFolder=new java.io.File(System.getProperty(DiffUtil.RSLT, "test"+java.io.File.separator+"Output"+java.io.File.separator+"Results"));
			String out = title.replace(".001", "").replace(".img","").replace(".dd", "").replace(".E01", "").replace(".raw", "");
			java.io.File standardFile = new java.io.File(testFolder.getAbsolutePath()+java.io.File.separator+out+DiffUtil.TD+".txt");
			String tempDirPath= testFolder.getAbsolutePath();
			java.io.File tempDir = new java.io.File(tempDirPath);
			String dbPath = tempDir.getPath() + java.io.File.separator + title + "_BU" + ".db";
			java.io.File dbFile = new java.io.File(dbPath);
			dbFile.delete();
			SleuthkitCase sk = SleuthkitCase.newCase(dbPath);
			String timezone = "";
			SleuthkitJNI.CaseDbHandle.AddImageProcess process = sk.makeAddImageProcess(timezone, true, false);
			java.io.File exfile = new java.io.File(standardFile.toString().replace(".txt",DiffUtil.EX+".txt"));
			exfile.createNewFile();
			try{
				process.run(imagePaths.toArray(new String[imagePaths.size()]));
			}catch (TskDataException ex){
				FileWriter exwriter=new FileWriter(exfile);
				exwriter.append(ex.toString());
				exwriter.flush();
				exwriter.close();
			}
			java.io.File lvs = new java.io.File(testFolder.getAbsolutePath()+java.io.File.separator+title.replace(".txt", DiffUtil.LVS+".txt"));
			Scanner climber = new Scanner(lvs);
			Content c = sk.getRootObjects().get(0);
			String split = ",[ ]";
			while(climber.hasNextLine())
			{
				
			}
		} catch (Exception ex)
		{
			fail("Failed to run BottomUp test");
		}
	}
}