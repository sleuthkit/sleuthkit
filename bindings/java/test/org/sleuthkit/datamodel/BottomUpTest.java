/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.datamodel;

import java.io.FileWriter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Scanner;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * @author smoss
 */
@RunWith(Parameterized.class)
public class BottomUpTest {
		

	private List<String> imagePaths;

	
	public BottomUpTest(List<String> imagePaths) {
		this.imagePaths = imagePaths;
	}
	/**
	 * Get the sets of filenames for each test image, they should be located in 
	 * the folder specified by the 
	 * @return A Collection of one-element Object arrays, where that one element
	 * is a List<String> containing the image file paths (the type is weird
	 * because that's what JUnit wants for parameters).
	 */
	@Parameterized.Parameters
	public static Collection<Object[]> testImageData() {
		Collection<Object[]> data = new ArrayList<Object[]>();
		
		for (Object imagePaths : DiffUtil.getImagePaths()) {
			data.add(new Object[]{imagePaths});
		}
		return data;
	}
	
	@Test
	public void testBottomUpDiff() {
		try{
			String title = imagePaths.get(0);
			title = title.substring(title.lastIndexOf(java.io.File.separator)+1);
			title = title.replace(".001", "").replace(".img","").replace(".dd", "").replace(".E01", "").replace(".raw", "");
			java.io.File dbFile=new java.io.File(System.getProperty(DiffUtil.RSLT, "test"+java.io.File.separator+"Output"+java.io.File.separator+"Results"));
			title = title.replace(".001", "").replace(".img","").replace(".dd", "").replace(".E01", "").replace(".raw", "");
			String tempDirPath= dbFile.getAbsolutePath();
			String dbPath = tempDirPath + java.io.File.separator + title + "_BU" + ".db";
			System.out.println(dbPath);
			dbFile.delete();
			SleuthkitCase sk = SleuthkitCase.newCase(dbPath);
			String timezone = "";
			title = title + ".txt";
			SleuthkitJNI.CaseDbHandle.AddImageProcess process = sk.makeAddImageProcess(timezone, true, false);
			try{
				process.run(imagePaths.toArray(new String[imagePaths.size()]));
			}catch (TskDataException ex){
			}
			process.commit();
			java.io.File lvs = new java.io.File(dbFile.getAbsolutePath()+java.io.File.separator+title.replace(".txt", DiffUtil.LVS+".txt"));
			System.out.println(lvs.toString());
			Scanner climber = new Scanner(lvs);
			while(climber.hasNextLine())
			{
				String cliNL = climber.nextLine();
				cliNL = cliNL.substring(1);
				String[] ids = cliNL.split("[\\],]\\s?+");
				Content c = sk.getContentById(Integer.parseInt(ids[0]));
				for(int x = 0; x<ids.length; x++)
				{
					assertEquals("Got ID " + c.getId() + " should have gotten ID " + ids[x], ids[x].equals(((Long)c.getId()).toString()), true);
					c = c.getParent();
				}
			}
		} catch (Exception ex)
		{
			System.out.println(ex.toString());
			fail("Failed to run BottomUp test");
		}
	}
}
