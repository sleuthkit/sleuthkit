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

import java.io.FileFilter;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;
/**
 *
 * Runs all regression tests.
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({org.sleuthkit.datamodel.TopDownTraversal.class,org.sleuthkit.datamodel.BottomUpTest.class,org.sleuthkit.datamodel.SequentialTest.class,org.sleuthkit.datamodel.CrossCompare.class})
public class DataModelTestSuite {
	static final String TEST_IMAGE_DIR_NAME = "test" + java.io.File.separator + "Input";
	static final String INPT = "inpt";
	static final String GOLD = "gold";
	static final String RSLT = "rslt";
	static final String SEQ = "_Seq";
	static final String TD = "_TD";
	static final String LVS = "_Leaves";
	static final String EX = "_Exceptions";
	static final String BU = "_BU";
	@BeforeClass
	public static void setUpClass() throws Exception{
		java.io.File results = new java.io.File(System.getProperty(RSLT,"test"+java.io.File.separator+"Output"+java.io.File.separator+"Results"));
		for(java.io.File del: results.listFiles())
		{
			del.delete();
		}
	}
	/**
	 * Creates the Sleuth Kit database for an image, then generates a string
	 * representation of the given traversal type of the resulting database to use as a standard for
	 * comparison, and saves the the standard to a file.
	 * @param standardPath The path to save the standard file to (will be
	 * overwritten if it already exists)
	 * @param tempDirPath An existing directory to create the test database in
	 * @param imagePaths The path(s) to the image file(s)
	 * @param type The type of traversal to run.
	 */
	public static void createStandard(String standardPath, String tempDirPath, List<String> imagePaths, String type)
	{
		java.io.File standardFile = new java.io.File(standardPath);
		try {
			String firstImageFile = getImgName(imagePaths.get(0));
			String dbPath = buildPath(tempDirPath, firstImageFile, type, ".db");
			java.io.File dbFile = new java.io.File(dbPath);
			standardFile.createNewFile();
			FileWriter standardWriter = new FileWriter(standardFile);
			ReprDataModel repr = new ReprDataModel(standardWriter, standardFile.toString().replace(".txt",EX+".txt"));
			dbFile.delete();
			SleuthkitCase sk = SleuthkitCase.newCase(dbPath);
			String timezone = "";
			SleuthkitJNI.CaseDbHandle.AddImageProcess process = sk.makeAddImageProcess(timezone, true, false);
			java.io.File exfile = new java.io.File(standardFile.toString().replace(".txt",EX+".txt"));
			exfile.createNewFile();
			try{
				process.run(imagePaths.toArray(new String[imagePaths.size()]));
			}catch (TskDataException ex){
				writeExceptions(standardFile.toString(), ex);
			}
			process.commit();
			if(type.equals(SEQ))
			{
				repr.startSeq(sk);
			}
			else
			{
				try (
						FileWriter testWriter = new FileWriter(standardFile.toString().replace(type,LVS))) {
						repr.setLeaves(testWriter);
						repr.startTD(sk.getRootObjects());
						testWriter.flush();
				}
			}
			standardWriter.flush();
			standardWriter.close();
			String sortedloc = standardFile.getAbsolutePath().replace(".txt", "_Sorted.txt");
			String cygpath = getSortPath();
			String[] cmd={cygpath ,standardFile.getAbsolutePath(), "-o", sortedloc};
			Runtime.getRuntime().exec(cmd).waitFor();
		}catch (Exception ex) {
			Logger.getLogger(DiffUtil.class.getName()).log(Level.SEVERE, "Couldn't create Standard", ex);
			throw new RuntimeException(ex);
		}
	}
	/**
	 * Gets the paths to the test image files by looking for a test image
	 * directory above the local SVN trunk/branch.
	 * @return A list of lists of paths to image parts
	 */
	static List<List<String>> getImagePaths() {
		
		// needs to be absolute file because we're going to walk up its path
		java.io.File dir = new java.io.File(System.getProperty(INPT,TEST_IMAGE_DIR_NAME));
		
		FileFilter imageFilter = new FileFilter() {
			@Override
			public boolean accept(java.io.File f) {
				return f.getName().endsWith(".001")||f.getName().endsWith(".img")||f.getName().endsWith(".dd")||f.getName().endsWith(".E01")||f.getName().endsWith(".raw");
			}
		};
		List<List<String>> images = new ArrayList<List<String>>();
		for (java.io.File imageSet : dir.listFiles(imageFilter)) {
			ArrayList<String> imgs = new ArrayList<String>();
			imgs.add(imageSet.getAbsolutePath());
			images.add(imgs);
		}
		return images;
	}
	/**
	 * Get the path for a standard corresponding to the given image path.
	 * @param imagePaths path of the image to get a standard for
	 * @return path to put/find the standard at
	 */
	static String standardPath(List<String> imagePaths, String type) {
		String firstImage = getImgName(imagePaths.get(0));
		String standardPath = System.getProperty(GOLD, ("test" + java.io.File.separator + "output" + java.io.File.separator + "gold")) + java.io.File.separator + firstImage +type+".txt";
		return standardPath;
	}
	/**
	 * removes the files with the file name from the from the given path
	 * @param path the path to the folder where files are to be deleted
	 * @param filename the name of the files to be deleted
	 */
	public static void emptyResults(String path, String filename)
	{
		final String filt = filename.replace(TD, "").replace(".txt", "").replace(SEQ, "");
		FileFilter imageResFilter = new FileFilter() {
			@Override
			public boolean accept(java.io.File f) {
				return f.getName().contains(filt)&!f.getName().contains(LVS)&!f.getName().contains("Sorted");
			}
		};
		java.io.File pth = new java.io.File(path);
		for(java.io.File del: pth.listFiles(imageResFilter))
		{
			del.deleteOnExit();
		}
	}
	
	public static void getTSKData(String StandardPath, List<String> img)
	{
		String tsk_loc = null;
		if(System.getProperty("os.name").contains("Windows"))
		{
			tsk_loc = "C:\\Users\\" + System.getProperty("user.name") + "\\Documents\\GitHub\\sleuthkit\\win32\\Release\\tsk_gettimes";
		}
		else
		{
			return;
		}
		String cmd=tsk_loc + " " + img.get(0);
		try {
			Process p=Runtime.getRuntime().exec(cmd);
			//p.waitFor();
			Scanner read = new Scanner(p.getInputStream());
			Scanner error1 = new Scanner(p.getErrorStream());
			FileWriter out = new FileWriter(StandardPath);
			while(read.hasNextLine())
			{
				String line = read.nextLine();
				String[] lineContents = line.split("\\|");
				String[] nameget = lineContents[1].split("\\s\\(deleted\\)");
				String name = nameget[0];
				name = name.replace("/", "\\");
				String size = lineContents[6];
				String crea = lineContents[7];
				String acc = lineContents[8];
				String modif = lineContents[10];
				if(!line.contains("|d/d"))
				{
					out.append("(FilePath): " + name + " (Size): " + size + " (Creation Time): " + crea + " (Accessed Time): " + acc + " (Modified Time): " + modif);
					out.flush();
					if(read.hasNextLine())
					{
						out.append("\n");
					}
				}
			}
		} catch (Exception ex) {
			Logger.getLogger(DiffUtil.class.getName()).log(Level.SEVERE, "Failed to run CPP program", ex);
		}
	}
	public static String stripExtension(String title)
	{
		return title.replace(".001", "").replace(".img","").replace(".dd", "").replace(".E01", "").replace(".raw","");
	}
	public static String buildPath(String path, String name, String type, String Ext)
	{
		return path+java.io.File.separator+name+type+Ext;
	}
	public static String getImgName(String img)
	{
		String[] imgSp = img.split("\\\\");
		return stripExtension(imgSp[imgSp.length-1]);
	}
	public static String getRsltPath()
	{
		return System.getProperty(RSLT, "test"+java.io.File.separator+"output"+java.io.File.separator+"results");
	}
	public static String getSortPath()
	{
		if(!System.getProperty("os.name").contains("Windows"))
		{
			return "sort";
		}
		else
		{
			return "C:\\Users\\" + System.getProperty("user.name")+ "\\Cygwin\\bin\\sort.exe";
		}
	}
	public static void writeExceptions(String filename, Exception ex)
	{
		try {
			filename = filename.replace(".txt",EX+".txt");
			java.io.File exFile = new java.io.File(filename);
			Scanner read = new Scanner(exFile);
			List<String> con = new ArrayList<String>();
			while(read.hasNextLine())
			{
				con.add(read.nextLine());
			}
			read.close();
			FileWriter exWriter;
			try {
				exWriter = new FileWriter(exFile);
				for(String out: con)
				{
					exWriter.append(out+"\n");
				}
				exWriter.append(ex.toString());
				exWriter.flush();
				exWriter.close();
			}
			catch (IOException ex1) {
				Logger.getLogger(DiffUtil.class.getName()).log(Level.SEVERE, "Couldn't log Exception", ex1);
			}
		}
		catch (FileNotFoundException ex1) {
			Logger.getLogger(DiffUtil.class.getName()).log(Level.SEVERE, "Couldn't log Exception", ex1);
		}
	}
	public static String goldStandardPath()
	{
		return System.getProperty(GOLD, ("test" + java.io.File.separator + "output" + java.io.File.separator + "gold"));
	}
}
