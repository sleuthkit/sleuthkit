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

import difflib.Delta;
import difflib.DiffUtils;
import difflib.Patch;
import java.io.BufferedReader;
import java.io.FileFilter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.sleuthkit.datamodel.SleuthkitJNI.CaseDbHandle.AddImageProcess;

public class DiffUtil {
	static final String TEST_IMAGE_DIR_NAME = "test" + java.io.File.separator + "Input";
	static final String INPT = "inpt";
	static final String GOLD = "gold";
	static final String RSLT = "rslt";
	/**
	 * Creates the Sleuth Kit database for an image, generates a string
	 * representation of a top down depth first traversal of the resulting database to use as a standard for
	 * comparison, and saves the the standard to a file.
	 * @param standardPath The path to save the standard file to (will be
	 * overwritten if it already exists)
	 * @param tempDirPath An existing directory to create the test database in
	 * @param imagePaths The path(s) to the image file(s)
	 */
	public static void createStandardTopDown(String standardPath, String tempDirPath, List<String> imagePaths) {
		java.io.File standardFile = new java.io.File(standardPath);
		try {
			java.io.File firstImageFile = new java.io.File(imagePaths.get(0));
			java.io.File tempDir = new java.io.File(tempDirPath);
			String dbPath = tempDir.getPath() + java.io.File.separator + firstImageFile.getName() + "_TD.db";
			java.io.File dbFile = new java.io.File(dbPath);
			standardFile.createNewFile();

			FileWriter standardWriter = new FileWriter(standardFile);
			int len=(int) (standardFile.toString().length()-4);
			FileWriter testWriter = new FileWriter(standardFile.toString().replace("_TD.txt","_leaves.txt"));
			ReprDataModel repr = new ReprDataModel(standardWriter,testWriter);
			dbFile.delete();
			
			SleuthkitCase sk = SleuthkitCase.newCase(dbPath);
			
			String timezone = "";
			AddImageProcess process = sk.makeAddImageProcess(timezone, true, false);
			java.io.File exfile = new java.io.File(standardFile.toString().replace(".txt","_exceptions.txt"));
			exfile.createNewFile();
			try{
				process.run(imagePaths.toArray(new String[imagePaths.size()]));
			}catch (TskDataException ex){
				FileWriter exwriter=new FileWriter(exfile);
				exwriter.append(ex.toString());
				exwriter.flush();
			}

			process.commit();
			repr.start(sk.getRootObjects());
			standardWriter.flush();
			standardWriter.close();
			testWriter.flush();
			testWriter.close();
			String sortedloc = standardFile.getAbsolutePath().substring(0,standardFile.getAbsolutePath().length()-4)+"_sorted.txt";
			String[] cmd={"sort",standardFile.getAbsolutePath(),"/o",sortedloc};
			Runtime.getRuntime().exec(cmd);
		}catch (Exception ex) {
			System.err.println(ex.toString());
			throw new RuntimeException(ex);
		}
	}
		/**
		 * Creates the Sleuth Kit database for an image, generates a string
		 * representation of a top down traversal of the resulting database to use as a standard for
		 * comparison, and saves the the standard to a file.
		 * @param standardPath The path to save the standard file to (will be
		 * overwritten if it already exists)
		 * @param tempDirPath An existing directory to create the test database in
		 * @param imagePaths The path(s) to the image file(s)
		 */
		/*public static void createStandardTopDown(String standardPath, String tempDirPath, List<String> imagePaths) {
		java.io.File standardFile = new java.io.File(standardPath);
		try {
			java.io.File firstImageFile = new java.io.File(imagePaths.get(0));
			java.io.File tempDir = new java.io.File(tempDirPath);
			String dbPath = tempDir.getPath() + java.io.File.separator + firstImageFile.getName() + "_TD.db";
			java.io.File dbFile = new java.io.File(dbPath);

			standardFile.createNewFile();
			FileWriter standardWriter = new FileWriter(standardFile);
			int len=(int) (standardFile.toString().length()-4);
			FileWriter testWriter = new FileWriter(standardFile.toString().substring(0,len)+"_leaves.txt");
			ReprDataModel repr = new ReprDataModel(standardWriter,testWriter);

			dbFile.delete();
			
			SleuthkitCase sk = SleuthkitCase.newCase(dbPath);
			
			String timezone = "";
			AddImageProcess process = sk.makeAddImageProcess(timezone, true, false);
			process.run(imagePaths.toArray(new String[imagePaths.size()]));
			process.commit();
			repr.topDown(sk.getRootObjects());
			standardWriter.close();

		}catch (TskDataException ex){			
		}catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}*/
	/**
	 * Calls {@link #createStandard(String, String, String[]) createStandard}
	 * with default arguments
	 * @param args Ignored 
	 */
	public static void main(String[] args) {
		String tempDirPath = System.getProperty("java.io.tmpdir");
		List<List<String>> imagePaths = getImagePaths();
		for(List<String> paths : imagePaths) {
			String standardPath = standardPath(paths,"_TD");
			System.out.println("Creating standards for: " + paths.get(0));
			createStandardTopDown(standardPath, tempDirPath, paths);
		}
	}

	private static List<String> fileToLines(String filename) {
		List<String> lines = new LinkedList<String>();
		String line = "";
		try {
			BufferedReader in = new BufferedReader(new FileReader(new java.io.File(filename).getAbsolutePath()));
			while ((line = in.readLine()) != null) {
				lines.add(line);
			}
		} catch (IOException ex) {
			throw new RuntimeException(ex);
		}
		return lines;
	}

	protected static boolean comparecontent(String original, String results) {
		try {
			java.io.File fi1 = new java.io.File(original);
			java.io.File fi2 = new java.io.File(results);
			FileReader f1 = new FileReader(new java.io.File(original).getAbsolutePath());
			FileReader f2 = new FileReader (new java.io.File(results).getAbsolutePath());
			Scanner in = new Scanner(f1);
			Scanner in1 = new Scanner(f2);
			boolean ret=true;
			while (in.hasNextLine()||in1.hasNextLine()) {
				if(in.hasNextLine()^in1.hasNextLine())
				{
					in.close();
					in1.close();
					f1.close();
					f2.close();
					getDiff(fi1.getAbsolutePath(),fi2.getAbsolutePath(),original.substring(original.lastIndexOf(java.io.File.separator)+1));
					return false;
				}
				if(!(in.nextLine().equals(in1.nextLine())))
				{
					in.close();
					in1.close();
					f1.close();
					f2.close();
					getDiff(fi1.getAbsolutePath(),fi2.getAbsolutePath(),original.substring(original.lastIndexOf(java.io.File.separator)+1));
					return false;
				}
			}
			emptyResults(fi2.getParent(), fi2.getName());
			return ret;
		} catch (IOException ex) {
			throw new RuntimeException(ex);
		}
	}
	/**
	 * Returns the diff between the two given files
	 * @param pathOriginal The path to the original file
	 * @param pathRevised The path to the revised (new) file
	 * @return A representation of the diff
	 */
	public static String getDiff(String pathOriginal, String pathRevised, String title) {
		List<String> originalLines, revisedLines;	
		originalLines = fileToLines(pathOriginal);
		revisedLines = fileToLines(pathRevised);
		java.io.File outp = new java.io.File(System.getProperty(RSLT, "test"+java.io.File.separator+"Output"+java.io.File.separator+"Results") + java.io.File.separator + title.replace(".txt","")+"_Diff.txt");
		// Compute diff. Get the Patch object. Patch is the container for computed deltas.
		Patch patch = DiffUtils.diff(originalLines, revisedLines);
		StringBuilder diff = new StringBuilder();

		for (Delta delta : patch.getDeltas()) {
			diff.append(delta.toString());
			diff.append("\n");
		}
		try {
			FileWriter out = new FileWriter(outp);
			out.append(diff);
			out.flush();
			out.close();
		} catch (IOException ex) {
			Logger.getLogger(DiffUtil.class.getName()).log(Level.SEVERE, null, ex);
		}
		return diff.toString();
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
	public static void addTempStore(String title) throws IOException
	{
		java.io.File imageStore=new java.io.File("TempStore.txt");
		Scanner inp = new Scanner(imageStore);
		StringBuilder curr = new StringBuilder();
		while(inp.hasNextLine())
		{
			curr.append(inp.nextLine());
			curr.append("\n");
		}
		inp.close();
		FileWriter outp = new FileWriter(imageStore);
		outp.write(curr.toString());
		outp.append(title);
		outp.flush();
		outp.close();
	}
	/**
	 * Get the path for a standard corresponding to the given image path.
	 * @param imagePaths path of the image to get a standard for
	 * @return path to put/find the standard at
	 */
	static String standardPath(List<String> imagePaths, String type) {
		java.io.File firstImage = new java.io.File(imagePaths.get(0));
		String standardPath = System.getProperty(GOLD, ("test" + java.io.File.separator + "output" + java.io.File.separator + "Gold")) + java.io.File.separator + firstImage.getName().split("\\.")[0] +type+".txt";
		return standardPath;
	}
	
	public static void emptyResults(String path, String filename)
	{
		final String filt = filename.replace("_TD", "").replace(".txt", "").replace("_sorted","");
		FileFilter imageResFilter = new FileFilter() {
			@Override
			public boolean accept(java.io.File f) {
				return f.getName().contains(filt)&!f.getName().contains("leaves")&!f.getName().contains("sorted");
			}
		};
		java.io.File pth = new java.io.File(path);
		for(java.io.File del: pth.listFiles(imageResFilter))
		{
			del.deleteOnExit();
		}
	}
}