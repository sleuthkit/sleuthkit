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
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

public class DiffUtil {
	/**
	 * Calls {@link #createStandard(String, String, String[]) createStandard}
	 * with default arguments
	 * @param args Ignored 
	 */
	public static void main(String[] args){
		String tempDirPath = System.getProperty("java.io.tmpdir");
		java.io.File pth = new java.io.File(DataModelTestSuite.goldStandardPath());
		for(java.io.File del: pth.listFiles())
		{
			del.delete();
		}
		List<Traverser> tests = DataModelTestSuite.getTests();
		List<List<String>> imagePaths = DataModelTestSuite.getImagePaths();
		for(List<String> paths : imagePaths) {
			for(Traverser tstrn: tests)
			{
				String standardPath = DataModelTestSuite.standardPath(paths, tstrn.getClass().getSimpleName());
				System.out.println("Creating " + tstrn.getClass().getSimpleName() + " standard for: " + paths.get(0));
				String exFile = standardPath.replace(".txt",DataModelTestSuite.EX+".txt");
				DataModelTestSuite.createStandard(standardPath, tempDirPath, paths, tstrn, exFile);
			}
			String standardPathCPP = DataModelTestSuite.standardPath(paths,CPPtoJavaCompare.class.getSimpleName());
			DataModelTestSuite.getTSKData(standardPathCPP, paths);
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
			Logger.getLogger(DiffUtil.class.getName()).log(Level.SEVERE, "Couldn't read file", ex);
			throw new RuntimeException(ex);
		}
		return lines;
	}
	/**
	 * Compares the content of two files to determine if they are equal, if they are it removes the file from the results folder
	 * @param original is the first file to be compared
	 * @param results is the second file to be compared
	 */
	protected static boolean comparecontent(String original, String results) {
		try {
			java.io.File fi1 = new java.io.File(original);
			java.io.File fi2 = new java.io.File(results);
			FileReader f1 = new FileReader (new java.io.File(original).getAbsolutePath());
			FileReader f2 = new FileReader (new java.io.File(results).getAbsolutePath());
			Scanner in1 = new Scanner(f1);
			Scanner in2 = new Scanner(f2);
			while (in1.hasNextLine()||in2.hasNextLine()) {
				if((in1.hasNextLine()^in2.hasNextLine())||!(in1.nextLine().equals(in2.nextLine())))
				{
					in1.close();
					in2.close();
					f1.close();
					f2.close();
					getDiff(fi1.getAbsolutePath(),fi2.getAbsolutePath(),original.substring(original.lastIndexOf(java.io.File.separator)+1));
					return false;
				}
			}
			//DataModelTestSuite.emptyResults(fi2.getParent(), fi2.getName());
			return true;
		} catch (IOException ex) {
			Logger.getLogger(DiffUtil.class.getName()).log(Level.SEVERE, "Couldn't compare content", ex);
			return false;
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
		java.io.File outp = new java.io.File(DataModelTestSuite.getRsltPath() + java.io.File.separator + title.replace(".txt","_Diff.txt"));
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
			Logger.getLogger(DiffUtil.class.getName()).log(Level.SEVERE, "Couldn't write Diff to file", ex);
		}
		System.out.println(diff.toString());
		return diff.toString();
	}
}