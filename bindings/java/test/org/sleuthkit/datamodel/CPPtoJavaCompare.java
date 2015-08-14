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
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 * Compares the Java test output to the C++ test output. Basic concept is to run
 * tsk_gettimes on an image to get the body file format and then make equivalent
 * output from Java code. Diff. Does not use gold standards.
 */
@RunWith(Parameterized.class)
public class CPPtoJavaCompare extends ImgTraverser {

	private static final Logger logg = Logger.getLogger(CPPtoJavaCompare.class.getName());

	public CPPtoJavaCompare(List<String> imagePaths) {
		testName = DataModelTestSuite.CPP;
		this.imagePaths = imagePaths;
	}

	/**
	 * Get the sets of filenames for each test image
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
	public void testCppToJavaDiff() {
		try {
			// generate the C++ output and store it in gold standard -- even though it won't be checked in -- redesign this!
			String standardPathCPP = DataModelTestSuite.standardFilePath(imagePaths, DataModelTestSuite.CPP);
			java.io.File tskOutFile = new java.io.File(standardPathCPP);
			// get rid of copy from previous runs
			tskOutFile.delete();

			runTskGetTimes(standardPathCPP, imagePaths);

			assertTrue("TSK gettimes output is zero sized (" + standardPathCPP + ")", tskOutFile.length() > 0);

			// perform test
			List<Boolean> test = basicTest();

			// compare exceptions
			assertEquals("Generated exceptions  (" + outputExceptionsPath + ") differ with gold standards (" + goldExceptionsPath + ") .", test.get(0), true);

			//compare sorted output instead of unsorted output
			String goldFilePathSorted = DataModelTestSuite.sortedFlPth(goldFilePath);
			String outputFilePathSorted = DataModelTestSuite.sortedFlPth(outputFilePath);
			List<Boolean> ret = new ArrayList<Boolean>(1);
			ret.add(DataModelTestSuite.comparecontent(goldFilePathSorted, outputFilePathSorted));
			assertEquals("Java output (" + outputFilePathSorted + ") differ with C++ results (" + goldFilePathSorted + ") .", ret.get(0), true);
		} catch (Exception ex) {
			fail("Couldn't open gold standard file. " + ex.getMessage());
		}
	}

	/**
	 * Runs tsk_gettimes to create a standard for comparing DataModel and TSK
	 * output.
	 *
	 * @param outputFile The path to the file to put the tsk data in. Sorted
	 * results will be stored in separate file.
	 * @param img the path to the image, is a list for compatability reasons
	 */
	private static void runTskGetTimes(String outputFile, List<String> img) {
		String tsk_loc;
		java.io.File up = new java.io.File(System.getProperty("user.dir"));
		up = up.getParentFile();
		up = up.getParentFile();
		if (System.getProperty("os.name").contains("Windows")) {
			tsk_loc = up.getAbsolutePath() + "\\win32\\Release\\tsk_gettimes.exe";
		} else {
			tsk_loc = up.getAbsolutePath() + "/tools/autotools/tsk_gettimes";
		}

		// verify it exists
		java.io.File f = new java.io.File(tsk_loc);
		assertTrue("cannot find tsk_gettimes method", f.exists());

		String[] cmd = {tsk_loc, img.get(0)};
		try {
			Process p = Runtime.getRuntime().exec(cmd);
			Scanner read = new Scanner(p.getInputStream());
			Scanner error1 = new Scanner(p.getErrorStream());
			FileWriter out = new FileWriter(outputFile);
			while (read.hasNextLine()) {
				String line = read.nextLine();
				line = line.replace(" (deleted)", "");
				line = line.replace("(null)", "");
				//removes unknown data attached to metaAddr
				String[] linecontents = line.split("\\|");
				String metaaddrcon = linecontents[2];
				String mtad = metaaddrcon.split("\\-")[0];
				line = line.replace(metaaddrcon, mtad);
				out.append(line);
				out.flush();
				out.append("\n");
			}
			DataModelTestSuite.runSort(outputFile);
		} catch (Exception ex) {
			logg.log(Level.SEVERE, "Failed to run CPP program", ex);
		}

		java.io.File xfile = new java.io.File(DataModelTestSuite.exceptionPath(outputFile));
		try {
			xfile.createNewFile();
		} catch (IOException ex) {
			logg.log(Level.SEVERE, "Failed to create exceptions file", ex);
		}
	}

	/**
	 * gets the metadata from a datamodel file object
	 *
	 * @param fi
	 * @return
	 * @throws TskCoreException
	 */
	private static String convertToBodyFileFormat(FsContent fi) throws TskCoreException {
		String[] path = fi.getUniquePath().split("/", 3);
		String name;
		if (path[2].contains("vol_")) {
			String[] pthget = path[2].split("_", 2);
			name = pthget[pthget.length - 1];
		} else {
			name = path[2];
		}
		name = name.replaceAll("[^\\x20-\\x7e]", "");
		String prpnd;
		if (fi.isFile()) {
			prpnd = "r/";
		} else {
			prpnd = "d/";
		}
		if (fi.isVirtual() && !fi.isDir()) {
			prpnd = "v/";
		}
		return ("0|" + name + "|" + fi.metaAddr + "|" + fi.getMetaTypeAsString() + "/" + fi.getModesAsString() + "|" + fi.getUid() + "|0|" + fi.getSize() + "|" + fi.getAtime() + "|" + fi.getMtime() + "|" + fi.getCtime() + "|" + fi.getCrtime());
	}

	/**
	 * Traverses through an image and generates a TSK gettimes like
	 * representation
	 *
	 * @param sk the sleuthkit case used for the traversal
	 * @param path the location of the output file
	 * @return the file writer to be closed by testStandard
	 */
	@Override
	public OutputStreamWriter traverse(SleuthkitCase sk, String path) {
		OutputStreamWriter reslt;
		try {
			reslt = new OutputStreamWriter(new BufferedOutputStream(new FileOutputStream(path), 8192 * 4), Charset.forName("UTF-8"));
			try {
				tskTraverse(sk.getRootObjects(), reslt);
				return reslt;
			} catch (TskCoreException ex) {
				List<Exception> inp = new ArrayList<Exception>();
				inp.add(ex);
				DataModelTestSuite.writeExceptions(outputFilePath, inp);
			}
		} catch (IOException ex) {
			logg.log(Level.SEVERE, "Failed to Traverse", ex);
		}
		return null;
	}

	/**
	 * Recursively traverses through an image and generates a TSK gettimes like
	 * representation
	 *
	 * @param lc the list of content to be traversed
	 * @param reslt the filewriter to append output to
	 */
	private void tskTraverse(List<Content> lc, Appendable reslt) {
		for (Content c : lc) {
			try {
				if (c instanceof FsContent && !c.getUniquePath().endsWith(".") && !c.getUniquePath().endsWith("/")) {
					try {
						reslt.append(convertToBodyFileFormat((FsContent) c));
						reslt.append("\n");
					} catch (IOException ex) {
						logg.log(Level.SEVERE, "Failed to Traverse", ex);
					}
				}
				// recurse into childern
				tskTraverse(c.getChildren(), reslt);
			} catch (TskCoreException ex) {
				List<Exception> inp = new ArrayList<Exception>();
				inp.add(ex);
				DataModelTestSuite.writeExceptions(outputFilePath, inp);
			}
		}
	}
}
