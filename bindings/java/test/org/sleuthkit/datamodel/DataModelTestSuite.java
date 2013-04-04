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

import java.io.BufferedReader;
import java.io.FileFilter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

/**
 *
 * Runs all regression tests and contains utility methods for the tests
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({org.sleuthkit.datamodel.TopDownTraversal.class, org.sleuthkit.datamodel.SequentialTraversal.class, org.sleuthkit.datamodel.CrossCompare.class, org.sleuthkit.datamodel.BottomUpTest.class, org.sleuthkit.datamodel.CPPtoJavaCompare.class})
public class DataModelTestSuite {

	static final String TEST_IMAGE_DIR_NAME = "test" + java.io.File.separator + "Input";
	static final String INPT = "inpt";
	static final String GOLD = "gold";
	static final String RSLT = "rslt";
	static final String SEQ = "_Seq";
	static final String TD = "_TD";
	static final String BTTMUP = "_BU";
	static final String EX = "_Exc";
	static final String TST = "types";
	static final String CPP = "_CPP";
	static final int READ_BUFFER_SIZE = 8192;
	static final String HASH_ALGORITHM = "MD5";
	private static final Logger logg = Logger.getLogger(DataModelTestSuite.class.getName());

	/**
	 * Empties the results directory
	 *
	 * @throws Exception
	 */
	@BeforeClass
	public static void setUpClass() throws Exception {
		java.io.File results = new java.io.File(getRsltPath());
		for (java.io.File del : results.listFiles()) {
			del.delete();
		}
	}

	/**
	 * Generates a list of the traversals to be used for standard creations
	 *
	 * @return
	 */
	public static List<ImgTraverser> getTests() {
		List<ImgTraverser> ret = new ArrayList<ImgTraverser>();
		ret.add(new SequentialTraversal(null));
		ret.add(new TopDownTraversal(null));
		return ret;
	}

	/**
	 * Creates the Sleuth Kit database for an image, then generates a string
	 * representation of the given traversal type of the resulting database to
	 * use as a standard for comparison, and saves the the standard to a file.
	 *
	 * @param standardPath The path to save the standard file to (will be
	 * overwritten if it already exists)
	 * @param tempDirPath An existing directory to create the test database in
	 * @param imagePaths The path(s) to the image file(s)
	 * @param type The type of traversal to run.
	 * @param exFile The exceptions file, will be used for logging purposes
	 */
	public static void createStandard(String standardPath, String tempDirPath, List<String> imagePaths, ImgTraverser type) {
		java.io.File standardFile = new java.io.File(standardPath);
		String exFile = standardFile.getAbsolutePath().replace(".txt", EX + ".txt");
		List<Exception> inp = new ArrayList<Exception>();
		try {
			String firstImageFile = getImgName(imagePaths.get(0));
			String dbPath = buildPath(tempDirPath, firstImageFile, type.testName, ".db");
			java.io.File dbFile = new java.io.File(dbPath);
			standardFile.createNewFile();
			dbFile.delete();
			SleuthkitCase sk = SleuthkitCase.newCase(dbPath);
			String timezone = "";
			SleuthkitJNI.CaseDbHandle.AddImageProcess process = sk.makeAddImageProcess(timezone, true, false);
			java.io.File xfile = new java.io.File(exFile);
			xfile.createNewFile();
			try {
				process.run(imagePaths.toArray(new String[imagePaths.size()]));
			} catch (TskDataException ex) {
				inp.add(ex);
			}
			writeExceptions(standardFile.getAbsolutePath(), inp);
			process.commit();
			OutputStreamWriter standardWriter = type.traverse(sk, standardFile.getAbsolutePath());
			standardWriter.flush();
			runSort(standardFile.getAbsolutePath());
		} catch (IOException ex) {
			logg.log(Level.SEVERE, "Couldn't create Standard", ex);
			throw new RuntimeException(ex);
		} catch (TskCoreException ex) {
			List<Exception> inp1 = new ArrayList<Exception>();
			inp1.add(ex);
			writeExceptions(standardFile.getAbsolutePath(), inp1);
		}
	}

	/**
	 * Gets the paths to the test image files by looking for a test image in the
	 * given output directory
	 *
	 * @return A list of lists of paths to image parts
	 */
	static List<List<String>> getImagePaths() {

		// needs to be absolute file because we're going to walk up its path
		java.io.File dir = new java.io.File(System.getProperty(INPT, TEST_IMAGE_DIR_NAME));

		FileFilter imageFilter = new FileFilter() {
			@Override
			public boolean accept(java.io.File f) {
				return isImgFile(f.getName());
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
	 *
	 * @param imagePaths path of the image to get a standard for
	 * @return path to put/find the standard at
	 */
	static String standardPath(List<String> imagePaths, String type) {
		String firstImage = getImgName(imagePaths.get(0));
		String standardPath = goldStandardPath() + java.io.File.separator + firstImage + type + ".txt";
		return standardPath;
	}

	/**
	 * removes the files with the file name from the from the given path
	 *
	 * @param path the path to the folder where files are to be deleted
	 * @param filename the name of the files to be deleted
	 */
	public static void emptyResults(String path, String filename) {
		final String filt = filename.replace(TD, "").replace(".txt", "").replace(SEQ, "");
		FileFilter imageResFilter = new FileFilter() {
			@Override
			public boolean accept(java.io.File f) {
				return f.getName().contains(filt) & !f.getName().contains(BTTMUP) & !f.getName().contains("SRT");
			}
		};
		java.io.File pth = new java.io.File(path);
		for (java.io.File del : pth.listFiles(imageResFilter)) {
			del.deleteOnExit();
		}
	}

	/**
	 * Runs tsk_gettimes to create a standard for comparing DataModel and TSK
	 * output.
	 *
	 * @param standardPath The path to the file to put the tsk data in
	 * @param img the path to the image, is a list for compatability reasons
	 */
	 private static void getTSKData(String standardPath, List<String> img) {
		String tsk_loc;
		java.io.File  up = new java.io.File(System.getProperty("user.dir"));
		up = up.getParentFile();
		up = up.getParentFile();
		if (System.getProperty("os.name").contains("Windows")) {
			tsk_loc = up.getAbsolutePath() + "\\win32\\Release\\tsk_gettimes";
		} else {
			tsk_loc = up.getAbsolutePath() + "/tools/autotools/tsk_gettimes";
		}
		String[] cmd = {tsk_loc, img.get(0)};
		try {
			Process p = Runtime.getRuntime().exec(cmd);
			Scanner read = new Scanner(p.getInputStream());
			Scanner error1 = new Scanner(p.getErrorStream());
			FileWriter out = new FileWriter(standardPath);
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
			runSort(standardPath);
		} catch (Exception ex) {
			logg.log(Level.SEVERE, "Failed to run CPP program", ex);
		}
		java.io.File xfile = new java.io.File(standardPath.replace(".txt", DataModelTestSuite.EX + ".txt"));
		try {
			xfile.createNewFile();
		} catch (IOException ex) {
			logg.log(Level.SEVERE, "Failed to create exceptions file", ex);
		}
	}

	/**
	 * Strips the file extension from the given string
	 *
	 * @param title the file to have its extension stripped
	 * @return
	 */
	private static String stripExtension(String title) {
		return title.substring(0, title.lastIndexOf("."));
	}

	/**
	 * builds the path for an output file
	 *
	 * @param path the path to the directory for the file to be stored in
	 * @param name the name of the file
	 * @param type the output type of the file
	 * @param Ext the file extension
	 * @return the path for an output file
	 */
	public static String buildPath(String path, String name, String type, String Ext) {
		return path + java.io.File.separator + name + type + Ext;
	}

	/**
	 * Returns the name of an image from the given path
	 *
	 * @param img
	 * @return
	 */
	public static String getImgName(String img) {
		String[] imgSp;
		if (System.getProperty("os.name").contains("Windows")) {
			 imgSp = img.split("\\\\");
		} else {
			 imgSp = img.split("/");
		}
		return stripExtension(imgSp[imgSp.length - 1]);
	}

	/**
	 * Gets the location results are stored in.
	 *
	 * @return
	 */
	public static String getRsltPath() {
		return System.getProperty(RSLT, "test" + java.io.File.separator + "output" + java.io.File.separator + "results");
	}

	/**
	 * returns the path to the sort command
	 *
	 * @return
	 */
	private static String getSortPath() {
		if (!System.getProperty("os.name").contains("Windows")) {
			return "sort";
		} else {
			return "\\cygwin\\bin\\sort.exe";
		}
	}

	/**
	 * returns the path to the diff command
	 *
	 * @return
	 */
	private static String getDiffPath() {
		if (!System.getProperty("os.name").contains("Windows")) {
			return "diff";
		} else {
			return "\\cygwin\\bin\\diff.exe";
		}
	}

	/**
	 * Writes the given exception to the given file
	 *
	 * @param filename the path of the file that exceptions are being stored for
	 * @param ex the exception to be written
	 */
	protected static void writeExceptions(String filename, List<Exception> ex) {
		filename = filename.replace(".txt", EX + ".txt");
		FileWriter exWriter;
		try {
			exWriter = new FileWriter(filename, true);
			for(Exception exc: ex)
			{
				exWriter.append(exc.toString());
			}
			exWriter.flush();
			exWriter.close();
		} catch (IOException ex1) {
			logg.log(Level.SEVERE, "Couldn't log Exception", ex1);
		}
	}

	/**
	 * returns the gold standard path
	 *
	 * @return
	 */
	private static String goldStandardPath() {
		return System.getProperty(GOLD, ("test" + java.io.File.separator + "output" + java.io.File.separator + "gold"));
	}

	/**
	 * Reads the data for a given content object, used to create hashes
	 *
	 * @param c the content object to be read
	 * @param result the appendable to append the results to
	 * @param StrgFile the file path that the content is being read for
	 */
	public static void readContent(Content c, Appendable result, String StrgFile) {
		long size = c.getSize();
		byte[] readBuffer = new byte[READ_BUFFER_SIZE];
		try {
			MessageDigest md5 = MessageDigest.getInstance("MD5");

			for (long i = 0; i < size; i = i + READ_BUFFER_SIZE) {
				c.read(readBuffer, i, Math.min(size - i, READ_BUFFER_SIZE));
				md5.update(readBuffer);
			}
			String hash = toHex(md5.digest());

			result.append("md5=" + hash);

		} catch (NoSuchAlgorithmException ex) {
			logg.log(Level.SEVERE, "Failed to generate Hash", ex);
		} catch (IOException ex){
			logg.log(Level.SEVERE, "Failed to generate Hash", ex);
		} catch (TskCoreException ex) {
			List<Exception> inp = new ArrayList<Exception>();
			inp.add(ex);
			writeExceptions(StrgFile, inp);
		}
	}

	/**
	 * Helper method for Read Content, converts a byte array to a Hexadecimal
	 * String
	 *
	 * @param bytes given byte array.
	 * @return a Hexadecimal String
	 */
	private static String toHex(byte[] bytes) {
		StringBuilder hex = new StringBuilder();
		for (byte b : bytes) {
			hex.append(String.format("%02x", b & 0xFF));
		}
		return hex.toString();
	}

	/**
	 * gets the metadata from a datamodel file object
	 *
	 * @param fi
	 * @return
	 * @throws TskCoreException
	 */
	protected static String getFsCData(FsContent fi) throws TskCoreException {
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
	 * Calls {@link #createStandard(String, String, String[]) createStandard}
	 * with default arguments
	 *
	 * @param args Ignored
	 */
	public static void main(String[] args) {
		if(System.getProperty("os.name").contains("Mac")||System.getProperty("os.name").toLowerCase().contains("unix")){
			java.io.File dep = new java.io.File("/usr/local/lib");
			boolean deps = false;
			for(String chk: dep.list())
			{
				deps = (deps||chk.toLowerCase().contains("tsk"));
			}
			if(!deps)
			{
				System.out.println("Run make install on tsk");
				throw new RuntimeException("Run make install on tsk");
			}
		}
		String tempDirPath = System.getProperty("java.io.tmpdir");
		tempDirPath = tempDirPath.substring(0, tempDirPath.length() - 1);
		java.io.File pth = new java.io.File(DataModelTestSuite.goldStandardPath());
		FileFilter testExFilter = new FileFilter() {
			@Override
			public boolean accept(java.io.File f) {
				return f.getName().contains(EX);
			}
		};
		for (java.io.File del : pth.listFiles(testExFilter)) {
			del.delete();
		}
		List<ImgTraverser> tests = DataModelTestSuite.getTests();
		List<List<String>> imagePaths = DataModelTestSuite.getImagePaths();
		for (List<String> paths : imagePaths) {
			for (ImgTraverser tstrn : tests) {
				String standardPath = DataModelTestSuite.standardPath(paths, tstrn.testName);
				System.out.println("Creating " + tstrn.testName + " standard for: " + paths.get(0));
				DataModelTestSuite.createStandard(standardPath, tempDirPath, paths, tstrn);
			}
			String standardPathCPP = DataModelTestSuite.standardPath(paths, CPP);
			DataModelTestSuite.getTSKData(standardPathCPP, paths);
		}
	}

	/**
	 * Compares the content of two files to determine if they are equal, if they
	 * are it removes the file from the results folder
	 *
	 * @param original is the first file to be compared
	 * @param results is the second file to be compared
	 */
	protected static boolean comparecontent(String original, String results) {
		try {
			java.io.File fi1 = new java.io.File(original);
			java.io.File fi2 = new java.io.File(results);
			BufferedReader f1 = new BufferedReader(new FileReader(new java.io.File(original).getAbsolutePath()), 8192*4);
			BufferedReader f2 = new BufferedReader(new FileReader(new java.io.File(results).getAbsolutePath()), 8192*4);
			Scanner in1 = new Scanner(f1);
			Scanner in2 = new Scanner(f2);
			while (in1.hasNextLine() || in2.hasNextLine()) {
				if ((in1.hasNextLine() ^ in2.hasNextLine()) || !(in1.nextLine().equals(in2.nextLine()))) {
					in1.close();
					in2.close();
					f1.close();
					f2.close();
					runDiff(fi1.getAbsolutePath(), fi2.getAbsolutePath());
					return false;
				}
			}
			//DataModelTestSuite.emptyResults(fi2.getParent(), fi2.getName());
			return true;
		} catch (IOException ex) {
			logg.log(Level.SEVERE, "Couldn't compare content", ex);
			return false;
		}
	}

	/**
	 * runs sort on the given file
	 *
	 * @param inp
	 */
	private static void runSort(String inp) {
		String outp = sortedFlPth(inp);
		String cygpath = getSortPath();
		String[] cmd = {cygpath, inp, "-o", outp};
		try {
			Runtime.getRuntime().exec(cmd).waitFor();
		} catch (InterruptedException ex) {
			logg.log(Level.SEVERE, "Couldn't create Standard", ex);
			throw new RuntimeException(ex);
		} catch(IOException ex){
			logg.log(Level.SEVERE, "Couldn't create Standard", ex);
			throw new RuntimeException(ex);
		}
	}

	/**
	 * Returns the name of the sorted file
	 *
	 * @param path the original name of the file
	 * @return
	 */
	protected static String sortedFlPth(String path) {
		return path.replace(".txt", "_SRT.txt");
	}

	/**
	 * Runs the Cygwin Diff algorithm on two files, is currently unused
	 *
	 * @param path1 is the path to the first file
	 * @param path2 is the path to the second file
	 */
	private static void runDiff(String path1, String path2) {
		String diffPath = getDiffPath();
		String outputLoc = path2.replace(".txt", "_Diff.txt");
		String[] cmd = {diffPath, path1, path2};
		try {
			Process p = Runtime.getRuntime().exec(cmd);
			Scanner read = new Scanner(p.getInputStream());
			Scanner error1 = new Scanner(p.getErrorStream());
			FileWriter out = new FileWriter(outputLoc);
			while (read.hasNextLine()) {
				String line = read.nextLine();
				out.append(line);
				out.flush();
				out.append("\n");
				out.flush();
			}
		} catch (Exception ex) {
			logg.log(Level.SEVERE, "Failed to run Diff program", ex);
		}
	}

	/**
	 * Returns whether or not a file is an image file
	 *
	 * @param name the name of the file
	 * @return a boolean that is true if the name ends with an image file
	 * extension
	 */
	protected static boolean isImgFile(String name) {
		return name.endsWith(".001") || name.endsWith(".raw") || name.endsWith(".img") || name.endsWith(".E01") || name.endsWith(".dd");
	}
}
