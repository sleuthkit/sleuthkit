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

import java.io.File;
import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.Charset;
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
 * Tests that we get all of the results by directly requesting a specific
 * object.  Basic concept of test is to sequentially request objects, starting
 * at 1.  Details of each object are printed and results are compared with
 * gold standard. 
 */
@RunWith(Parameterized.class)
public class HashDbTest extends ImgTraverser {
	private static final Logger logg = Logger.getLogger(HashDbTest.class.getName());

	public HashDbTest(List<String> imagePaths) {
		testName = DataModelTestSuite.HASH;
		this.imagePaths = imagePaths;
	}

	/**
	 * Get the sets of filenames for each test image, they should be located in
	 * the folder specified by the build.xml
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
	public void testHashDb() {
		try {
			// Doesn't matter for hashDB tests
			//List<Boolean> test = basicTest();
			//assertEquals("Generated results (" + outputExceptionsPath + ") differ with gold standard (" + goldExceptionsPath + ") .", test.get(0), true);
			//assertEquals("Generated results (" + outputFilePath + ") differ with gold standard (" + goldFilePath + ") .", test.get(1), true);
			
            String hashfn = "regtestHash.kdb";
            String md5hash = "2c875b03541ffa970679986b48dca943";
            String md5hash2 = "cb4aca35f3fd54aacf96da9cd9acadb8";
			String md5hash3 = "48199F51973F317459E80E18DC744B12";
            String md5hashBad = "35b299c6fcf47ece375b3221bdc16969";
            
            // Test Reindexing
            
            // Re-index a legacy index (which has a source db)          
            //String pathLegacy = "testmd5.dat";
            //("Opening existing idx (legacy) file...");
            //int handleLegacy = SleuthkitJNI.openHashDatabase(pathLegacy);
            
            //("Re-indexing...");
            //SleuthkitJNI.createLookupIndexForHashDatabase(handleLegacy, true);
            //File f2 = new File("testmd5.dat.kdb");
            //assertTrue(Boolean.toString(f2.exists()), Boolean.toString(true));

			// End Test Reindexing
			
            //("Opening existing kdb file...");
            //int handle = SleuthkitJNI.openHashDatabase(hashfn);
            //("handle = " + handle);
            
            // Make sure we start with a clean slate
			java.io.File currdir = new java.io.File(".");
			 
            java.io.File f = new File(currdir.getAbsolutePath() + java.io.File.separator + hashfn);
            //if (f.exists()) {
			boolean deleted = f.delete();
			assertTrue(deleted);
				
            //Creating hash db
            int handle = SleuthkitJNI.createHashDatabase(hashfn);
            
            //hashDatabaseCanBeReindexed?
            boolean retIndexable = SleuthkitJNI.hashDatabaseCanBeReindexed(handle);
            
            //getHashDatabasePath?
            String retDbpath = SleuthkitJNI.getHashDatabasePath(handle);
			assertFalse(retDbpath.equals("None"));

            //getHashDatabaseIndexPath?
            String retIndexDbpath = SleuthkitJNI.getHashDatabaseIndexPath(handle);
			assertFalse(retIndexDbpath.equals("None"));
           
			SleuthkitJNI.addToHashDatabase(null, md5hash, null, null, null, handle);

			SleuthkitJNI.addToHashDatabase("junk.exe", md5hash2, null, null, "The Mysterious Case of Mr. Chunk", handle); 

			SleuthkitJNI.addToHashDatabase("bunk.exe", md5hash3, null, null, "The Sinister Case of Capt. Funk", handle);
			
            //Querying for known hash " + md5hash
            boolean b = SleuthkitJNI.lookupInHashDatabase(md5hash, handle);

            //Querying for unknown hash " + md5hashBad
            boolean b2 = SleuthkitJNI.lookupInHashDatabase(md5hashBad, handle);

            //Test: hashDatabaseHasLookupIndex()
            boolean hasLookup = SleuthkitJNI.hashDatabaseHasLookupIndex(handle);
			            
			// Close it out
			SleuthkitJNI.closeHashDatabase(handle);

		} catch (Exception ex) {
			fail("Error running JNI HashDb test: " + ex.getMessage());
		}
	}

	/**
	 * Traverses through an image and generates a sequential representation of
	 * the image
	 *
	 * @param sk the sleuthkit case used for the traversal
	 * @param path the location of the output file
	 * @return the file writer to be closed by testStandard
	 */
	@Override
	public OutputStreamWriter traverse(SleuthkitCase sk, String path) {
		try {
			Charset chr = Charset.forName("UTF-8");
			OutputStreamWriter reslt = new OutputStreamWriter(new BufferedOutputStream(new FileOutputStream(path), 8192*4), chr);
			return reslt;
		} catch (IOException ex) {
			logg.log(Level.SEVERE, "Failed to Traverse", ex);
			return null;
		}
	}
}
