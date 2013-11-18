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
            String hashfn = "regtestHash.kdb";
            String md5hash = "2c875b03541ffa970679986b48dca943";
			String md5hash2 = "48199F51973F317459E80E18DC744B12";
            String md5hash3 = "CB4ACA35F3FD54AACF96DA9CD9ACADB8";			
            String md5hashBad = "35b299c6fcf47ece375b3221bdc16969";
			String name = "junk.exe";
			String name2 = "bunk.exe";
			String com = "The Mysterious Case of Mr. Chunk";
			String com2 = "The Sinister Case of Capt. Funk";
			          
            // Make sure we start with a clean slate
			//java.io.File currdir = new java.io.File(".");
            //java.io.File f = new File(currdir.getAbsolutePath() + java.io.File.separator + hashfn);
			java.io.File f = new File(hashfn);
			boolean deleted = f.delete();
			assertTrue(deleted);
				
            //Creating hash db
            int handle = SleuthkitJNI.createHashDatabase(hashfn);
            assertTrue(handle > 0);
							
            // Test the get path or name functions            
			String retDbpath = SleuthkitJNI.getHashDatabasePath(handle);
			assertFalse(retDbpath.equals("None"));

            String retIndexDbpath = SleuthkitJNI.getHashDatabaseIndexPath(handle);
			assertFalse(retIndexDbpath.equals("None"));
           
			String dbName = SleuthkitJNI.getHashDatabaseName(handle);
			assertTrue(dbName.equals(hashfn));

			// Make a little hash set to test with
			SleuthkitJNI.addToHashDatabase(null, md5hash, null, null, null, handle);
			SleuthkitJNI.addToHashDatabase(name, md5hash2, null, null, com, handle); 
			SleuthkitJNI.addToHashDatabase(name2, md5hash3, null, null, com2, handle);
			
            // Querying for known hash
            boolean b = SleuthkitJNI.lookupInHashDatabase(md5hash, handle);
			assertTrue(b);

            // Querying for unknown hash
            boolean b2 = SleuthkitJNI.lookupInHashDatabase(md5hashBad, handle);
			assertFalse(b2);

			// Getting full hash info
            HashInfo h = SleuthkitJNI.lookupInHashDatabaseVerbose(md5hash2, handle);  
			ArrayList<String> nlist = h.getNames();
			ArrayList<String> clist = h.getComments();
			
			//assertTrue(h.getHashMd5().equals(md5hash2));
			assertTrue(h.getHashSha1().equals(""));
			assertTrue(h.getHashSha256().equals(""));
			assertTrue(nlist.size() > 0);
			assertTrue(clist.size() > 0);
			assertTrue(nlist.get(0).equals(name));
			assertTrue(clist.get(0).equals(com));
				
			// Getting full hash info (for another hash)
            HashInfo h2 = SleuthkitJNI.lookupInHashDatabaseVerbose(md5hash3, handle);
			ArrayList<String> nlist2 = h2.getNames();
			ArrayList<String> clist2 = h2.getComments();
			
			//assertTrue(h.getHashMd5().equals(md5hash2));
			assertTrue(h2.getHashSha1().equals(""));
			assertTrue(h2.getHashSha256().equals(""));
			assertTrue(nlist2.size() > 0);
			assertTrue(clist2.size() > 0);
			assertTrue(nlist2.get(0).equals(name2));
			assertTrue(clist2.get(0).equals(com2));
			
            // Test the boolean functions
            boolean indexable = SleuthkitJNI.hashDatabaseCanBeReindexed(handle);
            assertFalse(indexable);			
			
            boolean hasLookup = SleuthkitJNI.hashDatabaseHasLookupIndex(handle);
			assertTrue(hasLookup);
			            
			boolean isUpdateable = SleuthkitJNI.isUpdateableHashDatabase(handle);
			assertTrue(isUpdateable);
			
			boolean hlio = SleuthkitJNI.hashDatabaseHasLegacyLookupIndexOnly(handle);
			assertFalse(hlio);
			
			// Close it out
			SleuthkitJNI.closeHashDatabase(handle);
			
            // Test Reindexing            
            // Re-index a legacy index (which has a source db)          
            //String pathLegacy = "testmd5.dat";
            //("Opening existing idx (legacy) file...");
            //int handleLegacy = SleuthkitJNI.openHashDatabase(pathLegacy);
            
            //("Re-indexing...");
            //SleuthkitJNI.createLookupIndexForHashDatabase(handleLegacy, true);
            //File f2 = new File("testmd5.dat.kdb");
            //assertTrue(Boolean.toString(f2.exists()), Boolean.toString(true));
	
            //Test existing kdb file
            //int handle = SleuthkitJNI.openHashDatabase(hashfn);
            //("handle = " + handle);			
			

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
