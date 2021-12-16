/*
 * Sleuth Kit Data Model
 *
 * Copyright 2021 Basis Technology Corp.
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

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Misc tests for data model.
 * 
 */
public class DataModelMiscTests {
	
	private static final String MODULE_NAME = "DataModelMiscTests";
	
	private static final Logger LOGGER = Logger.getLogger(ArtifactTest.class.getName());

	private static SleuthkitCase caseDB;

	private final static String TEST_DB = "DataModelMiscTests.db";


	private static String dbPath = null;
	private static Image image = null;
	private static FileSystem fs = null;
	
	

	public DataModelMiscTests (){

	}
	
	@BeforeClass
	public static void setUpClass() {
		String tempDirPath = System.getProperty("java.io.tmpdir");
		try {
			dbPath = Paths.get(tempDirPath, TEST_DB).toString();

			// Delete the DB file, in case
			java.io.File dbFile = new java.io.File(dbPath);
			dbFile.delete();
			if (dbFile.getParentFile() != null) {
				dbFile.getParentFile().mkdirs();
			}

			// Create new case db
			caseDB = SleuthkitCase.newCase(dbPath);
			
			// uncomment to manually test with PostgreSQL
			//CaseDbConnectionInfo connectionInfo = new CaseDbConnectionInfo("HostName", "5432", "User", "Password", TskData.DbType.POSTGRESQL);
			//caseDB = SleuthkitCase.newCase("TskArtifactTest", connectionInfo, tempDirPath);

			SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();

			image = caseDB.addImage(TskData.TSK_IMG_TYPE_ENUM.TSK_IMG_TYPE_DETECT, 512, 1024, "", Collections.emptyList(), "America/NewYork", null, null, null, "first", trans);

			fs = caseDB.addFileSystem(image.getId(), 0, TskData.TSK_FS_TYPE_ENUM.TSK_FS_TYPE_RAW, 0, 0, 0, 0, 0, "", trans);

			trans.commit();

			System.out.println("Miscellenaous Test DB created at: " + dbPath);
		} catch (TskCoreException ex) {
			LOGGER.log(Level.SEVERE, "Failed to create new case", ex);
		}
	}

	@AfterClass
	public static void tearDownClass() {

	}

	@Before
	public void setUp() {
	}

	@After
	public void tearDown() {
	}
	
	@Test
	public void miscTests() throws TskCoreException, Blackboard.BlackboardException, OsAccountManager.NotUserSIDException {


		// first add a few folders and files.
		String testMD5 = "c67017ead6356b987b30536d35e8f562";
		List<Attribute> fileAttributes = new ArrayList<>();
		fileAttributes.add(new Attribute(new BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED), 1611233915l));

		List<Attribute> fileAttributes2 = new ArrayList<>();
		fileAttributes2.add(new Attribute(new BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SSID), "S-1-15-3443-2233"));

		long dataSourceObjectId = fs.getDataSource().getId();
		
		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();

		// Add a root folder
		FsContent _root = caseDB.addFileSystemFile(dataSourceObjectId, fs.getId(), "", 0, 0,
				TskData.TSK_FS_ATTR_TYPE_ENUM.TSK_FS_ATTR_TYPE_DEFAULT, 0, TskData.TSK_FS_NAME_FLAG_ENUM.ALLOC,
				(short) 0, 200, 0, 0, 0, 0, null, null, null, false, fs, null, null, Collections.emptyList(), trans);

		// Add a dir - no attributes 
		FsContent _windows = caseDB.addFileSystemFile(dataSourceObjectId, fs.getId(), "Windows", 0, 0,
				TskData.TSK_FS_ATTR_TYPE_ENUM.TSK_FS_ATTR_TYPE_DEFAULT, 0, TskData.TSK_FS_NAME_FLAG_ENUM.ALLOC,
				(short) 0, 200, 0, 0, 0, 0, null, null, null, false, _root, "S-1-5-80-956008885-3418522649-1831038044-1853292631-227147846", null, Collections.emptyList(), trans);

		// Add dllhosts.exe file to the above dir
		FsContent _dllhosts = caseDB.addFileSystemFile(dataSourceObjectId, fs.getId(), "dllhosts.exe", 0, 0,
				TskData.TSK_FS_ATTR_TYPE_ENUM.TSK_FS_ATTR_TYPE_DEFAULT, 0, TskData.TSK_FS_NAME_FLAG_ENUM.ALLOC,
				(short) 0, 200, 0, 0, 0, 0, testMD5, null, "Applicatione/Exe", true, _windows, "S-1-5-32-544", null, fileAttributes, trans);

		// add another no attribute file to the same folder
		FsContent _nofile = caseDB.addFileSystemFile(dataSourceObjectId, fs.getId(), "nofile.exe", 0, 0,
				TskData.TSK_FS_ATTR_TYPE_ENUM.TSK_FS_ATTR_TYPE_DEFAULT, 0, TskData.TSK_FS_NAME_FLAG_ENUM.ALLOC,
				(short) 0, 200, 0, 0, 0, 0, null, null, "Applicatione/Exe", true, _windows, null, null, Collections.emptyList(), trans);
		
		// add another no attribute file to same folder
		FsContent _abcTextFile = caseDB.addFileSystemFile(dataSourceObjectId, fs.getId(), "abc.txt", 0, 0,
					TskData.TSK_FS_ATTR_TYPE_ENUM.TSK_FS_ATTR_TYPE_DEFAULT, 0, TskData.TSK_FS_NAME_FLAG_ENUM.ALLOC,
					(short) 0, 200, 0, 0, 0, 0, null, null, "Text/Plain", true, _windows, null, null, Collections.emptyList(), trans);
		
		// add another no attribute file to same folder
		FsContent _defTextFile = caseDB.addFileSystemFile(dataSourceObjectId, fs.getId(), "def.txt", 0, 0,
					TskData.TSK_FS_ATTR_TYPE_ENUM.TSK_FS_ATTR_TYPE_DEFAULT, 0, TskData.TSK_FS_NAME_FLAG_ENUM.ALLOC,
					(short) 0, 200, 0, 0, 0, 0, null, null, "Text/Plain", true, _windows, null, null, Collections.emptyList(), trans);			
		
		// Add additional attributes to dllhosts file - within the same transaction. 
		_dllhosts.addAttributes(fileAttributes2, trans);
	
		trans.commit();
		
		
		
		// Add a custom type object to the top level folder
		
		CaseDbAccessManager caseDbAccessManager = caseDB.getCaseDbAccessManager();
		
		SleuthkitCase.CaseDbTransaction trans2 = caseDB.beginTransaction();
		
		// add a custom type child to file abc.txt 
		long childId1 = caseDbAccessManager.newCustomObject(_windows.getId(), trans2);
	
		// add a custom type child to file abc.txt
		long childId2 = caseDbAccessManager.newCustomObject(_abcTextFile.getId(), trans2);
				
		trans2.commit();
		
		// ensure that the object created has the right type. 
		Content child1 = caseDB.getContentById(childId1);
		Content child2 = caseDB.getContentById(childId2);
		assertTrue(child1 instanceof CustomContent);
		assertTrue(child2 instanceof CustomContent);
		
	}
}
