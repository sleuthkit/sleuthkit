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
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Test artifact apis.
 * 
 */
public class ArtifactTest {
	
	private static final String MODULE_NAME = "ArtifactTest";
	
	private static final Logger LOGGER = Logger.getLogger(ArtifactTest.class.getName());

	private static SleuthkitCase caseDB;

	private final static String TEST_DB = "ArtifactApiTest.db";


	private static String dbPath = null;
	private static Image image = null;
	private static FileSystem fs = null;
	
	

	public ArtifactTest (){

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

			SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();

			image = caseDB.addImage(TskData.TSK_IMG_TYPE_ENUM.TSK_IMG_TYPE_DETECT, 512, 1024, "", Collections.emptyList(), "America/NewYork", null, null, null, "first", trans);

			fs = caseDB.addFileSystem(image.getId(), 0, TskData.TSK_FS_TYPE_ENUM.TSK_FS_TYPE_RAW, 0, 0, 0, 0, 0, "", trans);

			trans.commit();

			System.out.println("Artifacts Test DB created at: " + dbPath);
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
	public void artifactTests() throws TskCoreException {

		// first add a few files.
		
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
			
		
		// Add additional attributes to dllhosts file - within the same transaction. 
		_dllhosts.addAttributes(fileAttributes2, trans);
	
		trans.commit();
		
		
		// Create a host and an account.
		String hostname1 = "host1";
		String realmName1 = "realm1";
		String ownerUid1 = "S-1-5-32-111111111-222222222-3333333333-0001";

		Host host1 = caseDB.getHostManager().createHost(hostname1);
		OsAccountRealm localRealm1 = caseDB.getOsAccountRealmManager().createWindowsRealm(ownerUid1, realmName1, host1, OsAccountRealm.RealmScope.LOCAL);
		OsAccount osAccount1 = caseDB.getOsAccountManager().createWindowsAccount(ownerUid1, null, realmName1, host1, OsAccountRealm.RealmScope.LOCAL);

		// create a 2nd account on the same host
		String ownerUid2 = "S-1-5-32-111111111-222222222-3333333333-0009";
		OsAccount osAccount2 = caseDB.getOsAccountManager().createWindowsAccount(ownerUid2, null, realmName1, host1, OsAccountRealm.RealmScope.LOCAL);
		
		
		// now find the file abc.text
		List<AbstractFile> abctextfiles = caseDB.findFiles(fs.getDataSource(), "abc.txt");
		assertEquals(1, abctextfiles.size());
	
		AbstractFile abcTextFile = abctextfiles.get(0);
		
		// create an attribute for the artifact
        Collection<BlackboardAttribute> attributes = new ArrayList<>();
        attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_KEYWORD, MODULE_NAME, "keyword1"));
        
		// Test: attach an analysis result to the file. 
		AnalysisResultAdded analysisResultAdded1 = abcTextFile.newAnalysisResult(new BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.TSK_KEYWORD_HIT), 
																		new Score(Score.Significance.LIKELY_NOTABLE, Score.Confidence.NORMAL), "Keyword hit found", "", "", attributes);
   
		assertEquals(analysisResultAdded1.getAnalysisResult().getScore().getSignificance().getId(), Score.Significance.LIKELY_NOTABLE.getId());
		assertEquals(analysisResultAdded1.getAnalysisResult().getScore().getConfidence().getId(), Score.Confidence.NORMAL.getId());
		assertEquals(analysisResultAdded1.getAnalysisResult().getConclusion().equalsIgnoreCase("Keyword hit found"), true);
		
		// Add a 2nd analysis result to the same file
		AnalysisResultAdded analysisResultAdded2 = abcTextFile.newAnalysisResult(new BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT), 
																	new Score(Score.Significance.LIKELY_NOTABLE, Score.Confidence.NORMAL), "Thats a rather intersting file.", "", "", Collections.emptyList());
   
		// Add a 3rd analysis result to the same file 
		AnalysisResultAdded analysisResultAdded3 = abcTextFile.newAnalysisResult(new BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.TSK_ENCRYPTION_DETECTED), 
																	new Score(Score.Significance.NOTABLE, Score.Confidence.NORMAL), "Highly scrambled text!!", "", "", Collections.emptyList());
		// get analysis results and verify count
		
		List<AnalysisResult> ars = abcTextFile.getAllAnalysisResults();
		assertEquals(ars.size(), 3);
		
		// verify the aggregate score - expect HIGH/HIGH - highest of the 3 results added
		Score aggScore = abcTextFile.getAggregateScore();
		assertEquals(aggScore.getSignificance().getId(), Score.Significance.NOTABLE.getId());
		assertEquals(aggScore.getConfidence().getId(), Score.Confidence.NORMAL.getId());
		
		// delete an anlysis result 3
		Score newScore = caseDB.getBlackboard().deleteAnalysisResult(analysisResultAdded3.getAnalysisResult());
		
		// get analysis results and verify count
		ars = abcTextFile.getAllAnalysisResults();
		assertEquals(ars.size(), 2);
		
		// verify aggregate score - should now be Medium/High
		Score newAggScore = abcTextFile.getAggregateScore();
		assertEquals(newAggScore.getSignificance().getId(), Score.Significance.LIKELY_NOTABLE.getId());
		assertEquals(newAggScore.getConfidence().getId(), Score.Confidence.NORMAL.getId());
		
		
		// Test: add a new data artifact to the file
        DataArtifact dataArtifact1 = abcTextFile.newDataArtifact(new BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_SEARCH), Collections.emptyList(), osAccount1);
        
		assertEquals(dataArtifact1.getOsAccount().isPresent(), true);
		assertEquals(dataArtifact1.getOsAccount().get().getUniqueIdWithinRealm().orElse("").equalsIgnoreCase(ownerUid1), true);
		
		
		// Test: add a second data artifact to file - associate it with a different account
		DataArtifact dataArtifact2 = abcTextFile.newDataArtifact(new BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.TSK_CLIPBOARD_CONTENT), Collections.emptyList(), osAccount2);
		assertEquals(dataArtifact2.getOsAccount().isPresent(), true);
		assertEquals(dataArtifact2.getOsAccount().get().getUniqueIdWithinRealm().orElse("").equalsIgnoreCase(ownerUid2), true);
				
				
		// and two more 
		DataArtifact dataArtifact3 = abcTextFile.newDataArtifact(new BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_AREA), Collections.emptyList(), osAccount2);
		DataArtifact dataArtifact4 = abcTextFile.newDataArtifact(new BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_AREA), Collections.emptyList(), osAccount2);

		
		// TEST: get all TSK_GPS_SEARCH data artifacts in the data source
		List<DataArtifact> gpsArtifacts = caseDB.getBlackboard().getDataArtifacts(BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_SEARCH.getTypeID(), image.getId());
		assertEquals(gpsArtifacts.size(), 1);
		// verify the account 
		assertEquals(gpsArtifacts.get(0).getOsAccount().get().getUniqueIdWithinRealm().orElse("").equalsIgnoreCase(ownerUid1), true);
		
		
		// TES: get all data artifacts of type TSK_YARA_HIT
		List<DataArtifact> gpsAreaArtifacts = caseDB.getBlackboard().getDataArtifacts(BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_AREA.getTypeID(), image.getId());
		assertEquals(gpsAreaArtifacts.size(), 2);
		// verify the account on each
		assertEquals(gpsAreaArtifacts.get(0).getOsAccount().get().getUniqueIdWithinRealm().orElse("").equalsIgnoreCase(ownerUid2), true);
		assertEquals(gpsAreaArtifacts.get(1).getOsAccount().get().getUniqueIdWithinRealm().orElse("").equalsIgnoreCase(ownerUid2), true);
		
		
		
		
	}
}
