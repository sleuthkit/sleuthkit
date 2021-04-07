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
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
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
			
			// uncomment to manually test with PostgreSQL
			//CaseDbConnectionInfo connectionInfo = new CaseDbConnectionInfo("HostName", "5432", "User", "Password", TskData.DbType.POSTGRESQL);
			//caseDB = SleuthkitCase.newCase("TskArtifactTest", connectionInfo, tempDirPath);

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
	public void artifactTests() throws TskCoreException, Blackboard.BlackboardException, OsAccountManager.NotUserSIDException {


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
		
		// add another no attribute file to same folder
		FsContent _defTextFile = caseDB.addFileSystemFile(dataSourceObjectId, fs.getId(), "def.txt", 0, 0,
					TskData.TSK_FS_ATTR_TYPE_ENUM.TSK_FS_ATTR_TYPE_DEFAULT, 0, TskData.TSK_FS_NAME_FLAG_ENUM.ALLOC,
					(short) 0, 200, 0, 0, 0, 0, null, null, "Text/Plain", true, _windows, null, null, Collections.emptyList(), trans);			
		
		// Add additional attributes to dllhosts file - within the same transaction. 
		_dllhosts.addAttributes(fileAttributes2, trans);
	
		trans.commit();
		
		
		// Create a host and an account.
		String hostname1 = "host1";
		String realmName1 = "realm1";
		String ownerUid1 = "S-1-5-21-111111111-222222222-3333333333-0001";

		Host host1 = caseDB.getHostManager().newHost(hostname1);
		OsAccountRealm localRealm1 = caseDB.getOsAccountRealmManager().newWindowsRealm(ownerUid1, realmName1, host1, OsAccountRealm.RealmScope.LOCAL);
		OsAccount osAccount1 = caseDB.getOsAccountManager().newWindowsOsAccount(ownerUid1, null, realmName1, host1, OsAccountRealm.RealmScope.LOCAL);

		// create a 2nd account on the same host
		String ownerUid2 = "S-1-5-21-111111111-222222222-3333333333-0009";
		OsAccount osAccount2 = caseDB.getOsAccountManager().newWindowsOsAccount(ownerUid2, null, realmName1, host1, OsAccountRealm.RealmScope.LOCAL);
		
		
		// now find the file abc.text
		List<AbstractFile> abctextfiles = caseDB.findFiles(fs.getDataSource(), "abc.txt");
		assertEquals(1, abctextfiles.size());
	
		AbstractFile abcTextFile = abctextfiles.get(0);
		
		// create an attribute for the artifact
        Collection<BlackboardAttribute> attributes = new ArrayList<>();
        attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_KEYWORD, MODULE_NAME, "keyword1"));
        
		// Test: attach an analysis result to the file. 
		AnalysisResultAdded analysisResultAdded1 = abcTextFile.newAnalysisResult(new BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.TSK_KEYWORD_HIT), 
																		new Score(Score.Significance.LIKELY_NOTABLE, Score.MethodCategory.AUTO), "Keyword hit found", "", "", attributes);
   
		assertEquals(Score.Significance.LIKELY_NOTABLE.getId(), analysisResultAdded1.getAnalysisResult().getScore().getSignificance().getId());
		assertEquals(Score.MethodCategory.AUTO.getId(), analysisResultAdded1.getAnalysisResult().getScore().getMethodCategory().getId());
		assertTrue(analysisResultAdded1.getAnalysisResult().getConclusion().equalsIgnoreCase("Keyword hit found"));
		
		// Add a 2nd analysis result to the same file
		AnalysisResultAdded analysisResultAdded2 = abcTextFile.newAnalysisResult(new BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT), 
																	new Score(Score.Significance.LIKELY_NOTABLE, Score.MethodCategory.AUTO), "Thats a rather intersting file.", "", "", Collections.emptyList());
   
		// Add a 3rd analysis result to the same file 
		AnalysisResultAdded analysisResultAdded3 = abcTextFile.newAnalysisResult(new BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.TSK_ENCRYPTION_DETECTED), 
																	new Score(Score.Significance.NOTABLE, Score.MethodCategory.AUTO), "Highly scrambled text!!", "", "", Collections.emptyList());
		// get analysis results and verify count
		
		List<AnalysisResult> ars = abcTextFile.getAllAnalysisResults();
		assertEquals(3, ars.size());
		
		// verify the aggregate score - expect HIGH/Auto - highest of the 3 results added
		Score aggScore = abcTextFile.getAggregateScore();
		assertEquals(Score.Significance.NOTABLE.getId(), aggScore.getSignificance().getId());
		assertEquals(Score.MethodCategory.AUTO.getId(), aggScore.getMethodCategory().getId());
		
		// delete an anlysis result 3
		Score newScore = caseDB.getBlackboard().deleteAnalysisResult(analysisResultAdded3.getAnalysisResult());
		
		// get analysis results and verify count
		ars = abcTextFile.getAllAnalysisResults();
		assertEquals(2, ars.size());
		
		// verify aggregate score - should now be Medium/Auto
		Score newAggScore = abcTextFile.getAggregateScore();
		assertEquals(Score.Significance.LIKELY_NOTABLE.getId(), newAggScore.getSignificance().getId());
		assertEquals(Score.MethodCategory.AUTO.getId(), newAggScore.getMethodCategory().getId());
		
		
		// Test Analysis Results in a Transaction
		SleuthkitCase.CaseDbTransaction transAr = caseDB.beginTransaction();
		AnalysisResultAdded analysisResultAdded4 = caseDB.getBlackboard().newAnalysisResult(new BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT), 
																	abcTextFile.getId(), abcTextFile.getDataSourceObjectId(), new Score(Score.Significance.LIKELY_NOTABLE, Score.MethodCategory.AUTO), "Thats a rather intersting file.", "", "", Collections.emptyList(), transAr);
		
		AnalysisResultAdded analysisResultAdded5 = caseDB.getBlackboard().newAnalysisResult(new BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT), 
																	abcTextFile.getId(), abcTextFile.getDataSourceObjectId(), new Score(Score.Significance.LIKELY_NONE, Score.MethodCategory.USER_DEFINED), "Thats a rather intersting file.", "", "", Collections.emptyList(), transAr);

		transAr.commit();
		ars = abcTextFile.getAllAnalysisResults();
		assertEquals(4, ars.size());
		
		// verify aggregate score - should now be Good/User
		newAggScore = abcTextFile.getAggregateScore();
		assertEquals(Score.Significance.LIKELY_NONE.getId(), newAggScore.getSignificance().getId());
		assertEquals(Score.MethodCategory.USER_DEFINED.getId(), newAggScore.getMethodCategory().getId());

		
		
		// Test: add a new data artifact to the file
		DataArtifact dataArtifact1 = abcTextFile.newDataArtifact(new BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_SEARCH), Collections.emptyList(), osAccount1);
        
		OsAccountManager osAcctMgr = caseDB.getOsAccountManager();
		
		assertTrue(dataArtifact1.getOsAccountObjectId().isPresent());
		assertTrue(osAcctMgr.getOsAccountByObjectId(dataArtifact1.getOsAccountObjectId().get()).getAddr().orElse("").equalsIgnoreCase(ownerUid1));
		
		
		// Test: add a second data artifact to file - associate it with a different account
		DataArtifact dataArtifact2 = abcTextFile.newDataArtifact(new BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.TSK_CLIPBOARD_CONTENT), Collections.emptyList(), osAccount2);
		assertTrue(dataArtifact2.getOsAccountObjectId().isPresent());
		assertTrue(osAcctMgr.getOsAccountByObjectId(dataArtifact2.getOsAccountObjectId().get()).getAddr().orElse("").equalsIgnoreCase(ownerUid2));
				
				
		// and two more 
		DataArtifact dataArtifact3 = abcTextFile.newDataArtifact(new BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_AREA), Collections.emptyList(), osAccount2);
		DataArtifact dataArtifact4 = abcTextFile.newDataArtifact(new BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_AREA), Collections.emptyList(), osAccount2);

		
		// TEST: get all TSK_GPS_SEARCH data artifacts in the data source
		List<DataArtifact> gpsArtifacts = caseDB.getBlackboard().getDataArtifacts(BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_SEARCH.getTypeID(), image.getId());
		assertEquals(1, gpsArtifacts.size());

		// verify the account was set from the query
		assertTrue(gpsArtifacts.get(0).getOsAccountObjectId().isPresent());
		assertTrue(osAcctMgr.getOsAccountByObjectId(gpsArtifacts.get(0).getOsAccountObjectId().get()).getAddr().orElse("").equalsIgnoreCase(ownerUid1));

		
		
		// TEST: get all data artifacts of type TSK_YARA_HIT
		List<DataArtifact> gpsAreaArtifacts = caseDB.getBlackboard().getDataArtifacts(BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_AREA.getTypeID(), image.getId());
		assertEquals(2, gpsAreaArtifacts.size());
		// verify the account on each
		assertTrue(osAcctMgr.getOsAccountByObjectId(gpsAreaArtifacts.get(0).getOsAccountObjectId().get()).getAddr().orElse("").equalsIgnoreCase(ownerUid2));
		assertTrue(osAcctMgr.getOsAccountByObjectId(gpsAreaArtifacts.get(1).getOsAccountObjectId().get()).getAddr().orElse("").equalsIgnoreCase(ownerUid2));

		
		// Testing that artifacts created using the old methods and new methods are treated the same.
		// Find the file def.text
		List<AbstractFile> deftextfiles = caseDB.findFiles(fs.getDataSource(), "def.txt");
		assertEquals(1, deftextfiles.size());
	
		AbstractFile defTextFile = deftextfiles.get(0);
		
		// Test analysis results.
		// Using a custom analysis result to for additional test coverage
		BlackboardArtifact.Type analysisArtType = caseDB.getBlackboard().getOrAddArtifactType("CUSTOM_ANALYSIS_RESULT", "Custom Analysis Result", BlackboardArtifact.Category.ANALYSIS_RESULT);

		AnalysisResultAdded added0 = defTextFile.newAnalysisResult(analysisArtType, new Score(Score.Significance.UNKNOWN, Score.MethodCategory.AUTO), 
				"", "", null, java.util.Collections.emptyList());
		trans = caseDB.beginTransaction();
		AnalysisResultAdded added1 = caseDB.getBlackboard().newAnalysisResult(analysisArtType, defTextFile.getId(), fs.getDataSource().getId(), Score.SCORE_UNKNOWN, 
				"conclusion1", "config1", "justification1", java.util.Collections.emptyList(), trans);
		AnalysisResultAdded added2 = caseDB.getBlackboard().newAnalysisResult(analysisArtType, defTextFile.getId(), fs.getDataSource().getId(), Score.SCORE_UNKNOWN, 
				"", "", null, java.util.Collections.emptyList(), trans);
		AnalysisResultAdded added3 = caseDB.getBlackboard().newAnalysisResult(analysisArtType, defTextFile.getId(), fs.getDataSource().getId(), Score.SCORE_UNKNOWN, 
				"", "config3", null, java.util.Collections.emptyList(), trans);
		AnalysisResultAdded added4 = caseDB.getBlackboard().newAnalysisResult(analysisArtType, defTextFile.getId(), fs.getDataSource().getId(), new Score(Score.Significance.NOTABLE, Score.MethodCategory.AUTO), 
				"", "", null, java.util.Collections.emptyList(), trans);
		trans.commit();
		BlackboardArtifact bbArt2 = defTextFile.newArtifact(analysisArtType.getTypeID());
		int analysisResultCount = 6;
		
		// TEST: getAnalysisResults(file id)
		List<AnalysisResult> analysisResultResults = caseDB.getBlackboard().getAnalysisResults(defTextFile.getId());
		assertEquals(analysisResultCount, analysisResultResults.size());

		// TEST: getAnalysisResults(file id, artifact type)
		analysisResultResults = caseDB.getBlackboard().getAnalysisResults(defTextFile.getId(), analysisArtType.getTypeID());
		assertEquals(analysisResultCount, analysisResultResults.size());

		// TEST: getAnalysisResultsWhere("obj_id = <file id>")
		analysisResultResults = caseDB.getBlackboard().getAnalysisResultsWhere("obj_id=" + defTextFile.getId());
		assertEquals(analysisResultCount, analysisResultResults.size());

		// Test: getArtifacts(artifact type, data source id)
		List<BlackboardArtifact> artifactResults = caseDB.getBlackboard().getArtifacts(analysisArtType.getTypeID(), fs.getDataSource().getId());
		assertEquals(analysisResultCount, artifactResults.size());
		
		// TEST: getBlackboardArtifact(artifactId) 
		BlackboardArtifact art = caseDB.getBlackboardArtifact(added0.getAnalysisResult().getArtifactID());
		assertEquals(analysisArtType.getTypeID(), art.getArtifactTypeID());
		art = caseDB.getBlackboardArtifact(added1.getAnalysisResult().getArtifactID());
		assertEquals(analysisArtType.getTypeID(), art.getArtifactTypeID());
		art = caseDB.getBlackboardArtifact(added2.getAnalysisResult().getArtifactID());
		assertEquals(analysisArtType.getTypeID(), art.getArtifactTypeID());
		art = caseDB.getBlackboardArtifact(added3.getAnalysisResult().getArtifactID());
		assertEquals(analysisArtType.getTypeID(), art.getArtifactTypeID());
		art = caseDB.getBlackboardArtifact(added4.getAnalysisResult().getArtifactID());
		assertEquals(analysisArtType.getTypeID(), art.getArtifactTypeID());
		art = caseDB.getBlackboardArtifact(bbArt2.getArtifactID());
		assertEquals(analysisArtType.getTypeID(), art.getArtifactTypeID());

		// TEST: getArtifactById(artifact obj id)
		art = caseDB.getArtifactById(added0.getAnalysisResult().getId());
		assertEquals(analysisArtType.getTypeID(), art.getArtifactTypeID());
		art = caseDB.getArtifactById(added1.getAnalysisResult().getId());
		assertEquals(analysisArtType.getTypeID(), art.getArtifactTypeID());
		art = caseDB.getArtifactById(added2.getAnalysisResult().getId());
		assertEquals(analysisArtType.getTypeID(), art.getArtifactTypeID());
		art = caseDB.getArtifactById(added3.getAnalysisResult().getId());
		assertEquals(analysisArtType.getTypeID(), art.getArtifactTypeID());
		art = caseDB.getArtifactById(added4.getAnalysisResult().getId());
		assertEquals(analysisArtType.getTypeID(), art.getArtifactTypeID());
		art = caseDB.getArtifactById(bbArt2.getId());
		assertEquals(analysisArtType.getTypeID(), art.getArtifactTypeID());
		
		// Test data artifactst
		// Using a custom data artifact to for additional test coverage
		BlackboardArtifact.Type dataArtType = caseDB.getBlackboard().getOrAddArtifactType("CUSTOM_DATA_ARTIFACT", "Custom Data Artifact", BlackboardArtifact.Category.DATA_ARTIFACT);

		// Create five data artifacts. Only three should create a row in tsk_data_artifacts.
		DataArtifact dataArt1 = defTextFile.newDataArtifact(dataArtType, java.util.Collections.emptyList(), null);
		DataArtifact dataArt2 = defTextFile.newDataArtifact(dataArtType, java.util.Collections.emptyList(), osAccount2);
		BlackboardArtifact bbArt1 = defTextFile.newArtifact(dataArtType.getTypeID());
		DataArtifact dataArt3 = defTextFile.newDataArtifact(dataArtType, java.util.Collections.emptyList(), osAccount2);
		DataArtifact dataArt4 = caseDB.getBlackboard().newDataArtifact(dataArtType, defTextFile.getId(), fs.getDataSource().getId(), java.util.Collections.emptyList(), osAccount2);
		int dataArtifactCount = 5;
		
		// TEST: getDataArtifacts(artifact type id)
		List<DataArtifact> dataArtifactResults = caseDB.getBlackboard().getDataArtifacts(dataArtType.getTypeID());
		assertEquals(dataArtifactCount, dataArtifactResults.size());
            
		// TEST: getDataArtifacts(artifact type id, data source id)
		dataArtifactResults = caseDB.getBlackboard().getDataArtifacts(dataArtType.getTypeID(), fs.getDataSource().getId());
		assertEquals(dataArtifactCount, dataArtifactResults.size());
		
		// TEST: getBlackboardArtifacts(artifact type id, data source id)
		artifactResults = caseDB.getBlackboardArtifacts(dataArtType.getTypeID());
		assertEquals(dataArtifactCount, artifactResults.size());

        // TEST: getBlackboardArtifacts(artifact type id, file id)
        artifactResults = caseDB.getBlackboardArtifacts(dataArtType.getTypeID(), defTextFile.getId());
		assertEquals(dataArtifactCount, artifactResults.size());
            
        // TEST: getArtifacts(artifact type id, data source id)
        artifactResults = caseDB.getBlackboard().getArtifacts(dataArtType.getTypeID(), fs.getDataSource().getId());
		assertEquals(dataArtifactCount, artifactResults.size());
            
        // TEST: getMatchingArtifacts(where clause)
        artifactResults = caseDB.getMatchingArtifacts("WHERE artifact_type_id=" + dataArtType.getTypeID());
		assertEquals(dataArtifactCount, artifactResults.size());
		
        // TEST: getBlackboardArtifact(artifactId) 
		art = caseDB.getBlackboardArtifact(dataArt1.getArtifactID());
		assertEquals(dataArtType.getTypeID(), art.getArtifactTypeID());
		art = caseDB.getBlackboardArtifact(dataArt2.getArtifactID());
		assertEquals(dataArtType.getTypeID(), art.getArtifactTypeID());
		art = caseDB.getBlackboardArtifact(bbArt1.getArtifactID());
		assertEquals(dataArtType.getTypeID(), art.getArtifactTypeID());
		art = caseDB.getBlackboardArtifact(dataArt3.getArtifactID());
		assertEquals(dataArtType.getTypeID(), art.getArtifactTypeID());
		art = caseDB.getBlackboardArtifact(dataArt4.getArtifactID());
		assertEquals(dataArtType.getTypeID(), art.getArtifactTypeID());
		
		// TEST: getArtifactById(artifact obj id)
		art = caseDB.getArtifactById(dataArt1.getId());
		assertEquals(dataArtType.getTypeID(), art.getArtifactTypeID());
		art = caseDB.getArtifactById(dataArt2.getId());
		assertEquals(dataArtType.getTypeID(), art.getArtifactTypeID());
		art = caseDB.getArtifactById(bbArt1.getId());
		assertEquals(dataArtType.getTypeID(), art.getArtifactTypeID());
		art = caseDB.getArtifactById(dataArt3.getId());
		assertEquals(dataArtType.getTypeID(), art.getArtifactTypeID());
		art = caseDB.getArtifactById(dataArt4.getId());
		assertEquals(dataArtType.getTypeID(), art.getArtifactTypeID());	
		
		// TEST: getBlackboardArtifactsCount()
		assertEquals(analysisResultCount + dataArtifactCount, caseDB.getBlackboardArtifactsCount(defTextFile.getId()));
		
		
		// set a file to unallocated.
		caseDB.setFileUnalloc(abcTextFile);
		assertFalse(abcTextFile.isDirNameFlagSet(TskData.TSK_FS_NAME_FLAG_ENUM.ALLOC));
		assertFalse(abcTextFile.isMetaFlagSet(TskData.TSK_FS_META_FLAG_ENUM.ALLOC));
		assertTrue(abcTextFile.isMetaFlagSet(TskData.TSK_FS_META_FLAG_ENUM.UNALLOC));
	}
}
