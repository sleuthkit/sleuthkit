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
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * Tests OsAccount apis.
 *
 */
public class OsAccountTest {
	
	private static final Logger LOGGER = Logger.getLogger(OsAccountTest.class.getName());

	private static SleuthkitCase caseDB;

	private final static String TEST_DB = "OsAccountApiTest.db";


	private static String dbPath = null;
	private static FileSystem fs = null;

	public OsAccountTest (){

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

			Image img = caseDB.addImage(TskData.TSK_IMG_TYPE_ENUM.TSK_IMG_TYPE_DETECT, 512, 1024, "", Collections.emptyList(), "America/NewYork", null, null, null, "first", trans);

			fs = caseDB.addFileSystem(img.getId(), 0, TskData.TSK_FS_TYPE_ENUM.TSK_FS_TYPE_RAW, 0, 0, 0, 0, 0, "", trans);

			trans.commit();


			System.out.println("OsAccount Test DB created at: " + dbPath);
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
	public void osAccountRealmTests() throws TskCoreException {
		
		
		SleuthkitCase.CaseDbTransaction transaction = caseDB.beginTransaction();
		
		try {
		// TEST: create a domain realm 
		String realmName1 = "basis";
		OsAccountRealm domainRealm1 = caseDB.getOsAccountRealmManager().getOrCreateRealmByName(realmName1, null, transaction);
		assertEquals(domainRealm1.getName().equalsIgnoreCase(realmName1), true );
		assertEquals(domainRealm1.getNameType(), OsAccountRealm.RealmNameType.EXPRESSED);
		assertEquals(domainRealm1.getRealmAddr().orElse(null), null);	// verify there is no realm addr
		
		
		
		String realmName2 = "win-raman-abcd";
		
		String realmAddr2SubAuth = "S-1-5-18-2033736216-1234567890";	
		String realmAddr2 = "S-1-5-18-2033736216-1234567890-5432109876";
		
		String hostName2 = "win-raman-abcd";
		
		// TEST: create a host
		Host host2 = caseDB.getHostManager().getOrCreateHost(hostName2, transaction);
		
		// verify host name
		assertEquals(host2.getName().equalsIgnoreCase(hostName2), true);

		//TEST: create a local realm with single host
		OsAccountRealm localRealm2 = caseDB.getOsAccountRealmManager().getOrCreateRealmByWindowsSid(realmAddr2, host2, transaction);
		assertEquals(localRealm2.getRealmAddr().orElse("").equalsIgnoreCase(realmAddr2SubAuth), true );
		assertEquals(localRealm2.getHost().orElse(null).getName().equalsIgnoreCase(hostName2), true);
		
		
		// update the a realm name
		OsAccountRealm updatedRealm2 = caseDB.getOsAccountRealmManager().updateRealmName(localRealm2.getId(), realmName2, OsAccountRealm.RealmNameType.EXPRESSED, transaction);
		
		assertEquals(updatedRealm2.getRealmAddr().orElse("").equalsIgnoreCase(realmAddr2SubAuth), true );
		assertEquals(updatedRealm2.getName().equalsIgnoreCase(realmName2), true );
		
		
		// get an existing realm - new SID but same sub authority as previously created realm.
		String realmAddr3 = realmAddr2SubAuth + "-88888888";
		
		OsAccountRealm existingRealm3 = caseDB.getOsAccountRealmManager().getOrCreateRealmByWindowsSid(realmAddr3, null, transaction);
		assertEquals(existingRealm3.getRealmAddr().orElse("").equalsIgnoreCase(realmAddr2SubAuth), true );
		assertEquals(existingRealm3.getName().equalsIgnoreCase(realmName2), true );
		
		
		}
		finally {
			transaction.commit();
		}
		
		
	}
	
	@Test
	public void basicOsAccountTests() throws TskCoreException {

		SleuthkitCase.CaseDbTransaction transaction = caseDB.beginTransaction();

		try {
			String ownerUid1 = "S-1-5-32-544";
			String ownerUid2 = "S-1-5-21-725345543-854245398-1060284298-1003";
			String ownerUid3 = "S-1-5-21-725345543-854245398-1060284298-1004";
			
			
			String realmName1 = "Realm1";
			String realmName2 = "Realm2";
			
			Host host = null;
			
			OsAccount osAccount1 = caseDB.getOsAccountManager().getOrCreateOsAccount(ownerUid1, null, realmName1, host, transaction);
			OsAccount osAccount2 = caseDB.getOsAccountManager().getOrCreateOsAccount(ownerUid2, null, realmName2, host, transaction);
			OsAccount osAccount3 = caseDB.getOsAccountManager().getOrCreateOsAccount(ownerUid3, null, realmName2, host, transaction);
				
		
			assertEquals(osAccount1.isAdmin(), false);
			assertEquals(osAccount1.getUniqueIdWithinRealm().orElse("").equalsIgnoreCase(ownerUid1), true);
			assertEquals(osAccount1.getRealm().getName().equalsIgnoreCase(realmName1), true);
			
			
			// Let's update osAccount1
			String fullName1 = "Johnny Depp";
			long creationTime1 = 1611858618;
			osAccount1.setCreationTime(creationTime1);
			osAccount1.setFullName(fullName1);
			osAccount1.setIsAdmin(true);
			
			osAccount1 = caseDB.getOsAccountManager().updateAccount(osAccount1, transaction);
			
			assertEquals(osAccount1.getCreationTime(), creationTime1);
			
			// now try and create osAccount1 again - it should return the existing account
			OsAccount osAccount1_copy1 = caseDB.getOsAccountManager().getOrCreateOsAccount(ownerUid1, null, realmName1, host, transaction);
			
			
			assertEquals(osAccount1_copy1.getUniqueIdWithinRealm().orElse("").equalsIgnoreCase(ownerUid1), true);
			assertEquals(osAccount1_copy1.getRealm().getName().equalsIgnoreCase(realmName1), true);
			
			
			assertEquals(osAccount1_copy1.isAdmin(), true); // should be true now
			assertEquals(osAccount1_copy1.getFullName().orElse("").equalsIgnoreCase(fullName1), true);
			assertEquals(osAccount1_copy1.getCreationTime(), creationTime1);
			
		}
		
		finally {
			transaction.commit();
		}
			
	}
}
