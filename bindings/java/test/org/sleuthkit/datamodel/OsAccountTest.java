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
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbTransaction;

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
	public void hostTests() throws TskCoreException {
		//SleuthkitCase.CaseDbTransaction transaction = caseDB.beginTransaction();
		try {
			String HOSTNAME1 = "host1";
			
			// Test: create a host
			Host host1 = caseDB.getHostManager().createHost(HOSTNAME1);
			assertEquals(host1.getName().equalsIgnoreCase(HOSTNAME1), true );
			
			
			// Test: get a host we just created.
			CaseDbTransaction transaction = caseDB.beginTransaction();
			
			
			Optional<Host> optionalhost1 = caseDB.getHostManager().getHost(HOSTNAME1, transaction);
			assertEquals(optionalhost1.isPresent(), true );
			
			
			String HOSTNAME2 = "host2";
			
			// Get a host not yet created
			Optional<Host> optionalhost2 = caseDB.getHostManager().getHost(HOSTNAME2, transaction);
			assertEquals(optionalhost2.isPresent(), false );
			
			transaction.commit();
			
			// now create the second host
			Host host2 = caseDB.getHostManager().createHost(HOSTNAME2);
			assertEquals(host2.getName().equalsIgnoreCase(HOSTNAME2), true );
			
			
			// now get it again, should be found this time
			transaction = caseDB.beginTransaction();
			optionalhost2 = caseDB.getHostManager().getHost(HOSTNAME2, transaction);
			assertEquals(optionalhost2.isPresent(), true);
			transaction.commit();
			
			// create a host that already exists - should transperently return the existting host.
			Host host2_2 = caseDB.getHostManager().createHost(HOSTNAME2);
			assertEquals(host2_2.getName().equalsIgnoreCase(HOSTNAME2), true );
			
		}
		catch(Exception ex) {
			//transaction.commit();
		}
	
	}
	@Test
	public void osAccountRealmTests() throws TskCoreException {
		
		
		SleuthkitCase.CaseDbTransaction transaction = null;
		
		try {
		// TEST: create a domain realm 
		String realmName1 = "basis";
		OsAccountRealm domainRealm1 = caseDB.getOsAccountRealmManager().createRealmByName(realmName1, null);
		
		assertEquals(domainRealm1.getName().equalsIgnoreCase(realmName1), true );
		assertEquals(domainRealm1.getNameType(), OsAccountRealm.RealmNameType.EXPRESSED);
		assertEquals(domainRealm1.getRealmAddr().orElse(null), null);	// verify there is no realm addr
		
	
		
		String realmName2 = "win-raman-abcd";
		
		String realmAddr2SubAuth = "S-1-5-18-2033736216-1234567890";	
		String realmAddr2 = "S-1-5-18-2033736216-1234567890-5432109876";
		
		String hostName2 = "win-raman-abcd";
		
	
		//TEST: create a local realm with single host
		// first create a host
		Host host2 = caseDB.getHostManager().createHost(hostName2);
		// verify host name
		assertEquals(host2.getName().equalsIgnoreCase(hostName2), true);
		
		// create realm
		OsAccountRealm localRealm2 = caseDB.getOsAccountRealmManager().createRealmByWindowsSid(realmAddr2, host2);
		assertEquals(localRealm2.getRealmAddr().orElse("").equalsIgnoreCase(realmAddr2SubAuth), true );
		assertEquals(localRealm2.getHost().orElse(null).getName().equalsIgnoreCase(hostName2), true);
		
		
		
		// update the a realm name
		OsAccountRealm updatedRealm2 = caseDB.getOsAccountRealmManager().updateRealmName(localRealm2.getId(), realmName2, OsAccountRealm.RealmNameType.EXPRESSED);
		assertEquals(updatedRealm2.getRealmAddr().orElse("").equalsIgnoreCase(realmAddr2SubAuth), true );
		assertEquals(updatedRealm2.getName().equalsIgnoreCase(realmName2), true );
		
		
		
		// get an existing realm - new SID but same sub authority as previously created realm.
		String realmAddr3 = realmAddr2SubAuth + "-88888888";
		
		transaction = caseDB.beginTransaction();
		Optional<OsAccountRealm> existingRealm3 = caseDB.getOsAccountRealmManager().getRealmByWindowsSid(realmAddr3, null, transaction);
		assertEquals(existingRealm3.isPresent(), true);
		assertEquals(existingRealm3.get().getRealmAddr().orElse("").equalsIgnoreCase(realmAddr2SubAuth), true );
		assertEquals(existingRealm3.get().getName().equalsIgnoreCase(realmName2), true );
		
		transaction.commit(); // faux commit
		
		}
		finally {
//			if (transaction != null) {
//				transaction.commit();
//			}
		}
		
		
	}
	
	@Test
	public void basicOsAccountTests() throws TskCoreException {

		SleuthkitCase.CaseDbTransaction transaction = null;

		try {
			String ownerUid1 = "S-1-5-32-544";
			String ownerUid2 = "S-1-5-21-725345543-854245398-1060284298-1003";
			String ownerUid3 = "S-1-5-21-725345543-854245398-1060284298-1004";
			
			
			String realmName1 = "Realm1";
			String realmName2 = "Realm2";
			
			Host host = null;
			
			// create account realms
			OsAccountRealm realm1 = caseDB.getOsAccountRealmManager().createRealmByName(realmName1, host);
			OsAccountRealm realm2 = caseDB.getOsAccountRealmManager().createRealmByName(realmName2, host);
			
			
			
			// create accounts
			OsAccount osAccount1 = caseDB.getOsAccountManager().createOsAccount(ownerUid1, null, realmName1, host);
			OsAccount osAccount2 = caseDB.getOsAccountManager().createOsAccount(ownerUid2, null, realmName2, host);
			OsAccount osAccount3 = caseDB.getOsAccountManager().createOsAccount(ownerUid3, null, realmName2, host);
				
		
			assertEquals(osAccount1.isAdmin(), false);
			assertEquals(osAccount1.getUniqueIdWithinRealm().orElse("").equalsIgnoreCase(ownerUid1), true);
			assertEquals(osAccount1.getRealm().getName().equalsIgnoreCase(realmName1), true);
			
			
			
			
			transaction = caseDB.beginTransaction(); // RAMAN TBD - does update need a transaction
			
			// Let's update osAccount1
			String fullName1 = "Johnny Depp";
			long creationTime1 = 1611858618;
			osAccount1.setCreationTime(creationTime1);
			osAccount1.setFullName(fullName1);
			osAccount1.setIsAdmin(true);
			
			osAccount1 = caseDB.getOsAccountManager().updateAccount(osAccount1, transaction);
			
			assertEquals(osAccount1.getCreationTime(), creationTime1);
			
			
			transaction.commit();
			transaction = null;
			
			transaction = caseDB.beginTransaction(); // RAMAN TBD
			
			
			
			// now try and create osAccount1 again - it should return the existing account
			OsAccount osAccount1_copy1 = caseDB.getOsAccountManager().createOsAccount(ownerUid1, null, realmName1, host);
			
			
			assertEquals(osAccount1_copy1.getUniqueIdWithinRealm().orElse("").equalsIgnoreCase(ownerUid1), true);
			assertEquals(osAccount1_copy1.getRealm().getName().equalsIgnoreCase(realmName1), true);
			
			
			assertEquals(osAccount1_copy1.isAdmin(), true); // should be true now
			assertEquals(osAccount1_copy1.getFullName().orElse("").equalsIgnoreCase(fullName1), true);
			assertEquals(osAccount1_copy1.getCreationTime(), creationTime1);
			
		}
		
		finally {
			if (transaction != null) {
				transaction.commit();
			}
		}

	}
}
