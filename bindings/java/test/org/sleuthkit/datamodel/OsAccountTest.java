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
import java.util.Collections;
import java.util.Optional;
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
	public void hostTests() throws TskCoreException {
		
		try {
			String HOSTNAME1 = "host11";
			
			// Test: create a host
			Host host1 = caseDB.getHostManager().createHost(HOSTNAME1);
			assertEquals(host1.getName().equalsIgnoreCase(HOSTNAME1), true );
			
			
			// Test: get a host we just created.
			Optional<Host> optionalhost1 = caseDB.getHostManager().getHost(HOSTNAME1);
			assertEquals(optionalhost1.isPresent(), true );
			
			
			String HOSTNAME2 = "host22";
			
			// Get a host not yet created
			Optional<Host> optionalhost2 = caseDB.getHostManager().getHost(HOSTNAME2);
			assertEquals(optionalhost2.isPresent(), false );
			
			
			// now create the second host
			Host host2 = caseDB.getHostManager().createHost(HOSTNAME2);
			assertEquals(host2.getName().equalsIgnoreCase(HOSTNAME2), true );
			
			
			// now get it again, should be found this time
			optionalhost2 = caseDB.getHostManager().getHost(HOSTNAME2);
			assertEquals(optionalhost2.isPresent(), true);
			
			// create a host that already exists - should transperently return the existting host.
			Host host2_2 = caseDB.getHostManager().createHost(HOSTNAME2);
			assertEquals(host2_2.getName().equalsIgnoreCase(HOSTNAME2), true );
			
		}
		catch(Exception ex) {
			
		}
	
	}
	@Test
	public void osAccountRealmTests() throws TskCoreException {
		
		try {
		// TEST: create a DOMAIN realm 
		
		String HOSTNAME1 = "host1";
		Host host1 = caseDB.getHostManager().createHost(HOSTNAME1);
			
		String realmName1 = "basis";
		String realmSID1 =  "S-1-5-18-1111111111-2222222222-3333333333";
		String realmAddr1 = "S-1-5-18-1111111111-2222222222";	
		
		OsAccountRealm domainRealm1 = caseDB.getOsAccountRealmManager().createWindowsRealm(realmSID1, realmName1, host1, OsAccountRealm.RealmScope.DOMAIN);
		
		assertEquals(domainRealm1.getRealmName().orElse("").equalsIgnoreCase(realmName1), true );
		assertEquals(domainRealm1.getScopeConfidence(), OsAccountRealm.ScopeConfidence.KNOWN);
		assertEquals(domainRealm1.getRealmAddr().orElse(null), realmAddr1); 
		
	
		//TEST: create a new LOCAL realm with a single host
		String realmSID2 = "S-1-5-18-2033736216-1234567890-5432109876";
		String realmAddr2 = "S-1-5-18-2033736216-1234567890";	
		String realmName2 = "win-raman-abcd";
		String hostName2 = "host2";
		
		Host host2 = caseDB.getHostManager().createHost(hostName2);
		OsAccountRealm localRealm2 = caseDB.getOsAccountRealmManager().createWindowsRealm(realmSID2, null, host2, OsAccountRealm.RealmScope.LOCAL);
		assertEquals(localRealm2.getRealmAddr().orElse("").equalsIgnoreCase(realmAddr2), true );
		assertEquals(localRealm2.getScopeHost().orElse(null).getName().equalsIgnoreCase(hostName2), true);
		
		// update the a realm name on a existing realm.
		OsAccountRealm updatedRealm2 = caseDB.getOsAccountRealmManager().updateRealmName(localRealm2.getId(), realmName2, OsAccountRealm.ScopeConfidence.KNOWN);
		assertEquals(updatedRealm2.getRealmAddr().orElse("").equalsIgnoreCase(realmAddr2), true );
		assertEquals(updatedRealm2.getRealmName().orElse("").equalsIgnoreCase(realmName2), true );
		
		
		
		// TEST get an existing DOMAIN realm - new SID  on a new host but same sub authority as previously created realm
		String realmSID3 = realmAddr1 + "-88888888";
		
		String hostName3 = "host3";
		Host host3 = caseDB.getHostManager().createHost(hostName3);
		
		// expect this to return realm1
		Optional<OsAccountRealm> existingRealm3 = caseDB.getOsAccountRealmManager().getWindowsRealm(realmSID3, null, host3); 
		assertEquals(existingRealm3.isPresent(), true);
		assertEquals(existingRealm3.get().getRealmAddr().orElse("").equalsIgnoreCase(realmAddr1), true );
		assertEquals(existingRealm3.get().getRealmName().orElse("").equalsIgnoreCase(realmName1), true );
		
		
		// TEST get a existing LOCAL realm by addr, BUT on a new referring host.
		String hostName4 = "host4";
		Host host4 = caseDB.getHostManager().createHost(hostName4);
		
		// Although the realm exists with this addr, it should  NOT match since the host is different from what the realm was created with
		Optional<OsAccountRealm> realm4 = caseDB.getOsAccountRealmManager().getWindowsRealm(realmSID2, null, host4);
		
		assertEquals(realm4.isPresent(), false);
				
		}
		finally {

		}
		
		
	}
	
	@Test
	public void basicOsAccountTests() throws TskCoreException {

		try {
			//String ownerUid1 = "S-1-5-32-544"; // special short SIDS not handled yet
			
			// Create an account in a local scoped realm.
			
			String ownerUid1 = "S-1-5-32-111111111-222222222-3333333333-0001";
			String realmName1 = "realm1";
			
			String hostname1 = "host1";
			Host host1 = caseDB.getHostManager().createHost(hostname1);
			
			OsAccountRealm localRealm1 = caseDB.getOsAccountRealmManager().createWindowsRealm(ownerUid1, realmName1, host1, OsAccountRealm.RealmScope.LOCAL);
			OsAccount osAccount1 = caseDB.getOsAccountManager().createWindowsAccount(ownerUid1, null, realmName1, host1, OsAccountRealm.RealmScope.LOCAL);
			
			assertEquals(osAccount1.isAdmin(), false);
			assertEquals(osAccount1.getUniqueIdWithinRealm().orElse("").equalsIgnoreCase(ownerUid1), true);
			assertEquals(osAccount1.getRealm().getRealmName().orElse("").equalsIgnoreCase(realmName1), true);
			
			
			// Let's update osAccount1
			String fullName1 = "Johnny Depp";
			Long creationTime1 = 1611858618L;
			osAccount1.setCreationTime(creationTime1);
			osAccount1.setFullName(fullName1);
			osAccount1.setIsAdmin(true);
			
			osAccount1 = osAccount1.update();
			assertEquals(osAccount1.getCreationTime().orElse(null), creationTime1);
			assertEquals(osAccount1.getFullName().orElse(null).equalsIgnoreCase(fullName1), true );
			
			
			// now try and create osAccount1 again - it should return the existing account
			OsAccount osAccount1_copy1 = caseDB.getOsAccountManager().createWindowsAccount(ownerUid1, null, realmName1, host1, OsAccountRealm.RealmScope.LOCAL);
			
			
			assertEquals(osAccount1_copy1.getUniqueIdWithinRealm().orElse("").equalsIgnoreCase(ownerUid1), true);
			assertEquals(osAccount1_copy1.getRealm().getRealmName().orElse("").equalsIgnoreCase(realmName1), true);
			
			
			assertEquals(osAccount1_copy1.isAdmin(), true); // should be true now
			assertEquals(osAccount1_copy1.getFullName().orElse("").equalsIgnoreCase(fullName1), true);
			assertEquals(osAccount1.getCreationTime().orElse(null), creationTime1);
			
			
			// Create two new accounts on a new domain realm
			String ownerUid2 = "S-1-5-21-725345543-854245398-1060284298-1003";
			String ownerUid3 = "S-1-5-21-725345543-854245398-1060284298-1004";
	
			String realmName2 = "basis";
			
			String hostname2 = "host2";
			String hostname3 = "host3";
			Host host2 = caseDB.getHostManager().createHost(hostname2);
			Host host3 = caseDB.getHostManager().createHost(hostname3);
		
			OsAccountRealm domainRealm1 = caseDB.getOsAccountRealmManager().createWindowsRealm(ownerUid2, realmName2, host2, OsAccountRealm.RealmScope.DOMAIN);
		
			// create accounts in this domain scoped realm
			OsAccount osAccount2 = caseDB.getOsAccountManager().createWindowsAccount(ownerUid2, null, realmName2, host2, OsAccountRealm.RealmScope.DOMAIN);
			OsAccount osAccount3 = caseDB.getOsAccountManager().createWindowsAccount(ownerUid3, null, realmName2, host3, OsAccountRealm.RealmScope.DOMAIN);
			
			assertEquals(osAccount2.isAdmin(), false);
			assertEquals(osAccount2.getUniqueIdWithinRealm().orElse("").equalsIgnoreCase(ownerUid2), true);
			assertEquals(osAccount2.getRealm().getRealmName().orElse("").equalsIgnoreCase(realmName2), true);
			
			
			assertEquals(osAccount3.isAdmin(), false);
			assertEquals(osAccount3.getUniqueIdWithinRealm().orElse("").equalsIgnoreCase(ownerUid3), true);
			assertEquals(osAccount3.getRealm().getRealmName().orElse("").equalsIgnoreCase(realmName2), true);
			
		}
		
		finally {
			
		}

	}
}
