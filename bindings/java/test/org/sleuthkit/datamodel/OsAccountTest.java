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
import java.util.stream.Collectors;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.sleuthkit.datamodel.OsAccount.OsAccountAttribute;
import org.sleuthkit.datamodel.OsAccountManager.OsAccountUpdateResult;
import org.sleuthkit.datamodel.OsAccountRealmManager.OsRealmUpdateResult;

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
	
	private static Image image;
	
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

			image = caseDB.addImage(TskData.TSK_IMG_TYPE_ENUM.TSK_IMG_TYPE_DETECT, 512, 1024, "", Collections.emptyList(), "America/NewYork", null, null, null, "first", trans);

			fs = caseDB.addFileSystem(image.getId(), 0, TskData.TSK_FS_TYPE_ENUM.TSK_FS_TYPE_RAW, 0, 0, 0, 0, 0, "", trans);

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
			Host host1 = caseDB.getHostManager().newHost(HOSTNAME1);
			assertEquals(host1.getName().equalsIgnoreCase(HOSTNAME1), true );
			
			
			// Test: get a host we just created.
			Optional<Host> optionalhost1 = caseDB.getHostManager().getHostByName(HOSTNAME1);
			assertEquals(optionalhost1.isPresent(), true );
			
			
			String HOSTNAME2 = "host22";
			
			// Get a host not yet created
			Optional<Host> optionalhost2 = caseDB.getHostManager().getHostByName(HOSTNAME2);
			assertEquals(optionalhost2.isPresent(), false );
			
			
			// now create the second host
			Host host2 = caseDB.getHostManager().newHost(HOSTNAME2);
			assertEquals(host2.getName().equalsIgnoreCase(HOSTNAME2), true );
			
			
			// now get it again, should be found this time
			optionalhost2 = caseDB.getHostManager().getHostByName(HOSTNAME2);
			assertEquals(optionalhost2.isPresent(), true);
			
			// create a host that already exists - should transperently return the existting host.
			Host host2_2 = caseDB.getHostManager().newHost(HOSTNAME2);
			assertEquals(host2_2.getName().equalsIgnoreCase(HOSTNAME2), true );
			
		}
		catch(Exception ex) {
			
		}
	
	}
	
	@Test 
	public void personTests() throws TskCoreException {
		String personName1 = "John Doe";
		String personName2 = "Jane Doe";
		
		org.sleuthkit.datamodel.PersonManager pm = caseDB.getPersonManager();
		
		Person p1 = pm.newPerson(personName1);
		assertEquals(personName1.equals(p1.getName()), true);
		
		Optional<Person> p1opt = pm.getPerson(personName1.toLowerCase());
		assertEquals(p1opt.isPresent(), true);
		
		p1.setName(personName2);
		assertEquals(personName2.equals(p1.getName()), true);
		
		pm.updatePerson(p1);
		Optional<Person> p2opt = pm.getPerson(personName2.toUpperCase());
		assertEquals(p2opt.isPresent(), true);
		
		pm.deletePerson(p1.getName());
		p2opt = pm.getPerson(personName2);
		assertEquals(p2opt.isPresent(), false);
	}
		
	@Test
	public void mergeHostTests() throws TskCoreException, OsAccountManager.NotUserSIDException {
		
		// Host 1 will be merged into Host 2
		String host1Name = "host1forHostMergeTest";
		String host2Name = "host2forHostMergeTest";
		Host host1 = caseDB.getHostManager().newHost(host1Name);
		Host host2 = caseDB.getHostManager().newHost(host2Name);
		
		// Data source is originally associated with host1
		org.sleuthkit.datamodel.SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		DataSource ds = caseDB.addLocalFilesDataSource("devId", "pathToFiles", "EST", host1, trans);
		trans.commit();
        
		String sid3 = "S-1-5-27-777777777-854245398-1060284298-7777";
		String sid4 = "S-1-5-27-788888888-854245398-1060284298-8888";
		String sid5 = "S-1-5-27-799999999-854245398-1060284298-9999";
		String sid6 = "S-1-5-27-711111111-854245398-1060284298-1111";
		String sid7 = "S-1-5-27-733333333-854245398-1060284298-3333";
		String sid8 = "S-1-5-27-744444444-854245398-1060284298-4444";
		
		String realmName1 = "hostMergeRealm1";
		String realmName2 = "hostMergeRealm2";
		String realmName4 = "hostMergeRealm4";
		String realmName5 = "hostMergeRealm5";
		String realmName6 = "hostMergeRealm6";
		String realmName7 = "hostMergeRealm7";
		String realmName8 = "hostMergeRealm8";
		
		String realm8AcctName = "hostMergeUniqueRealm8Account";
		String realm10AcctName = "hostMergeUniqueRealm10Account";
		
		// Save the created realms/accounts so we can query them later by object ID (the objects themselves will end up out-of-date)
		OsAccountRealmManager realmManager = caseDB.getOsAccountRealmManager();
		
		// 1 - Should get moved
		OsAccountRealm realm1 = realmManager.newWindowsRealm(null, realmName1, host1, OsAccountRealm.RealmScope.LOCAL);
		
		// 2 - Should be merged into 5
		OsAccountRealm realm2 = realmManager.newWindowsRealm(null, realmName2, host1, OsAccountRealm.RealmScope.LOCAL);
		
		// 3 - Should be merged into 5
		OsAccountRealm realm3 = realmManager.newWindowsRealm(sid3, null, host1, OsAccountRealm.RealmScope.LOCAL); 
		
		// 4 - Should get moved - not merged into 6 since addrs are different
		OsAccountRealm realm4 = realmManager.newWindowsRealm(sid4, realmName4, host1, OsAccountRealm.RealmScope.LOCAL); 

		// 5 - 2 and 3 should get merged in
		OsAccountRealm realm5 = realmManager.newWindowsRealm(sid3, realmName2, host2, OsAccountRealm.RealmScope.LOCAL);

		// 6 - Should not get merged with 4
		OsAccountRealm realm6 = realmManager.newWindowsRealm(sid5, realmName4, host2, OsAccountRealm.RealmScope.LOCAL);

		// 7 - Should be unchanged
		OsAccountRealm realm7 = realmManager.newWindowsRealm(null, realmName5, host2, OsAccountRealm.RealmScope.LOCAL);

		// 8, 9, 10 - 8 should be merged into 9 and then 10 should be merged into 9
		OsAccountRealm realm8 = realmManager.newWindowsRealm(null, realmName6, host2, OsAccountRealm.RealmScope.LOCAL); 
		OsAccount realm8acct = caseDB.getOsAccountManager().newWindowsOsAccount(null, realm8AcctName, realmName6, host2, OsAccountRealm.RealmScope.LOCAL);
		OsAccountRealm realm9 = realmManager.newWindowsRealm(sid6, null, host2, OsAccountRealm.RealmScope.LOCAL);
		OsAccountRealm realm10 = realmManager.newWindowsRealm(sid6, realmName6, host1, OsAccountRealm.RealmScope.LOCAL);
		OsAccount realm10acct = caseDB.getOsAccountManager().newWindowsOsAccount(null, realm10AcctName, realmName6, host1, OsAccountRealm.RealmScope.LOCAL);

		// 11, 12 - 11 should get merged into 12, adding the addr "sid8" to 12
		OsAccountRealm realm11 = realmManager.newWindowsRealm(sid8, realmName7, host1, OsAccountRealm.RealmScope.LOCAL);
		OsAccountRealm realm12 = realmManager.newWindowsRealm(null, realmName7, host2, OsAccountRealm.RealmScope.LOCAL);

		// 13,14 - 13 should get merged into 14, name for 14 should not change
		OsAccountRealm realm13 = realmManager.newWindowsRealm(sid7, "notRealm8", host1, OsAccountRealm.RealmScope.LOCAL);
		OsAccountRealm realm14 = realmManager.newWindowsRealm(sid7, realmName8, host2, OsAccountRealm.RealmScope.LOCAL);
		
		// Do the merge
		caseDB.getHostManager().mergeHosts(host1, host2);
		
		// Test the realms
		try (org.sleuthkit.datamodel.SleuthkitCase.CaseDbConnection connection = caseDB.getConnection()) {
			// Expected change: host is now host2
			testUpdatedRealm(realm1, OsAccountRealm.RealmDbStatus.ACTIVE, realm1.getRealmAddr(), realm1.getRealmNames(), Optional.of(host2), connection);
			
			// Expected change: should be marked as merged
			testUpdatedRealm(realm2, OsAccountRealm.RealmDbStatus.MERGED, null, null, null, connection);
			
			// Expected change: should be marked as merged
			testUpdatedRealm(realm3, OsAccountRealm.RealmDbStatus.MERGED, null, null, null, connection);
			
			// Expected change: should still be active and be moved to host2
			testUpdatedRealm(realm4, OsAccountRealm.RealmDbStatus.ACTIVE, realm4.getRealmAddr(), realm4.getRealmNames(), Optional.of(host2), connection);
			
			// Expected change: nothing
			testUpdatedRealm(realm7, realm7.getDbStatus(), realm7.getRealmAddr(), realm7.getRealmNames(), realm7.getScopeHost(), connection);
			
			// Expected change: should be marked as merged
			testUpdatedRealm(realm8, OsAccountRealm.RealmDbStatus.MERGED, null, null, null, connection);
			
			// Expected change: should have gained the name of realm 8
			testUpdatedRealm(realm9, OsAccountRealm.RealmDbStatus.ACTIVE, realm9.getRealmAddr(), realm8.getRealmNames(), realm9.getScopeHost(), connection);
			
			// Expected change: should have gained the addr of realm 11
			testUpdatedRealm(realm12, OsAccountRealm.RealmDbStatus.ACTIVE, realm11.getRealmAddr(), realm12.getRealmNames(), Optional.of(host2), connection);
			
			// "notRealm8" should not return any hits for either host (realm13 is marked as merged and the name was not copied to realm14)
			Optional<OsAccountRealm> optRealm = realmManager.getRealmByName("notRealm8", host1, connection);
			assertEquals(optRealm.isPresent(), false);
			optRealm = realmManager.getRealmByName("notRealm8", host2, connection);
			assertEquals(optRealm.isPresent(), false);
			
			// The realm8 and realm10 accounts should both be in realm9 now
			OsAccount acct = caseDB.getOsAccountManager().getOsAccountByObjectId(realm8acct.getId(), connection);
			assertEquals(acct.getRealmId() == realm9.getRealmId(), true);
			acct = caseDB.getOsAccountManager().getOsAccountByObjectId(realm10acct.getId(), connection);
			assertEquals(acct.getRealmId() == realm9.getRealmId(), true);
		}
			
		// The data source should now reference host2
		Host host = caseDB.getHostManager().getHostByDataSource(ds);
		assertEquals(host.getHostId() == host2.getHostId(), true);

		// We should get no results on a search for host1
		Optional<Host> optHost = caseDB.getHostManager().getHostByName(host1Name);
		assertEquals(optHost.isPresent(), false);
		
		// If we attempt to make a new host with the same name host1 had, we should get a new object Id
		host = caseDB.getHostManager().newHost(host1Name);
		assertEquals(host.getHostId() != host1.getHostId(), true);
	}
	
	/**
	 * Retrieve the new version of a realm from the database and compare with expected values.
	 * Addr, name, and host can be passed in as null to skip comparison.
	 */
	private void testUpdatedRealm(OsAccountRealm origRealm, OsAccountRealm.RealmDbStatus expectedStatus, Optional<String> expectedAddr,
			List<String> expectedNames, Optional<Host> expectedHost, org.sleuthkit.datamodel.SleuthkitCase.CaseDbConnection connection) throws TskCoreException {
		
		OsAccountRealm realm = caseDB.getOsAccountRealmManager().getRealmByRealmId(origRealm.getRealmId(), connection);
		assertEquals(realm.getDbStatus().equals(expectedStatus), true);	
		if (expectedAddr != null) {
			assertEquals(realm.getRealmAddr().equals(expectedAddr), true);
		}
		if(expectedNames != null && !expectedNames.isEmpty()){
			assertEquals(realm.getRealmNames().get(0).equals(expectedNames.get(0)), true);
		}
		if (expectedHost != null) {
			assertEquals(realm.getScopeHost().equals(expectedHost), true);
		}
	}
	
	
	@Test 
	public void mergeRealmsTests() throws TskCoreException, OsAccountManager.NotUserSIDException {
		Host host = caseDB.getHostManager().newHost("mergeTestHost");
		
		String destRealmName = "mergeTestDestRealm";
		String srcRealmName = "mergeTestSourceRealm";
		
		String sid1 = "S-1-5-21-222222222-222222222-1060284298-2222";
        String sid2 = "S-1-5-21-555555555-555555555-1060284298-5555";   
		
		String uniqueRealm2Name = "uniqueRealm2Account";
		String matchingName = "matchingNameAccount";
		String fullName1 = "FullName1";
		long creationTime1 = 555;
		
		OsAccountRealm srcRealm = caseDB.getOsAccountRealmManager().newWindowsRealm(null, srcRealmName, host, OsAccountRealm.RealmScope.LOCAL);
		OsAccountRealm destRealm = caseDB.getOsAccountRealmManager().newWindowsRealm(null, destRealmName, host, OsAccountRealm.RealmScope.LOCAL);
		
		OsAccount account1 = caseDB.getOsAccountManager().newWindowsOsAccount(null, "uniqueRealm1Account", destRealmName, host, OsAccountRealm.RealmScope.LOCAL);
		OsAccount account2 = caseDB.getOsAccountManager().newWindowsOsAccount(null, matchingName, destRealmName, host, OsAccountRealm.RealmScope.LOCAL);
		OsAccount account3 = caseDB.getOsAccountManager().newWindowsOsAccount(null, uniqueRealm2Name, srcRealmName, host, OsAccountRealm.RealmScope.LOCAL);
		OsAccount account4 = caseDB.getOsAccountManager().newWindowsOsAccount(null, matchingName, srcRealmName, host, OsAccountRealm.RealmScope.LOCAL);
		
		
		OsAccountUpdateResult updateResult =  caseDB.getOsAccountManager().updateStandardOsAccountAttributes(account4, fullName1, null, null, creationTime1);
		assertEquals(updateResult.getUpdateStatusCode(), OsAccountManager.OsAccountUpdateStatus.UPDATED);
		assertEquals(updateResult.getUpdatedAccount().isPresent(), true);
		account4 = updateResult.getUpdatedAccount().orElseThrow(() ->  new TskCoreException("Updated account not found."));
		
		
		OsAccount account5 = caseDB.getOsAccountManager().newWindowsOsAccount(sid1, null, destRealmName, host, OsAccountRealm.RealmScope.LOCAL);
		OsAccount account6 = caseDB.getOsAccountManager().newWindowsOsAccount(sid1, null, srcRealmName, host, OsAccountRealm.RealmScope.LOCAL);  
		OsAccount account7 = caseDB.getOsAccountManager().newWindowsOsAccount(sid2, null, destRealmName, host, OsAccountRealm.RealmScope.LOCAL);
		OsAccount account8 = caseDB.getOsAccountManager().newWindowsOsAccount(null, "nameForCombining", destRealmName, host, OsAccountRealm.RealmScope.LOCAL);
		OsAccount account9 = caseDB.getOsAccountManager().newWindowsOsAccount(sid2, "nameForCombining", srcRealmName, host, OsAccountRealm.RealmScope.LOCAL);
		
		// Test that we can currently get the source realm by name
		Optional<OsAccountRealm> optRealm = caseDB.getOsAccountRealmManager().getWindowsRealm(null, srcRealmName, host);
		assertEquals(optRealm.isPresent(), true);
		
		// Test that there is only one account associated with sid1
		List<OsAccount> accounts = caseDB.getOsAccountManager().getOsAccounts().stream().filter(p -> p.getAddr().isPresent() && p.getAddr().get().equals(sid1)).collect(Collectors.toList());
		assertEquals(accounts.size() == 1, true);
		
		// Expected results of the merge:
		// - account 4 will be merged into account 2 (and extra fields should be copied)
		// - account 6 will be merged into account 5
		// - account 8 will be merged into account 7 (due to account 9 containing matches for both)
		// - account 9 will be merged into account 7
		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		caseDB.getOsAccountRealmManager().mergeRealms(srcRealm, destRealm, trans);
		trans.commit();
		
		// Test that the source realm is no longer returned by a search by name
		optRealm = caseDB.getOsAccountRealmManager().getWindowsRealm(null, srcRealmName, host);
		assertEquals(optRealm.isPresent(), false);
		
		// Test that there is now only one account associated with sid1
		accounts = caseDB.getOsAccountManager().getOsAccounts().stream().filter(p -> p.getAddr().isPresent() && p.getAddr().get().equals(sid1)).collect(Collectors.toList());
		assertEquals(accounts.size() == 1, true);
		
		// Test that account 3 got moved into the destination realm. Tests are currently windows specific
		Optional<OsAccount> optAcct = caseDB.getOsAccountManager().getWindowsOsAccount(null,uniqueRealm2Name, destRealmName, host);
		assertEquals(optAcct.isPresent(), true);
		
		// Test that data from account 4 was merged into account 2. Tests are currently windows specific
		optAcct = caseDB.getOsAccountManager().getWindowsOsAccount(null, matchingName, destRealmName, host);
		assertEquals(optAcct.isPresent(), true);
		if (optAcct.isPresent()) {
			assertEquals(optAcct.get().getCreationTime().isPresent() &&  optAcct.get().getCreationTime().get() == creationTime1, true);
			assertEquals(optAcct.get().getFullName().isPresent() && fullName1.equalsIgnoreCase(optAcct.get().getFullName().get()), true);
		}
	}
	
	@Test 
	public void updateRealmAndMergeTests() throws TskCoreException, OsAccountManager.NotUserSIDException {
		
		/**
		 * Test the scenario where an update of an account triggers an update of 
		 * a realm and subsequent merge of realms and accounts.
		 */
		
		Host host = caseDB.getHostManager().newHost("updateRealmAndMergeTestHost");
		
		
		
			// Step 1: create a local account with SID and user name
			String ownerUid1 = "S-1-5-21-1182664808-117526782-2525957323-13395";
			String realmName1 = null;
			String loginName1 = "sandip";
			
			OsAccount osAccount1 = caseDB.getOsAccountManager().newWindowsOsAccount(ownerUid1, loginName1, realmName1, host, OsAccountRealm.RealmScope.LOCAL);
			OsAccountRealm realm1 = caseDB.getOsAccountRealmManager().getRealmByRealmId(osAccount1.getRealmId());
			
			assertEquals(realm1.getRealmAddr().isPresent(), true);	// verify the realm has a SID
			assertEquals(realm1.getRealmNames().isEmpty(), true);	// verify the realm has no name
			
			
			// Step2: create a local account with domain name and username
			String ownerUid2 = null;
			String realmName2 = "CORP";
			String loginName2 = "sandip";
			
			Optional<OsAccount> oOsAccount2 = caseDB.getOsAccountManager().getWindowsOsAccount(ownerUid2, loginName2, realmName2, host);
			
			// this account should not exists
			assertEquals(oOsAccount2.isPresent(), false);
			
			// create a new account -  a new realm as there is nothing to tie it to realm1 
			OsAccount osAccount2 = caseDB.getOsAccountManager().newWindowsOsAccount(ownerUid2, loginName2, realmName2, host, OsAccountRealm.RealmScope.LOCAL);
			OsAccountRealm realm2 = caseDB.getOsAccountRealmManager().getRealmByRealmId(osAccount2.getRealmId());
			
			assertTrue(osAccount1.getId() != osAccount2.getId());
			assertTrue(realm1.getRealmId() != realm2.getRealmId());
			
			
			
			// Step 3: now create/update the account with sid/domain/username
			// this should return the existing account1, which needs to be updated.
			String ownerUid3 = "S-1-5-21-1182664808-117526782-2525957323-13395";
			String realmAddr3 = "S-1-5-21-1182664808-117526782-2525957323";
			String loginName3 = "sandip";
			String realmName3 = "CORP";
			
			Optional<OsAccount> oOsAccount3 = caseDB.getOsAccountManager().getWindowsOsAccount(ownerUid3, loginName3, realmName3, host);

			assertTrue(oOsAccount3.isPresent());
			
            
			// update the account so that its domain gets updated.
			OsAccountManager.OsAccountUpdateResult updateResult = caseDB.getOsAccountManager().updateCoreWindowsOsAccountAttributes(oOsAccount3.get(), ownerUid3, loginName3, realmName3, host);
			Optional<OsAccount> updatedAccount3 = updateResult.getUpdatedAccount();
			assertTrue(updatedAccount3.isPresent());

			// this should cause the realm1 to be updated - and then realm2 to be merged into realm1 
			OsAccountRealm realm3 = caseDB.getOsAccountRealmManager().getRealmByRealmId(updatedAccount3.get().getRealmId());

			assertTrue(realm3.getRealmId() == realm1.getRealmId());

			assertTrue(realm3.getRealmAddr().isPresent());		// verify the realm gets an addr
			assertTrue(realm3.getRealmAddr().get().equalsIgnoreCase(realmAddr3));
			
			assertTrue(realm3.getRealmNames().get(0).equalsIgnoreCase(realmName3));	// verify realm name.


			// And now verify that the realm2 has been merged into realm1. 
			OsAccountRealm realm22 = caseDB.getOsAccountRealmManager().getRealmByRealmId(osAccount2.getRealmId());
			assertTrue(realm22.getDbStatus() == OsAccountRealm.RealmDbStatus.MERGED);

			//and account2 has been merged into account1
			OsAccount osAccount22 = caseDB.getOsAccountManager().getOsAccountByObjectId(osAccount2.getId());
			assertTrue(osAccount22.getOsAccountDbStatus() == OsAccount.OsAccountDbStatus.MERGED);
				
	}

	@Test
	public void updateRealmSameNameTests() throws TskCoreException, OsAccountManager.NotUserSIDException {

		/**
		 * Test the scenario where an update of an account triggers an update of
		 * a realm.
		 * 
		 * This test case has two realms with same name but different addr
		 */
		Host host = caseDB.getHostManager().newHost("updateRealmSameNameTests");

		// Step 1: create an account
		String ownerUid1 = "S-1-5-21-1182664808-117526782-2525957323-13395";
		String realmName1 = "CORP";
		String loginName1 = "sandip";

		OsAccount osAccount1 = caseDB.getOsAccountManager().newWindowsOsAccount(ownerUid1, loginName1, realmName1, host, OsAccountRealm.RealmScope.LOCAL);
		OsAccountRealm realm1 = caseDB.getOsAccountRealmManager().getRealmByRealmId(osAccount1.getRealmId());

		// Step 2: create another account with same username but different SID
		String ownerUid2 = "S-1-5-21-1182664808-117526782-2525957324-13396";
		String realmName2 = null;
		String loginName2 = "sandip";
		
		Optional<OsAccount> oOsAccount2 = caseDB.getOsAccountManager().getWindowsOsAccount(ownerUid2, loginName2, realmName2, host);

		// this account should not exists
		assertEquals(false, oOsAccount2.isPresent());

		// create a new account -  a new realm as there is nothing to tie it to realm1 
		OsAccount osAccount2 = caseDB.getOsAccountManager().newWindowsOsAccount(ownerUid2, loginName2, realmName2, host, OsAccountRealm.RealmScope.LOCAL);
		OsAccountRealm realm2 = caseDB.getOsAccountRealmManager().getRealmByRealmId(osAccount2.getRealmId());

		assertTrue(osAccount1.getId() != osAccount2.getId());
		assertTrue(realm1.getRealmId() != realm2.getRealmId());

		// Step 3: now create/update the account with sid/domain/username
		// this should return the existing account2, which needs to be updated.
		String ownerUid3 = "S-1-5-21-1182664808-117526782-2525957324-13396";
		String realmAddr3 = "S-1-5-21-1182664808-117526782-2525957324";
		String loginName3 = "sandip";
		String realmName3 = "CORP";

		Optional<OsAccount> oOsAccount3 = caseDB.getOsAccountManager().getWindowsOsAccount(ownerUid3, loginName3, realmName3, host);

		assertTrue(oOsAccount3.isPresent());

		// update the account so that its domain gets updated.
		OsAccountManager.OsAccountUpdateResult updateResult = caseDB.getOsAccountManager().updateCoreWindowsOsAccountAttributes(oOsAccount3.get(), ownerUid3, loginName3, realmName3, host);
		Optional<OsAccount> updatedAccount3 = updateResult.getUpdatedAccount();
		assertTrue(updatedAccount3.isPresent());

		// this should not cause the realm1 to be updated - realm2 should not be merged into realm1 because the SID was different
		OsAccountRealm realm3 = caseDB.getOsAccountRealmManager().getRealmByRealmId(updatedAccount3.get().getRealmId());

		assertTrue(realm3.getRealmId() != realm1.getRealmId());
		assertTrue(realm3.getRealmId() == realm2.getRealmId());
		
		assertTrue(realm3.getRealmAddr().isPresent()); // verify the realm gets an addr
		assertTrue(realm3.getRealmAddr().get().equalsIgnoreCase(realmAddr3));

		assertTrue(realm3.getRealmNames().get(0).equalsIgnoreCase(realmName3));	// verify realm name.

		// And now verify that the realms have not been merged
		OsAccountRealm realm12 = caseDB.getOsAccountRealmManager().getRealmByRealmId(osAccount1.getRealmId());
		assertTrue(realm12.getDbStatus() != OsAccountRealm.RealmDbStatus.MERGED);
		OsAccountRealm realm22 = caseDB.getOsAccountRealmManager().getRealmByRealmId(osAccount2.getRealmId());
		assertTrue(realm22.getDbStatus() != OsAccountRealm.RealmDbStatus.MERGED);

		// And the accounts have not been merged 
		OsAccount osAccount12 = caseDB.getOsAccountManager().getOsAccountByObjectId(osAccount1.getId());
		OsAccount osAccount22 = caseDB.getOsAccountManager().getOsAccountByObjectId(osAccount2.getId());
		assertTrue(osAccount12.getOsAccountDbStatus() != OsAccount.OsAccountDbStatus.MERGED);
		assertTrue(osAccount22.getOsAccountDbStatus() != OsAccount.OsAccountDbStatus.MERGED);

	}
	
	@Test 
	public void hostAddressTests() throws TskCoreException {
		
		
		// lets add a file 
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

		// add another no attribute file to same folder
		FsContent _abcTextFile = caseDB.addFileSystemFile(dataSourceObjectId, fs.getId(), "abc.txt", 0, 0,
					TskData.TSK_FS_ATTR_TYPE_ENUM.TSK_FS_ATTR_TYPE_DEFAULT, 0, TskData.TSK_FS_NAME_FLAG_ENUM.ALLOC,
					(short) 0, 200, 0, 0, 0, 0, null, null, "Text/Plain", true, _windows, null, null, Collections.emptyList(), trans);
		
		trans.commit();
			
		
		
		String ipv4Str = "11.22.33.44";
		String ipv6Str = "2001:0db8:85a3:0000:0000:8a2e:0370:6666";
		String hostnameStr = "basis.com";
		
		// Test creation
		HostAddress ipv4addr = caseDB.getHostAddressManager().newHostAddress(HostAddress.HostAddressType.IPV4, ipv4Str);
		assertEquals(ipv4addr.getAddress().equalsIgnoreCase(ipv4Str), true);
		
		HostAddress addr2 = caseDB.getHostAddressManager().newHostAddress(HostAddress.HostAddressType.DNS_AUTO, ipv6Str);
		assertEquals(addr2.getAddress().equalsIgnoreCase(ipv6Str), true);
		assertEquals(HostAddress.HostAddressType.IPV6.equals(addr2.getAddressType()), true);
		
		HostAddress hostAddr = caseDB.getHostAddressManager().newHostAddress(HostAddress.HostAddressType.DNS_AUTO, hostnameStr);
		assertEquals(hostAddr.getAddress().equalsIgnoreCase(hostnameStr), true);
		assertEquals(HostAddress.HostAddressType.HOSTNAME.equals(hostAddr.getAddressType()), true);
		
		// Test some IPV6 addresses with zone/interface specifiers
		String ipv6WithZoneStr1 = "fe80::1ff:fe23:4567:890a%eth2";
		String ipv6WithZoneStr2 = "fe80::1ff:fe23:4567:890a%3";
		String ipv6WithZoneStr3 = "fe80::1ff:fe23:4567:890a%12345";
		String ipv6WithoutZoneStr = "fe80::1ff:fe23:4567:890a";
		
		HostAddress addr3 = caseDB.getHostAddressManager().newHostAddress(HostAddress.HostAddressType.DNS_AUTO, ipv6WithZoneStr1);
		assertEquals(addr3.getAddress().equalsIgnoreCase(ipv6WithoutZoneStr), true);
		assertEquals(HostAddress.HostAddressType.IPV6.equals(addr3.getAddressType()), true);
		
		HostAddress addr4 = caseDB.getHostAddressManager().newHostAddress(HostAddress.HostAddressType.DNS_AUTO, ipv6WithZoneStr2);
		assertEquals(addr4.getAddress().equalsIgnoreCase(ipv6WithoutZoneStr), true);
		assertEquals(HostAddress.HostAddressType.IPV6.equals(addr4.getAddressType()), true);
		
		
		// Test get
		Optional<HostAddress> addr4opt = caseDB.getHostAddressManager().getHostAddress(HostAddress.HostAddressType.IPV4, ipv4Str);
		assertEquals(addr4opt.isPresent(), true);
		
		
		// Test get on IPv6 Address with zone specifiers - they should all resolve to same address  - the one without the zone.
		addr4opt = caseDB.getHostAddressManager().getHostAddress(HostAddress.HostAddressType.DNS_AUTO, ipv6WithZoneStr1);
		assertEquals(addr4opt.isPresent(), true);
		
		addr4opt = caseDB.getHostAddressManager().getHostAddress(HostAddress.HostAddressType.DNS_AUTO, ipv6WithZoneStr2);
		assertEquals(addr4opt.isPresent(), true);
		
		addr4opt = caseDB.getHostAddressManager().getHostAddress(HostAddress.HostAddressType.DNS_AUTO, ipv6WithZoneStr3);
		assertEquals(addr4opt.isPresent(), true);
		
		addr4opt = caseDB.getHostAddressManager().getHostAddress(HostAddress.HostAddressType.DNS_AUTO, ipv6WithoutZoneStr);
		assertEquals(addr4opt.isPresent(), true);
				
		// Test host map
		Host host = caseDB.getHostManager().newHost("TestHostAddress");
		
		trans = caseDB.beginTransaction();
		DataSource ds = caseDB.addLocalFilesDataSource("devId", "pathToFiles", "EST", null, trans);
		trans.commit();
		
		caseDB.getHostAddressManager().assignHostToAddress(host, ipv4addr, (long) 0, ds);
		List<HostAddress> hostAddrs = caseDB.getHostAddressManager().getHostAddressesAssignedTo(host);
		assertEquals(hostAddrs.size() == 1, true);
		
		// Test IP mapping
		caseDB.getHostAddressManager().addHostNameAndIpMapping(hostAddr, ipv4addr, (long) 0, ds);
		List<HostAddress> ipForHostSet = caseDB.getHostAddressManager().getIpAddress(hostAddr.getAddress());
		assertEquals(ipForHostSet.size() == 1, true);
		List<HostAddress> hostForIpSet = caseDB.getHostAddressManager().getHostNameByIp(ipv4addr.getAddress());
		assertEquals(hostForIpSet.size() == 1, true);
		
		
		// add address usage
		caseDB.getHostAddressManager().addUsage(_abcTextFile, ipv4addr);
		caseDB.getHostAddressManager().addUsage(_abcTextFile, addr2);
		caseDB.getHostAddressManager().addUsage(_abcTextFile, hostAddr);
		
		//test get addressUsed methods
		List<HostAddress> addrUsedByAbc = caseDB.getHostAddressManager().getHostAddressesUsedByContent(_abcTextFile);
		assertEquals(addrUsedByAbc.size() == 3, true);
		
		List<HostAddress> addrUsedByRoot = caseDB.getHostAddressManager().getHostAddressesUsedByContent(_root);
		assertEquals(addrUsedByRoot.isEmpty(), true);
		
		List<HostAddress> addrUsedOnDataSource = caseDB.getHostAddressManager().getHostAddressesUsedOnDataSource(_root.getDataSource());
		assertEquals(addrUsedOnDataSource.size() == 3, true);
		
	}
	
	@Test
	public void osAccountRealmTests() throws TskCoreException, OsAccountManager.NotUserSIDException {
		
		try {
		// TEST: create a DOMAIN realm 
		
		String HOSTNAME1 = "host1";
		Host host1 = caseDB.getHostManager().newHost(HOSTNAME1);
			
		String realmName1 = "basis";
		String realmSID1 =  "S-1-5-21-1111111111-2222222222-3333333333";
		String realmAddr1 = "S-1-5-21-1111111111-2222222222";	
		
		OsAccountRealm domainRealm1 = caseDB.getOsAccountRealmManager().newWindowsRealm(realmSID1, realmName1, host1, OsAccountRealm.RealmScope.DOMAIN);
		
		assertEquals(domainRealm1.getRealmNames().get(0).equalsIgnoreCase(realmName1), true );
		assertEquals(domainRealm1.getScopeConfidence(), OsAccountRealm.ScopeConfidence.KNOWN);
		assertEquals(domainRealm1.getRealmAddr().orElse(null), realmAddr1); 
		
	
		//TEST: create a new LOCAL realm with a single host
		String realmSID2 = "S-1-5-18-2033736216-1234567890-5432109876";
		String realmAddr2 = "S-1-5-18-2033736216-1234567890";	
		String realmName2 = "win-raman-abcd";
		String hostName2 = "host2";
		
		Host host2 = caseDB.getHostManager().newHost(hostName2);
		OsAccountRealm localRealm2 = caseDB.getOsAccountRealmManager().newWindowsRealm(realmSID2, null, host2, OsAccountRealm.RealmScope.LOCAL);
		assertEquals(localRealm2.getRealmAddr().orElse("").equalsIgnoreCase(realmAddr2), true );
		assertEquals(localRealm2.getScopeHost().orElse(null).getName().equalsIgnoreCase(hostName2), true);
		
		// update the a realm name on a existing realm.
		OsRealmUpdateResult realmUpdateResult = caseDB.getOsAccountRealmManager().updateRealm(localRealm2, null, realmName2 );
		assertEquals(realmUpdateResult.getUpdateStatus(), OsAccountRealmManager.OsRealmUpdateStatus.UPDATED );
		assertTrue(realmUpdateResult.getUpdatedRealm().isPresent());
		
		OsAccountRealm updatedRealm2 = realmUpdateResult.getUpdatedRealm().get();
		assertTrue(updatedRealm2.getRealmAddr().orElse("").equalsIgnoreCase(realmAddr2));
		assertTrue(updatedRealm2.getRealmNames().get(0).equalsIgnoreCase(realmName2));
		
		
		
		// TEST get an existing DOMAIN realm - new SID  on a new host but same sub authority as previously created realm
		String realmSID3 = realmAddr1 + "-88888888";
		
		String hostName3 = "host3";
		Host host3 = caseDB.getHostManager().newHost(hostName3);
		
		// expect this to return realm1
		Optional<OsAccountRealm> existingRealm3 = caseDB.getOsAccountRealmManager().getWindowsRealm(realmSID3, null, host3); 
		assertEquals(existingRealm3.isPresent(), true);
		assertEquals(existingRealm3.get().getRealmAddr().orElse("").equalsIgnoreCase(realmAddr1), true );
		assertEquals(existingRealm3.get().getRealmNames().get(0).equalsIgnoreCase(realmName1), true );
		
		
		// TEST get a existing LOCAL realm by addr, BUT on a new referring host.
		String hostName4 = "host4";
		Host host4 = caseDB.getHostManager().newHost(hostName4);
		
		// Although the realm exists with this addr, it should  NOT match since the host is different from what the realm was created with
		Optional<OsAccountRealm> realm4 = caseDB.getOsAccountRealmManager().getWindowsRealm(realmSID2, null, host4);
		
		assertEquals(realm4.isPresent(), false);
				
		}
		finally {

		}
		
		
	}
	
	@Test
	public void basicOsAccountTests() throws TskCoreException, OsAccountManager.NotUserSIDException {

		try {
			//String ownerUid1 = "S-1-5-32-544"; // special short SIDS not handled yet
			
			// Create an account in a local scoped realm.
			
			String ownerUid1 = "S-1-5-21-111111111-222222222-3333333333-1001";
			String loginName1 = "jay";
			String realmName1 = "local";
			
			String hostname1 = "host1";
			Host host1 = caseDB.getHostManager().newHost(hostname1);
			
			//OsAccountRealm localRealm1 = caseDB.getOsAccountRealmManager().newWindowsRealm(ownerUid1, realmName1, host1, OsAccountRealm.RealmScope.LOCAL);
			OsAccount osAccount1 = caseDB.getOsAccountManager().newWindowsOsAccount(ownerUid1, loginName1, realmName1, host1, OsAccountRealm.RealmScope.LOCAL);
			
			assertEquals(osAccount1.getAddr().orElse("").equalsIgnoreCase(ownerUid1), true);
			assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(osAccount1.getRealmId()).getRealmNames().get(0).equalsIgnoreCase(realmName1), true);
			
			// Create another account - with same SID on the same host - should return the existing account
			String loginName11 = "BlueJay";
			String realmName11 = "DESKTOP-9TO5";
			OsAccount osAccount11 = caseDB.getOsAccountManager().newWindowsOsAccount(ownerUid1, loginName11, realmName11, host1, OsAccountRealm.RealmScope.DOMAIN);
			
			// account should be the same as osAccount1
			assertEquals(osAccount11.getAddr().orElse("").equalsIgnoreCase(ownerUid1), true);	
			assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(osAccount11.getRealmId()).getRealmNames().get(0).equalsIgnoreCase(realmName1), true);
			assertEquals(osAccount11.getLoginName().orElse("").equalsIgnoreCase(loginName1), true);	
			
			
			// try and get the account with null sid & login name.  It should use the login name to find the account
			Optional<OsAccount> osAccount21 =  caseDB.getOsAccountManager().getWindowsOsAccount("S-1-0-0", loginName1, realmName1, host1);
			
			assertTrue(osAccount21.isPresent());
			assertEquals(osAccount21.get().getAddr().orElse("").equalsIgnoreCase(ownerUid1), true);	
			assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(osAccount21.get().getRealmId()).getRealmNames().get(0).equalsIgnoreCase(realmName1), true);
			assertEquals(osAccount21.get().getLoginName().orElse("").equalsIgnoreCase(loginName1), true);	
			
			
			// Let's update osAccount1
			String fullName1 = "Johnny Depp";
			Long creationTime1 = 1611858618L;
			
			
			OsAccountUpdateResult updateResult = caseDB.getOsAccountManager().updateStandardOsAccountAttributes(osAccount1, fullName1, null, null, creationTime1 );
			assertEquals(updateResult.getUpdateStatusCode(), OsAccountManager.OsAccountUpdateStatus.UPDATED);
			assertTrue(updateResult.getUpdatedAccount().isPresent());
			
			osAccount1 = updateResult.getUpdatedAccount().orElseThrow(() -> new TskCoreException("Updated account not found"));
			assertEquals(osAccount1.getCreationTime().orElse(null), creationTime1);
			assertEquals(osAccount1.getFullName().orElse(null).equalsIgnoreCase(fullName1), true );
			
			
			// now try and create osAccount1 again - it should return the existing account
			OsAccount osAccount1_copy1 = caseDB.getOsAccountManager().newWindowsOsAccount(ownerUid1, null, realmName1, host1, OsAccountRealm.RealmScope.LOCAL);
			
			
			assertEquals(osAccount1_copy1.getAddr().orElse("").equalsIgnoreCase(ownerUid1), true);
			assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(osAccount1_copy1.getRealmId()).getRealmNames().get(0).equalsIgnoreCase(realmName1), true);
			
			
			assertEquals(osAccount1_copy1.getFullName().orElse("").equalsIgnoreCase(fullName1), true);
			assertEquals(osAccount1.getCreationTime().orElse(null), creationTime1);
			
			
			// Test that getContentById() returns the same account
			Content content = caseDB.getContentById(osAccount1.getId());
			assertEquals(content != null, true);
			assertEquals(content instanceof OsAccount, true);
			OsAccount osAccount1_copy2 = (OsAccount) content;
			assertEquals(osAccount1_copy2.getAddr().orElse("").equalsIgnoreCase(ownerUid1), true);
			
			
			
			// Create two new accounts on a new domain realm
			String ownerUid2 = "S-1-5-21-725345543-854245398-1060284298-1003";
			String ownerUid3 = "S-1-5-21-725345543-854245398-1060284298-1004";
	
			String realmName2 = "basis";
			
			String hostname2 = "host2";
			String hostname3 = "host3";
			Host host2 = caseDB.getHostManager().newHost(hostname2);
			Host host3 = caseDB.getHostManager().newHost(hostname3);
		
			OsAccountRealm domainRealm1 = caseDB.getOsAccountRealmManager().newWindowsRealm(ownerUid2, realmName2, host2, OsAccountRealm.RealmScope.DOMAIN);
		
			// create accounts in this domain scoped realm
			OsAccount osAccount2 = caseDB.getOsAccountManager().newWindowsOsAccount(ownerUid2, null, realmName2, host2, OsAccountRealm.RealmScope.DOMAIN);
			OsAccount osAccount3 = caseDB.getOsAccountManager().newWindowsOsAccount(ownerUid3, null, realmName2, host3, OsAccountRealm.RealmScope.DOMAIN);
			
			assertEquals(osAccount2.getAddr().orElse("").equalsIgnoreCase(ownerUid2), true);
			assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(osAccount2.getRealmId()).getRealmNames().get(0).equalsIgnoreCase(realmName2), true);
			
			
			assertEquals(osAccount3.getAddr().orElse("").equalsIgnoreCase(ownerUid3), true);
			assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(osAccount3.getRealmId()).getRealmNames().get(0).equalsIgnoreCase(realmName2), true);
			
		}
		
		finally {
			
		}

	}
	
	@Test
	public void basicLinuxOsAccountTests() throws TskCoreException {

		try {
			String hostname1 = "linuxTestHost";
			Host host1 = caseDB.getHostManager().newHost(hostname1);
			
			// Create an account with uid and username
			String uid1 = "501";
			String loginName1 = "user1";
			
			OsAccount osAccount1 = caseDB.getOsAccountManager().newLocalLinuxOsAccount(uid1, loginName1, host1);
			assertEquals(osAccount1.getAddr().orElse("").equalsIgnoreCase(uid1), true);
			assertEquals(osAccount1.getLoginName().orElse("").equalsIgnoreCase(loginName1), true);
			
			Optional<OsAccount> osAccount1loadWithUID = caseDB.getOsAccountManager().getLocalLinuxOsAccount(uid1, null, host1);
			assertEquals(osAccount1loadWithUID.isPresent(), true);
			assertEquals(osAccount1loadWithUID.get().getAddr().orElse("").equalsIgnoreCase(uid1), true);
			assertEquals(osAccount1loadWithUID.get().getLoginName().orElse("").equalsIgnoreCase(loginName1), true);
				
			// Create an account with only a UID then update it
			String uid2 = "502";
			String loginName2 = "user2";
			
			OsAccount osAccount2 = caseDB.getOsAccountManager().newLocalLinuxOsAccount(uid2, null, host1);
			assertEquals(osAccount2.getAddr().orElse("").equalsIgnoreCase(uid2), true);
			assertEquals(osAccount2.getLoginName().isEmpty(), true);
			
			OsAccountManager.OsAccountUpdateResult updateResult = caseDB.getOsAccountManager()
					.updateCoreLocalLinuxOsAccountAttributes(osAccount2, uid2, loginName2);
            Optional<OsAccount> oOsAccount2Updated = updateResult.getUpdatedAccount();
			
			assertEquals(updateResult.getUpdateStatusCode().equals(OsAccountManager.OsAccountUpdateStatus.UPDATED), true);
			assertEquals(oOsAccount2Updated.isPresent(), true);
			assertEquals(oOsAccount2Updated.get().getAddr().orElse("").equalsIgnoreCase(uid2), true);
			assertEquals(oOsAccount2Updated.get().getLoginName().orElse("").equalsIgnoreCase(loginName2), true);
			
			// Test unusual merge case (unusual because we're updating the account with the name, not the UID)
			String uid3 = "503";
			String loginName3 = "user3";
			
			OsAccount osAccount3uidOnly = caseDB.getOsAccountManager().newLocalLinuxOsAccount(uid3, null, host1);
			OsAccount osAccount3nameOnly = caseDB.getOsAccountManager().newLocalLinuxOsAccount(null, loginName3, host1);
			
			updateResult = caseDB.getOsAccountManager()
					.updateCoreLocalLinuxOsAccountAttributes(osAccount3nameOnly, uid3, loginName3);
            Optional<OsAccount> oOsAccount3Updated = updateResult.getUpdatedAccount();
			
			assertEquals(updateResult.getUpdateStatusCode().equals(OsAccountManager.OsAccountUpdateStatus.UPDATED), true);
			assertEquals(oOsAccount3Updated.isPresent(), true);
			assertEquals(oOsAccount3Updated.get().getAddr().orElse("").equalsIgnoreCase(uid3), true);
			assertEquals(oOsAccount3Updated.get().getLoginName().orElse("").equalsIgnoreCase(loginName3), true);
			
			// Test normal merge case
			String uid4 = "504";
			String loginName4 = "user4";
			
			OsAccount osAccount4uidOnly = caseDB.getOsAccountManager().newLocalLinuxOsAccount(uid4, null, host1);
			OsAccount osAccount4nameOnly = caseDB.getOsAccountManager().newLocalLinuxOsAccount(null, loginName4, host1);
			
			updateResult = caseDB.getOsAccountManager()
					.updateCoreLocalLinuxOsAccountAttributes(osAccount4uidOnly, uid4, loginName4);
            Optional<OsAccount> oOsAccount4Updated = updateResult.getUpdatedAccount();
			
			assertEquals(updateResult.getUpdateStatusCode().equals(OsAccountManager.OsAccountUpdateStatus.UPDATED), true);
			assertEquals(oOsAccount4Updated.isPresent(), true);
			assertEquals(oOsAccount4Updated.get().getAddr().orElse("").equalsIgnoreCase(uid4), true);
			assertEquals(oOsAccount4Updated.get().getLoginName().orElse("").equalsIgnoreCase(loginName4), true);
			
			
			// Linux user names are case sensitive. 
			String uid5 = "505";
			String loginname5 = "user5";
			String loginName5 = "User5";
			// creates a user with only id
			caseDB.getOsAccountManager().newLocalLinuxOsAccount(uid5, null, host1);
			// Creates a user with name only - lowercase 
			caseDB.getOsAccountManager().newLocalLinuxOsAccount(null, loginname5, host1);
			
			Optional<OsAccount> oOsAccount5_ = caseDB.getOsAccountManager().getLocalLinuxOsAccount(null, loginname5, host1);
			assertEquals(oOsAccount5_.isPresent(), true); // Asserting that lowercase login was created		
			assertEquals(oOsAccount5_.get().getLoginName().orElse(""), loginname5);
			
			// Creates a user with name only uppercase   
			caseDB.getOsAccountManager().newLocalLinuxOsAccount(null, loginName5, host1);
		
			// get the osaccount by uid5
			Optional<OsAccount> oOsAccount5 = caseDB.getOsAccountManager().getLocalLinuxOsAccount(uid5, "", host1);
			assertEquals(oOsAccount5.isPresent(), true);
			
			// Login name was not provided. so should be blank 
			assertEquals(oOsAccount5.get().getLoginName().orElse("") , "");
			assertEquals(oOsAccount5.get().getAddr().orElse(""), uid5);
		
			// attempt to add an account with uid5 and loginName5 (505, User5) 
			OsAccount act5 = caseDB.getOsAccountManager().newLocalLinuxOsAccount(uid5, loginName5, host1);
			
			// Previous create should not have happened. 
			assertEquals(act5.getLoginName().orElse("") , "");
			assertEquals(act5.getAddr().orElse(""), uid5);
		
			// Lets try to update the os account uid5 and loginName5 (505, "") to  (505, User5)
			updateResult = caseDB.getOsAccountManager()
					.updateCoreLocalLinuxOsAccountAttributes(oOsAccount5.get(), uid5, loginName5);
			Optional<OsAccount> oOsAccount5Updated = updateResult.getUpdatedAccount();			
			
			assertEquals(updateResult.getUpdateStatusCode().equals(OsAccountManager.OsAccountUpdateStatus.UPDATED), true);
			assertEquals(oOsAccount5Updated.isPresent(), true);
			assertEquals(oOsAccount5Updated.get().getAddr().orElse(""), uid5);
			assertEquals(oOsAccount5Updated.get().getLoginName().orElse(""), loginName5);
			
						
			Optional<OsAccount> oOsAccount5_loginName = caseDB.getOsAccountManager().getLocalLinuxOsAccount(null, loginName5, host1);
			assertEquals(oOsAccount5_loginName.isPresent(), true);  	
			assertEquals(oOsAccount5_loginName.get().getLoginName().orElse(""), loginName5);
			assertEquals(oOsAccount5_loginName.get().getAddr().orElse(""), uid5);
						
			// Asserting that lowercase login is still there in the database. 	
			// and did not merge the wrong user. 
			Optional<OsAccount> oOsAccount5_loginname5 = caseDB.getOsAccountManager().getLocalLinuxOsAccount(null, loginname5, host1);
			assertEquals(oOsAccount5_loginname5.isPresent(), true); 	
			assertEquals(oOsAccount5_loginname5.get().getLoginName().orElse(""), loginname5);
			
			 
		} finally {
			
		}

	}
	
	@Test
	public void windowsSpecialAccountTests() throws TskCoreException, OsAccountManager.NotUserSIDException {

		try {
			
			// TEST create accounts with special SIDs on host2
			{
				String hostname2 = "host222";
				Host host2 = caseDB.getHostManager().newHost(hostname2);

				String ntAuthorityRealmAddr = "S-1-5";
				
				String specialSid1 = "S-1-5-18";
				String specialSid2 = "S-1-5-19";
				String specialSid3 = "S-1-5-20";

				OsAccount specialAccount1 = caseDB.getOsAccountManager().newWindowsOsAccount(specialSid1, null, null, host2, OsAccountRealm.RealmScope.UNKNOWN);
				OsAccount specialAccount2 = caseDB.getOsAccountManager().newWindowsOsAccount(specialSid2, null, null, host2, OsAccountRealm.RealmScope.UNKNOWN);
				OsAccount specialAccount3 = caseDB.getOsAccountManager().newWindowsOsAccount(specialSid3, null, null, host2, OsAccountRealm.RealmScope.UNKNOWN);

				assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(specialAccount1.getRealmId()).getRealmAddr().orElse("").equalsIgnoreCase(ntAuthorityRealmAddr), true);
				assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(specialAccount2.getRealmId()).getRealmAddr().orElse("").equalsIgnoreCase(ntAuthorityRealmAddr), true);
				assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(specialAccount3.getRealmId()).getRealmAddr().orElse("").equalsIgnoreCase(ntAuthorityRealmAddr), true);
			}
			
			
			// TEST create accounts with special SIDs on host3 - should create their own realm 
			{
				String hostname3 = "host333";
				Host host3 = caseDB.getHostManager().newHost(hostname3);

				String ntAuthorityRealmName = "NT AUTHORITY";
				String ntAuthorityRealmAddr = "S-1-5";
				
				
				String specialSid1518 = "S-1-5-18";
				
				// Create an account with just the well known SID - it should automatically get a realmname and loginName
				// each of these well known SIDs should get their own realm with the SID as the realm addr
				OsAccount specialAccount1 = caseDB.getOsAccountManager().newWindowsOsAccount(specialSid1518, null, null, host3, OsAccountRealm.RealmScope.UNKNOWN);
				
				// the realm address for this wellknown SIDS are the SIDs themselves. 
				assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(specialAccount1.getRealmId()).getRealmAddr().orElse("").equalsIgnoreCase(ntAuthorityRealmAddr), true);
				
				// verify a new local realm with host3 was created for these account even they've been seen previously on another host
				assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(specialAccount1.getRealmId()).getScopeHost().orElse(null).getName().equalsIgnoreCase(hostname3), true);
				
				// default realm name for these three special SIDs is 'NT AUTHORITY' 
				assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(specialAccount1.getRealmId()).getRealmNames().get(0).equalsIgnoreCase(ntAuthorityRealmName), true);
				
					
				
				// Get the same account in another language - "NT instans"/SYSTEM - it should resolve to the account create above. 
				Optional<OsAccount> optSpecialAccount11 = caseDB.getOsAccountManager().getWindowsOsAccount(null, "SYSTEM", "NT instans", host3);
				assertEquals(optSpecialAccount11.isPresent(), true);
				
				OsAccount specialAccount11 = optSpecialAccount11.get();
				assertEquals(specialAccount11.getId(), specialAccount1.getId());	// should return the same account we created above
				
				// should have the same SID
				assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(specialAccount11.getRealmId()).getRealmAddr().orElse("").equalsIgnoreCase(ntAuthorityRealmAddr), true);
				
				// should have the english realm name
				assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(specialAccount11.getRealmId()).getRealmNames().get(0).equalsIgnoreCase(ntAuthorityRealmName), true);
			
				
				
				// Test getting account in yet another language - AUTORITE NT/SYSTÈME
				Optional<OsAccount> optSpecialAccount12 = caseDB.getOsAccountManager().getWindowsOsAccount(null, "SYSTÈME", "AUTORITE NT", host3);
				assertEquals(optSpecialAccount12.isPresent(), true);
				
				OsAccount specialAccount12 = optSpecialAccount12.get();
				assertEquals(specialAccount11.getId(), specialAccount1.getId());	// should return the same account we created above
				assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(specialAccount12.getRealmId()).getRealmAddr().orElse("").equalsIgnoreCase(ntAuthorityRealmAddr), true);
				assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(specialAccount12.getRealmId()).getRealmNames().get(0).equalsIgnoreCase(ntAuthorityRealmName), true);
				
				
			
				//create new account with S-1-5-18/NT instans/SYSTEM - it should be resolved to the exiting account S-1-5-18/NT AUTHORITY/SYSTEM
				OsAccount specialAccount13 = caseDB.getOsAccountManager().newWindowsOsAccount(specialSid1518, "SYSTEM", "NT instans", host3, OsAccountRealm.RealmScope.UNKNOWN);
				
				// Ensure it's the same realm as specialAccount1
				assertEquals(specialAccount13.getRealmId(), specialAccount1.getRealmId());
				
				assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(specialAccount13.getRealmId()).getRealmAddr().orElse("").equalsIgnoreCase(ntAuthorityRealmAddr), true);
				
				// ensure that the name of the realm stays the well known english name - "NT AUTHORITY"
				assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(specialAccount13.getRealmId()).getRealmNames().get(0).equalsIgnoreCase(ntAuthorityRealmName), true);
				
				
			
				// Test another well known SID
				String specialSid1519 = "S-1-5-19";
				String localServiceLoginName = "LOCAL SERVICE";
				
				// create account with SID and non english names S-1-5-19/SERVIZIO LOCALE/AUTORITE NT - it shuould be created anew with english names. 
				OsAccount specialAccount2 = caseDB.getOsAccountManager().newWindowsOsAccount(specialSid1519, "SERVIZIO LOCALE", "AUTORITE NT", host3, OsAccountRealm.RealmScope.UNKNOWN);
						
				assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(specialAccount2.getRealmId()).getScopeHost().orElse(null).getName().equalsIgnoreCase(hostname3), true);
				assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(specialAccount2.getRealmId()).getRealmNames().get(0).equalsIgnoreCase(ntAuthorityRealmName), true);
				assertEquals(specialAccount2.getLoginName().get().equalsIgnoreCase(localServiceLoginName), true);
				
				
				// now get account for NT INSTANS/LOKALER DIENST - it should just get the above account
				Optional<OsAccount> optSpecialAccount21 = caseDB.getOsAccountManager().getWindowsOsAccount(null, "LOKALER DIENST", "NT INSTANS", host3);	
				assertEquals(optSpecialAccount21.isPresent(), true);
				
				OsAccount specialAccount21 = optSpecialAccount21.get();
			
				// should be same account as one created above
				assertEquals(specialAccount2.getId(), specialAccount21.getId());
				assertEquals(specialAccount2.getRealmId(), specialAccount21.getRealmId());
				
				assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(specialAccount21.getRealmId()).getRealmAddr().orElse("").equalsIgnoreCase(ntAuthorityRealmAddr), true);
				assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(specialAccount21.getRealmId()).getRealmNames().get(0).equalsIgnoreCase(ntAuthorityRealmName), true);
				assertEquals(specialAccount21.getLoginName().get().equalsIgnoreCase(localServiceLoginName), true);
				
				
				//---- 
				String specialSid1520 = "S-1-5-20";
				String networkServiceLoginName = "NETWORK SERVICE";
				
				//Test where we first create an account with realm/name only and then get it with SID alone.  What should happen in that case ???
				OsAccount specialAccount3 = caseDB.getOsAccountManager().newWindowsOsAccount(null, "NETZWERKDIENST", "NT instans", host3, OsAccountRealm.RealmScope.UNKNOWN);
						
				assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(specialAccount3.getRealmId()).getScopeHost().orElse(null).getName().equalsIgnoreCase(hostname3), true);
				assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(specialAccount3.getRealmId()).getRealmNames().get(0).equalsIgnoreCase(ntAuthorityRealmName), true);
				assertEquals(specialAccount3.getLoginName().get().equalsIgnoreCase(networkServiceLoginName), true);
				
				
				// Now get the account by correpsonding SID - it should resolve to the account created above. 
				Optional<OsAccount> optSpecialAccount31 = caseDB.getOsAccountManager().getWindowsOsAccount(specialSid1520, null, null, host3);	
				assertEquals(optSpecialAccount31.isPresent(), true);
				
				OsAccount specialAccount31 = optSpecialAccount31.get();
				assertEquals(specialAccount3.getId(), specialAccount31.getId());
				assertEquals(specialAccount3.getRealmId(), specialAccount31.getRealmId());
				
				assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(specialAccount31.getRealmId()).getRealmAddr().orElse("").equalsIgnoreCase(ntAuthorityRealmAddr), true);
				assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(specialAccount31.getRealmId()).getScopeHost().orElse(null).getName().equalsIgnoreCase(hostname3), true);
				assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(specialAccount31.getRealmId()).getRealmNames().get(0).equalsIgnoreCase(ntAuthorityRealmName), true);
				assertEquals(specialAccount31.getLoginName().get().equalsIgnoreCase(networkServiceLoginName), true);
				
				// Try getting the account with realm/loginName in another language
				Optional<OsAccount> optSpecialAccount32 = caseDB.getOsAccountManager().getWindowsOsAccount(null, "SERVICE RÉSEAU", "AUTORITE NT", host3);	
				assertEquals(optSpecialAccount32.isPresent(), true);
				
				OsAccount specialAccount32 = optSpecialAccount32.get();
				assertEquals(specialAccount3.getId(), specialAccount32.getId());
				assertEquals(specialAccount3.getRealmId(), specialAccount32.getRealmId());
				
				assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(specialAccount32.getRealmId()).getRealmAddr().orElse("").equalsIgnoreCase(ntAuthorityRealmAddr), true);
				assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(specialAccount32.getRealmId()).getScopeHost().orElse(null).getName().equalsIgnoreCase(hostname3), true);
				assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(specialAccount32.getRealmId()).getRealmNames().get(0).equalsIgnoreCase(ntAuthorityRealmName), true);
				assertEquals(specialAccount32.getLoginName().get().equalsIgnoreCase(networkServiceLoginName), true);
			}

			
			// Test some other special account.
			{
				String hostname4 = "host444";
				Host host4 = caseDB.getHostManager().newHost(hostname4);

				String specialSid1 = "S-1-5-80-3696737894-3623014651-202832235-645492566-13622391";
				String specialSid2 = "S-1-5-82-4003674586-223046494-4022293810-2417516693-151509167";
				String specialSid3 = "S-1-5-90-0-2";
				String specialSid4 = "S-1-5-96-0-3";
				
				// expected realm addresses for these special SIDs
				String specialSidRealmAddr1 = "S-1-5-80";
				String specialSidRealmAddr2 = "S-1-5-82";
				String specialSidRealmAddr3 = "S-1-5-90";
				String specialSidRealmAddr4 = "S-1-5-96";
				
				// All accounts in the range S-1-5-80 to S-1-5-111 are well known SIDS
				String specialSid5 = "S-1-5-99-0-3";
				String specialSid6 = "S-1-5-100-0-3";
				String specialSid7 = "S-1-5-111-0-3";
				String specialSid8 = "S-1-5-112-0-3"; // NOT SPECIAL SID
				String specialSid9 = "S-1-5-79-0-3"; // NOT SPECIAL SID
				
				// expected realm addresses for these special SIDs
				String specialSidRealmAddr5 = "S-1-5-99";
				String specialSidRealmAddr6 = "S-1-5-100";
				String specialSidRealmAddr7 = "S-1-5-111";
				String specialSidRealmAddr8 = "S-1-5-112-0"; // NOT SPECIAL SID
				String specialSidRealmAddr9 = "S-1-5-79-0"; // NOT SPECIAL SID
				
				
				
				OsAccount specialAccount1 = caseDB.getOsAccountManager().newWindowsOsAccount(specialSid1, null, null, host4, OsAccountRealm.RealmScope.UNKNOWN);
				OsAccount specialAccount2 = caseDB.getOsAccountManager().newWindowsOsAccount(specialSid2, null, null, host4, OsAccountRealm.RealmScope.UNKNOWN);
				OsAccount specialAccount3 = caseDB.getOsAccountManager().newWindowsOsAccount(specialSid3, null, null, host4, OsAccountRealm.RealmScope.UNKNOWN);
				OsAccount specialAccount4 = caseDB.getOsAccountManager().newWindowsOsAccount(specialSid4, null, null, host4, OsAccountRealm.RealmScope.UNKNOWN);
				

				assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(specialAccount1.getRealmId()).getRealmAddr().orElse("").equalsIgnoreCase(specialSidRealmAddr1), true);
				assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(specialAccount2.getRealmId()).getRealmAddr().orElse("").equalsIgnoreCase(specialSidRealmAddr2), true);
				assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(specialAccount3.getRealmId()).getRealmAddr().orElse("").equalsIgnoreCase(specialSidRealmAddr3), true);
				assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(specialAccount4.getRealmId()).getRealmAddr().orElse("").equalsIgnoreCase(specialSidRealmAddr4), true);
				
				
				OsAccount specialAccount5 = caseDB.getOsAccountManager().newWindowsOsAccount(specialSid5, null, null, host4, OsAccountRealm.RealmScope.UNKNOWN);
				OsAccount specialAccount6 = caseDB.getOsAccountManager().newWindowsOsAccount(specialSid6, null, null, host4, OsAccountRealm.RealmScope.UNKNOWN);
				OsAccount specialAccount7 = caseDB.getOsAccountManager().newWindowsOsAccount(specialSid7, null, null, host4, OsAccountRealm.RealmScope.UNKNOWN);
				OsAccount specialAccount8 = caseDB.getOsAccountManager().newWindowsOsAccount(specialSid8, null, null, host4, OsAccountRealm.RealmScope.UNKNOWN);
				OsAccount specialAccount9 = caseDB.getOsAccountManager().newWindowsOsAccount(specialSid9, null, null, host4, OsAccountRealm.RealmScope.UNKNOWN);
				
				assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(specialAccount5.getRealmId()).getRealmAddr().orElse("").equalsIgnoreCase(specialSidRealmAddr5), true);
				assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(specialAccount6.getRealmId()).getRealmAddr().orElse("").equalsIgnoreCase(specialSidRealmAddr6), true);
				assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(specialAccount7.getRealmId()).getRealmAddr().orElse("").equalsIgnoreCase(specialSidRealmAddr7), true);
				assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(specialAccount8.getRealmId()).getRealmAddr().orElse("").equalsIgnoreCase(specialSidRealmAddr8), true);  // specialSid8 is NOT special.
				assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(specialAccount9.getRealmId()).getRealmAddr().orElse("").equalsIgnoreCase(specialSidRealmAddr9), true);  // specialSid9 is NOT special.
		}
			
			// TEST: create accounts with a invalid user SIDs - these should generate an exception
			{
				String hostname5 = "host555";
				String realmName5 = "realmName555";
				Host host5 = caseDB.getHostManager().newHost(hostname5);

				try {
					String sid1 = "S-1-5-32-544"; // builtin Administrators
					OsAccount osAccount1 = caseDB.getOsAccountManager().newWindowsOsAccount(sid1, null, realmName5, host5, OsAccountRealm.RealmScope.UNKNOWN);
					
					// above should raise an exception
					assertEquals(true, false);
				}
				catch (OsAccountManager.NotUserSIDException ex) {
					// continue
				}
				
				try {
					String sid2 = "S-1-5-21-725345543-854245398-1060284298-512"; //  domain admins group
					OsAccount osAccount2 = caseDB.getOsAccountManager().newWindowsOsAccount(sid2, null, realmName5, host5, OsAccountRealm.RealmScope.UNKNOWN);
					
					// above should raise an exception
					assertEquals(true, false);
				}
				catch (OsAccountManager.NotUserSIDException ex) {
					// continue
				}
				
				try {
					String sid3 = "S-1-1-0"; //  Everyone
					OsAccount osAccount3 = caseDB.getOsAccountManager().newWindowsOsAccount(sid3, null, realmName5, host5, OsAccountRealm.RealmScope.UNKNOWN);
					
					// above should raise an exception
					assertEquals(true, false);
				}
				catch (OsAccountManager.NotUserSIDException ex) {
					// continue
				}

				try {
					// try to create account with NULL SID and null name - should fail. 
					String sid4 = "S-1-0-0"; //  NULL SID
					OsAccount osAccount4 = caseDB.getOsAccountManager().newWindowsOsAccount(sid4, null, realmName5, host5, OsAccountRealm.RealmScope.UNKNOWN);
					
					// above should raise an exception
					assertEquals(true, false);
				}
				catch (TskCoreException ex) {
					// continue
				}
				
				try {
					// try to create an account with "NULL SID" and valid login name. Should throw away the NULL SID And create account with login name.
					String sid5 = "S-1-0-0"; //  NULL SID
					String loginName5 = "login5";
					OsAccount osAccount5 = caseDB.getOsAccountManager().newWindowsOsAccount(sid5, loginName5, realmName5, host5, OsAccountRealm.RealmScope.UNKNOWN);
					
					assertFalse(osAccount5.getAddr().isPresent());	// should NOT have a SID
					assertEquals(caseDB.getOsAccountRealmManager().getRealmByRealmId(osAccount5.getRealmId()).getRealmNames().get(0).equalsIgnoreCase(realmName5), true);
					assertEquals(osAccount5.getLoginName().orElse("").equalsIgnoreCase(loginName5), true);	
			
				}
				catch (OsAccountManager.NotUserSIDException ex) {
					// DO NOT EXPECT this exception to be thrown here. 
					assertEquals(true, false);
				}
				
			}
		}
		
		finally {
			
		}

	}
	
	
	@Test
	public void osAccountInstanceTests() throws TskCoreException, OsAccountManager.NotUserSIDException {

		String ownerUid1 = "S-1-5-21-111111111-222222222-3333333333-0001";
		String realmName1 = "realm1111";

		String hostname1 = "host1111";
		Host host1 = caseDB.getHostManager().newHost(hostname1);

		OsAccountRealm localRealm1 = caseDB.getOsAccountRealmManager().newWindowsRealm(ownerUid1, realmName1, host1, OsAccountRealm.RealmScope.LOCAL);
		OsAccount osAccount1 = caseDB.getOsAccountManager().newWindowsOsAccount(ownerUid1, null, realmName1, host1, OsAccountRealm.RealmScope.LOCAL);

		// Test: add an instance
		caseDB.getOsAccountManager().newOsAccountInstance(osAccount1, image, OsAccountInstance.OsAccountInstanceType.ACCESSED);
		
		// Verify 
		List<OsAccountInstance> account1Instances = caseDB.getOsAccountManager().getOsAccountInstances(osAccount1);
		assertEquals(account1Instances.size(), 1);
		assertEquals(account1Instances.get(0).getInstanceType().getId(), OsAccountInstance.OsAccountInstanceType.ACCESSED.getId());

		// Test: add an instance that already exists - with less significant instance type - this should be a no op.
		caseDB.getOsAccountManager().newOsAccountInstance(osAccount1, image, OsAccountInstance.OsAccountInstanceType.REFERENCED); // since ACCESSED > REFERENCED - this should do nothing
		account1Instances = caseDB.getOsAccountManager().getOsAccountInstances(osAccount1);
		assertEquals(account1Instances.size(), 1);
		assertEquals(account1Instances.get(0).getInstanceType().getId(), OsAccountInstance.OsAccountInstanceType.ACCESSED.getId());
		
		
		// Test: add an instance that already exists - with more significant instance type - this update the existing instance.
		caseDB.getOsAccountManager().newOsAccountInstance(osAccount1, image, OsAccountInstance.OsAccountInstanceType.LAUNCHED); // since LAUNCHED > ACCESSED - this should update the existing instance
		account1Instances = caseDB.getOsAccountManager().getOsAccountInstances(osAccount1);
		assertEquals(account1Instances.size(), 1);
		assertEquals(account1Instances.get(0).getInstanceType().getId(), OsAccountInstance.OsAccountInstanceType.LAUNCHED.getId());
		
	
		// Test: add an instance that already exists - with less significant instance type - should do nothing
		caseDB.getOsAccountManager().newOsAccountInstance(osAccount1, image, OsAccountInstance.OsAccountInstanceType.REFERENCED); 
		caseDB.getOsAccountManager().newOsAccountInstance(osAccount1, image, OsAccountInstance.OsAccountInstanceType.ACCESSED); 
		account1Instances = caseDB.getOsAccountManager().getOsAccountInstances(osAccount1);
		assertEquals(account1Instances.size(), 1);
		assertEquals(account1Instances.get(0).getInstanceType().getId(), OsAccountInstance.OsAccountInstanceType.LAUNCHED.getId());
		
		// Test: create account instance on a new host
		String hostname2 = "host2222";
		Host host2 = caseDB.getHostManager().newHost(hostname2);
		caseDB.getOsAccountManager().newOsAccountInstance(osAccount1, image, OsAccountInstance.OsAccountInstanceType.LAUNCHED);
	
		
		List<OsAccountAttribute> accountAttributes = new ArrayList<>();
		Long resetTime1 = 1611859999L;	
		
		// TBD: perhaps add some files to the case and then use one of the files as the source of attributes.
		
		OsAccountAttribute attrib1 = osAccount1.new OsAccountAttribute(caseDB.getBlackboard().getAttributeType(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_PASSWORD_RESET.getTypeID()), resetTime1, osAccount1, null, image);
		accountAttributes.add(attrib1);
		
		String hint = "HINT";
		OsAccountAttribute attrib2 = osAccount1.new OsAccountAttribute(caseDB.getBlackboard().getAttributeType(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PASSWORD_HINT.getTypeID()), hint, osAccount1, host2, image);
		accountAttributes.add(attrib2);
		
		// add attributes to account.
		caseDB.getOsAccountManager().addExtendedOsAccountAttributes(osAccount1, accountAttributes);
		
		// now get the account with same sid,  and get its attribuites and verify.
		Optional<OsAccount> existingAccount1 = caseDB.getOsAccountManager().getOsAccountByAddr(osAccount1.getAddr().get(), caseDB.getOsAccountRealmManager().getRealmByRealmId(osAccount1.getRealmId()));
		List<OsAccountAttribute> existingAccountAttribs  = existingAccount1.get().getExtendedOsAccountAttributes();
		
		
		assertEquals(existingAccountAttribs.size(), 2);
		for (OsAccountAttribute attr: existingAccountAttribs) {
			if (attr.getAttributeType().getTypeID() == BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_PASSWORD_RESET.getTypeID()) {
				assertEquals(attr.getValueLong(), resetTime1.longValue() );
				
			} else if (attr.getAttributeType().getTypeID() == BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PASSWORD_HINT.getTypeID()) {
				assertEquals(attr.getValueString().equalsIgnoreCase(hint), true );
			}
			
		}
		
		
	}
	
	
	@Test
	public void windowsAccountRealmUpdateTests() throws TskCoreException, OsAccountManager.NotUserSIDException {

		String ownerUid1 = "S-1-5-21-111111111-222222222-4444444444-0001";
		//String realmName1 = "realm4444";

		String hostname1 = "host4444";
		Host host1 = caseDB.getHostManager().newHost(hostname1);

		
		// create an account, a realm should be created implicitly with just the SID, and no name
		
		OsAccount osAccount1 = caseDB.getOsAccountManager().newWindowsOsAccount(ownerUid1, null, null, host1, OsAccountRealm.RealmScope.LOCAL);
		
		String realmAddr1 = "S-1-5-21-111111111-222222222-4444444444";
		OsAccountRealm realm1 = caseDB.getOsAccountRealmManager().getRealmByRealmId(osAccount1.getRealmId());
		assertEquals(realm1.getRealmAddr().orElse("").equalsIgnoreCase(realmAddr1), true );
		assertEquals(realm1.getRealmNames().isEmpty(), true);	//
		
		
		
		// create a 2nd account with the same realmaddr, along with a known realm name
		String ownerUid2 = "S-1-5-21-111111111-222222222-4444444444-0002";
		
		String realmName2 = "realm4444";
		OsAccount osAccount2 = caseDB.getOsAccountManager().newWindowsOsAccount(ownerUid2, null, realmName2, host1, OsAccountRealm.RealmScope.LOCAL);
		
		// Account 2 should have the same realm by addr, but it's realm name should now get updated.
		OsAccountRealm realm2 = caseDB.getOsAccountRealmManager().getRealmByRealmId(osAccount2.getRealmId());
		
		assertEquals(osAccount1.getRealmId(), osAccount2.getRealmId() );
		assertEquals(realm2.getRealmAddr().orElse("").equalsIgnoreCase(realmAddr1), true );
		assertEquals(realm2.getRealmNames().size(), 1 );	// should have 1 name
		assertEquals(realm2.getRealmNames().get(0).equalsIgnoreCase(realmName2), true );
		
		
		// Create an account with  known realm name but no known addr
		String hostname3 = "host4444_3";
		Host host3 = caseDB.getHostManager().newHost(hostname3);
		
		String realmName3 = "realm4444_3";
		String loginName3 = "User4444_3";
		OsAccount osAccount3 = caseDB.getOsAccountManager().newWindowsOsAccount(null, loginName3, realmName3, host3, OsAccountRealm.RealmScope.DOMAIN);
		
		OsAccountRealm realm3 = caseDB.getOsAccountRealmManager().getRealmByRealmId(osAccount3.getRealmId());
		assertEquals(realm3.getRealmAddr().orElse("").equalsIgnoreCase(""), true );
		assertEquals(realm3.getRealmNames().size(), 1 );	// should have 1 name
		assertEquals(realm3.getRealmNames().get(0).equalsIgnoreCase(realmName3), true );
		
		
		// add a second user with same realmname and a known addr - expect the realm to get updated
		String loginName4 = "User4444_4";
		String ownerSid4 =  "S-1-5-21-111111111-444444444-4444444444-0001";
	    String realm4Addr = "S-1-5-21-111111111-444444444-4444444444";
		
		String hostname4 = "host4444_4";
		Host host4 = caseDB.getHostManager().newHost(hostname4);
		
		OsAccount osAccount4 = caseDB.getOsAccountManager().newWindowsOsAccount(ownerSid4, loginName4, realmName3, host4, OsAccountRealm.RealmScope.DOMAIN);
		
		// realm4 should be the same as realm3 but the addr should be updaed now
		OsAccountRealm realm4 = caseDB.getOsAccountRealmManager().getRealmByRealmId(osAccount4.getRealmId());
		assertEquals(osAccount3.getRealmId(), osAccount4.getRealmId() );
		assertEquals(realm4.getRealmAddr().orElse("").equalsIgnoreCase(realm4Addr), true );
		assertEquals(realm4.getRealmNames().size(), 1 );	// should have 1 name
		assertEquals(realm4.getRealmNames().get(0).equalsIgnoreCase(realmName3), true );
		
	
	}
	
	
	@Test
	public void windowsAccountUpdateTests() throws TskCoreException, OsAccountManager.NotUserSIDException {

		
		String hostname1 = "host55555";
		Host host1 = caseDB.getHostManager().newHost(hostname1);
		
	
		// Test 1: create an account with a SID alone. Then update the loginName.
		
		String ownerUid1 = "S-1-5-21-111111111-222222222-555555555-0001";
		OsAccount osAccount1 = caseDB.getOsAccountManager().newWindowsOsAccount(ownerUid1, null, null, host1, OsAccountRealm.RealmScope.DOMAIN);
		
		
		// now update the account login name
		String loginname1 = "jbravo";
		
		OsAccountUpdateResult updateResult = caseDB.getOsAccountManager().updateCoreWindowsOsAccountAttributes(osAccount1, null, loginname1, null, host1);
		assertEquals(updateResult.getUpdateStatusCode(), OsAccountManager.OsAccountUpdateStatus.UPDATED);
		assertEquals(updateResult.getUpdatedAccount().isPresent(), true);
		OsAccount updatedAccount = updateResult.getUpdatedAccount().orElseThrow(() ->  new TskCoreException("Updated account not found."));
		
		// verify that account has both addr and loginName, and that signature is the addr
		assertTrue(updatedAccount.getAddr().orElse("").equalsIgnoreCase(ownerUid1));
		assertTrue(updatedAccount.getLoginName().orElse("").equalsIgnoreCase(loginname1));
		assertTrue(updatedAccount.getSignature().equalsIgnoreCase(ownerUid1));	// account signature should not change
		
		
		String realmAddr1 = "S-1-5-21-111111111-222222222-555555555";
		String realmSignature1 = realmAddr1 + "_DOMAIN";	// for a domain realm - signature is sid/name + "_DOMAIN"
		
		OsAccountRealm realm1 = caseDB.getOsAccountRealmManager().getRealmByRealmId(updatedAccount.getRealmId());
		assertTrue(realm1.getRealmAddr().orElse("").equalsIgnoreCase(realmAddr1));
		assertTrue(realm1.getSignature().equalsIgnoreCase(realmSignature1));	
		
		
		// TBD Test2: create an account with realmName/loginname and then update the SID
		
		String loginname2 = "janeB";
		String realmName2 = "realm55555";
		OsAccount osAccount2 = caseDB.getOsAccountManager().newWindowsOsAccount(null, loginname2, realmName2, host1, OsAccountRealm.RealmScope.DOMAIN);
		
		assertFalse(osAccount2.getAddr().isPresent());
		assertTrue(osAccount2.getLoginName().orElse("").equalsIgnoreCase(loginname2));
		assertTrue(osAccount2.getSignature().equalsIgnoreCase(loginname2));	// account signature should be the login name
		
		// now update the account SID
		String ownerUid2 = "S-1-5-21-111111111-222222222-555555555-0007";
		OsAccountUpdateResult updateResult2 = caseDB.getOsAccountManager().updateCoreWindowsOsAccountAttributes(osAccount2, ownerUid2, null, realmName2, host1);
		assertEquals(updateResult2.getUpdateStatusCode(), OsAccountManager.OsAccountUpdateStatus.UPDATED);
		assertEquals(updateResult2.getUpdatedAccount().isPresent(), true);
		OsAccount updatedAccount2 = updateResult2.getUpdatedAccount().orElseThrow(() ->  new TskCoreException("Updated account not found."));
		
		// verify that account has both addr and loginName, and that signature is the addr
		assertTrue(updatedAccount2.getAddr().orElse("").equalsIgnoreCase(ownerUid2));
		assertTrue(updatedAccount2.getLoginName().orElse("").equalsIgnoreCase(loginname2));
		assertTrue(updatedAccount2.getSignature().equalsIgnoreCase(ownerUid2));	// account signature should now be addr
		
		OsAccountRealm realm2 = caseDB.getOsAccountRealmManager().getRealmByRealmId(updatedAccount2.getRealmId());
		assertTrue(realm2.getRealmAddr().orElse("").equalsIgnoreCase(realmAddr1));
		assertTrue(realm2.getSignature().equalsIgnoreCase(realmSignature1));
	}
	
	@Test
	public void windowsAccountMergeTests() throws TskCoreException, OsAccountManager.NotUserSIDException {

		String hostname1 = "windowsAccountMergeTestHost";
		Host host1 = caseDB.getHostManager().newHost(hostname1);
	
		// 1. Create an account with a SID alone
		String sid = "S-1-5-21-111111111-222222222-666666666-0001";
		OsAccount osAccount1 = caseDB.getOsAccountManager().newWindowsOsAccount(sid, null, null, host1, OsAccountRealm.RealmScope.LOCAL);
		
		Long realmId = osAccount1.getRealmId();
		
		// 2. Create an account with loginName and realmName
		String loginName = "jdoe";
		String realmName = "testRealm";
		OsAccount osAccount2 = caseDB.getOsAccountManager().newWindowsOsAccount(null, loginName, realmName, host1, OsAccountRealm.RealmScope.LOCAL);

		// 3. Lookup account by SID, loginName, and realmName
		Optional<OsAccount> oOsAccount = caseDB.getOsAccountManager().getWindowsOsAccount(sid, loginName, realmName, host1);
		assertTrue(oOsAccount.isPresent());
		
		// 4. Update this account with all SID, loginName, and realmName
		caseDB.getOsAccountManager().updateCoreWindowsOsAccountAttributes(oOsAccount.get(), sid, loginName, realmName, host1);
		
		// The two accounts should be merged
		
		// Test that there is now only one account associated with sid1
		List<OsAccount> accounts = caseDB.getOsAccountManager().getOsAccounts().stream().filter(a -> a.getAddr().isPresent() && a.getAddr().get().equals(sid)).collect(Collectors.toList());
		assertEquals(accounts.size() == 1, true);
		
		// Test that there is now only one account associated with loginName
		accounts = caseDB.getOsAccountManager().getOsAccounts().stream().filter(p -> p.getLoginName().isPresent() && p.getLoginName().get().equals(loginName)).collect(Collectors.toList());
		assertEquals(accounts.size() == 1, true);
	}
}
