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
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
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
	public void personTests() throws TskCoreException {
		String personName1 = "John Doe";
		String personName2 = "Jane Doe";
		
		org.sleuthkit.datamodel.PersonManager pm = caseDB.getPersonManager();
		
		Person p1 = pm.createPerson(personName1);
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
	public void mergeTests() throws TskCoreException {
		Host host = caseDB.getHostManager().createHost("mergeTestHost");
		
		String destRealmName = "mergeTestDestRealm";
		String srcRealmName = "mergeTestSourceRealm";
		
		String sid1 = "S-1-5-21-222222222-222222222-1060284298-2222";
        String sid2 = "S-1-5-21-555555555-555555555-1060284298-5555";   
		
		String uniqueRealm2Name = "uniqueRealm2Account";
		String matchingName = "matchingNameAccount";
		String fullName1 = "FullName1";
		long creationTime1 = 555;
		
		OsAccountRealm srcRealm = caseDB.getOsAccountRealmManager().createWindowsRealm(null, srcRealmName, host, OsAccountRealm.RealmScope.LOCAL);
		OsAccountRealm destRealm = caseDB.getOsAccountRealmManager().createWindowsRealm(null, destRealmName, host, OsAccountRealm.RealmScope.LOCAL);
		
		OsAccount account1 = caseDB.getOsAccountManager().createWindowsAccount(null, "uniqueRealm1Account", destRealmName, host, OsAccountRealm.RealmScope.LOCAL);
		OsAccount account2 = caseDB.getOsAccountManager().createWindowsAccount(null, matchingName, destRealmName, host, OsAccountRealm.RealmScope.LOCAL);
		OsAccount account3 = caseDB.getOsAccountManager().createWindowsAccount(null, uniqueRealm2Name, srcRealmName, host, OsAccountRealm.RealmScope.LOCAL);
		OsAccount account4 = caseDB.getOsAccountManager().createWindowsAccount(null, matchingName, srcRealmName, host, OsAccountRealm.RealmScope.LOCAL);
		account4.setFullName(fullName1);
		account4.setIsAdmin(true);
		account4.setCreationTime(creationTime1);
		caseDB.getOsAccountManager().updateAccount(account4);
		OsAccount account5 = caseDB.getOsAccountManager().createWindowsAccount(sid1, null, destRealmName, host, OsAccountRealm.RealmScope.LOCAL);
		OsAccount account6 = caseDB.getOsAccountManager().createWindowsAccount(sid1, null, srcRealmName, host, OsAccountRealm.RealmScope.LOCAL);  
		OsAccount account7 = caseDB.getOsAccountManager().createWindowsAccount(sid2, null, destRealmName, host, OsAccountRealm.RealmScope.LOCAL);
		OsAccount account8 = caseDB.getOsAccountManager().createWindowsAccount(null, "nameForCombining", destRealmName, host, OsAccountRealm.RealmScope.LOCAL);
		OsAccount account9 = caseDB.getOsAccountManager().createWindowsAccount(sid2, "nameForCombining", srcRealmName, host, OsAccountRealm.RealmScope.LOCAL);
		
		// Test that we can currently get the source realm by name
		Optional<OsAccountRealm> optRealm = caseDB.getOsAccountRealmManager().getWindowsRealm(null, srcRealmName, host);
		assertEquals(optRealm.isPresent(), true);
		
		// Test that there are currently two account associated with sid1
		List<OsAccount> accounts = caseDB.getOsAccountManager().getAccounts().stream().filter(p -> p.getUniqueIdWithinRealm().isPresent() && p.getUniqueIdWithinRealm().get().equals(sid1)).collect(Collectors.toList());
		assertEquals(accounts.size() == 2, true);
		
		// Expected results of the merge:
		// - account 4 will be merged into account 2 (and extra fields should be copied)
		// - account 6 will be merged into account 5
		// - account 8 will be merged into account 7 (due to account 9 containing matches for both)
		// - account 9 will be merged into account 7
		caseDB.getOsAccountRealmManager().mergeRealms(srcRealm, destRealm);
		
		// Test that the source realm is no longer returned by a search by name
		optRealm = caseDB.getOsAccountRealmManager().getWindowsRealm(null, srcRealmName, host);
		assertEquals(optRealm.isPresent(), false);
		
		// Test that there is now only one account associated with sid1
		accounts = caseDB.getOsAccountManager().getAccounts().stream().filter(p -> p.getUniqueIdWithinRealm().isPresent() && p.getUniqueIdWithinRealm().get().equals(sid1)).collect(Collectors.toList());
		assertEquals(accounts.size() == 1, true);
		
		// Test that account 3 got moved into the destination realm
		Optional<OsAccount> optAcct = caseDB.getOsAccountManager().getOsAccountByLoginName(uniqueRealm2Name, destRealm);
		assertEquals(optAcct.isPresent(), true);
		
		// Test that data from account 4 was merged into account 2
		optAcct = caseDB.getOsAccountManager().getOsAccountByLoginName(matchingName, destRealm);
		assertEquals(optAcct.isPresent(), true);
		if (optAcct.isPresent()) {
			assertEquals(optAcct.get().getCreationTime().isPresent() &&  optAcct.get().getCreationTime().get() == creationTime1, true);
			assertEquals(optAcct.get().getFullName().isPresent() && fullName1.equalsIgnoreCase(optAcct.get().getFullName().get()), true);
			assertEquals(optAcct.get().isAdmin().isPresent() && optAcct.get().isAdmin().get(), true);
		}
	}
	
	@Test 
	public void hostAddressTests() throws TskCoreException {
		String ipv4Str = "11.22.33.44";
		String ipv6Str = "2001:0db8:85a3:0000:0000:8a2e:0370:6666";
		String hostnameStr = "basis.com";
		
		// Test creation
		HostAddress ipv4addr = caseDB.getHostAddressManager().createHostAddress(HostAddress.HostAddressType.IPV4, ipv4Str);
		assertEquals(ipv4addr.getAddress().equalsIgnoreCase(ipv4Str), true);
		
		HostAddress addr2 = caseDB.getHostAddressManager().createHostAddress(HostAddress.HostAddressType.DNS_AUTO, ipv6Str);
		assertEquals(addr2.getAddress().equalsIgnoreCase(ipv6Str), true);
		assertEquals(HostAddress.HostAddressType.IPV6.equals(addr2.getAddressType()), true);
		
		HostAddress hostAddr = caseDB.getHostAddressManager().createHostAddress(HostAddress.HostAddressType.DNS_AUTO, hostnameStr);
		assertEquals(hostAddr.getAddress().equalsIgnoreCase(hostnameStr), true);
		assertEquals(HostAddress.HostAddressType.HOSTNAME.equals(hostAddr.getAddressType()), true);
		
		// Test get
		Optional<HostAddress> addr4opt = caseDB.getHostAddressManager().getHostAddress(HostAddress.HostAddressType.IPV4, ipv4Str);
		assertEquals(addr4opt.isPresent(), true);
		
		// Test host map
		Host host = caseDB.getHostManager().createHost("TestHostAddress");
		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		DataSource ds = caseDB.addLocalFilesDataSource("devId", "pathToFiles", "EST", null, trans);
		trans.commit();
		caseDB.getHostAddressManager().mapHostToAddress(host, ipv4addr, (long) 0, ds);
		List<HostAddress> hostAddrs = caseDB.getHostAddressManager().getHostAddresses(host);
		assertEquals(hostAddrs.size() == 1, true);
		
		// Test IP mapping
		caseDB.getHostAddressManager().addHostNameToIpMapping(hostAddr, ipv4addr, (long) 0, ds);
		List<HostAddress> ipForHostSet = caseDB.getHostAddressManager().getIp(hostAddr.getAddress());
		assertEquals(ipForHostSet.size() == 1, true);
		List<HostAddress> hostForIpSet = caseDB.getHostAddressManager().getHostNameByIp(ipv4addr.getAddress());
		assertEquals(hostForIpSet.size() == 1, true);
	}
	
	@Test
	public void osAccountRealmTests() throws TskCoreException {
		
		try {
		// TEST: create a DOMAIN realm 
		
		String HOSTNAME1 = "host1";
		Host host1 = caseDB.getHostManager().createHost(HOSTNAME1);
			
		String realmName1 = "basis";
		String realmSID1 =  "S-1-5-21-1111111111-2222222222-3333333333";
		String realmAddr1 = "S-1-5-21-1111111111-2222222222";	
		
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
		localRealm2.setRealmName(realmName2);
		OsAccountRealm updatedRealm2 = caseDB.getOsAccountRealmManager().updateRealm(localRealm2);
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
			
			assertEquals(osAccount1.isAdmin().orElse(Boolean.FALSE).equals(Boolean.FALSE), true); // did not set the admin flag.
			assertEquals(osAccount1.getUniqueIdWithinRealm().orElse("").equalsIgnoreCase(ownerUid1), true);
			assertEquals(osAccount1.getRealm().getRealmName().orElse("").equalsIgnoreCase(realmName1), true);
			
			
			// Let's update osAccount1
			String fullName1 = "Johnny Depp";
			Long creationTime1 = 1611858618L;
			boolean isChanged = osAccount1.setCreationTime(creationTime1);
			assertEquals(isChanged, true);
			
			osAccount1.setFullName(fullName1);
			osAccount1.setIsAdmin(true); // set admin flag
			
			
			osAccount1 = caseDB.getOsAccountManager().updateAccount(osAccount1);
			assertEquals(osAccount1.getCreationTime().orElse(null), creationTime1);
			assertEquals(osAccount1.getFullName().orElse(null).equalsIgnoreCase(fullName1), true );
			
			
			// now try and create osAccount1 again - it should return the existing account
			OsAccount osAccount1_copy1 = caseDB.getOsAccountManager().createWindowsAccount(ownerUid1, null, realmName1, host1, OsAccountRealm.RealmScope.LOCAL);
			
			
			assertEquals(osAccount1_copy1.getUniqueIdWithinRealm().orElse("").equalsIgnoreCase(ownerUid1), true);
			assertEquals(osAccount1_copy1.getRealm().getRealmName().orElse("").equalsIgnoreCase(realmName1), true);
			
			
			assertEquals(osAccount1_copy1.isAdmin().orElse(Boolean.FALSE).equals(Boolean.TRUE), true); // isAdmin should be true now
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
			
			assertEquals(osAccount2.isAdmin().orElse(Boolean.FALSE).equals(Boolean.FALSE), true);
			assertEquals(osAccount2.getUniqueIdWithinRealm().orElse("").equalsIgnoreCase(ownerUid2), true);
			assertEquals(osAccount2.getRealm().getRealmName().orElse("").equalsIgnoreCase(realmName2), true);
			
			
			assertEquals(osAccount3.isAdmin().orElse(Boolean.FALSE).equals(Boolean.FALSE), true);
			assertEquals(osAccount3.getUniqueIdWithinRealm().orElse("").equalsIgnoreCase(ownerUid3), true);
			assertEquals(osAccount3.getRealm().getRealmName().orElse("").equalsIgnoreCase(realmName2), true);
			
		}
		
		finally {
			
		}

	}
	
	
	@Test
	public void windowsSpecialAccountTests() throws TskCoreException {

		try {
			
			String SPECIAL_WINDOWS_REALM_ADDR = "SPECIAL_WINDOWS_ACCOUNTS";
			
			
			
			// TEST: create accounts with a "short" sid
			{
				String hostname1 = "host111";
				Host host1 = caseDB.getHostManager().createHost(hostname1);

				String realmName1 = "realmName111";
				String sid1 = "S-1-5-32-544"; // builtin Administrators
				String sid2 = "S-1-5-32-545"; //  builtin Users
				String sid3 = "S-1-5-32-546"; //  builtin Guests
				String realmAddr1 = "S-1-5-32";

				OsAccount osAccount1 = caseDB.getOsAccountManager().createWindowsAccount(sid1, null, realmName1, host1, OsAccountRealm.RealmScope.UNKNOWN);
				OsAccount osAccount2 = caseDB.getOsAccountManager().createWindowsAccount(sid2, null, realmName1, host1, OsAccountRealm.RealmScope.UNKNOWN);
				OsAccount osAccount3 = caseDB.getOsAccountManager().createWindowsAccount(sid3, null, realmName1, host1, OsAccountRealm.RealmScope.UNKNOWN);

				assertEquals(osAccount1.getRealm().getRealmName().orElse("").equalsIgnoreCase(realmName1), true);
				assertEquals(osAccount1.getRealm().getRealmAddr().orElse("").equalsIgnoreCase(realmAddr1), true);
				assertEquals(osAccount1.isAdmin().orElse(Boolean.FALSE).equals(Boolean.FALSE), true);
				assertEquals(osAccount1.getUniqueIdWithinRealm().orElse("").equalsIgnoreCase(sid1), true);

				assertEquals(osAccount2.getRealm().getRealmName().orElse("").equalsIgnoreCase(realmName1), true);
				assertEquals(osAccount2.getRealm().getRealmAddr().orElse("").equalsIgnoreCase(realmAddr1), true);
				assertEquals(osAccount2.isAdmin().orElse(Boolean.FALSE).equals(Boolean.FALSE), true);
				assertEquals(osAccount2.getUniqueIdWithinRealm().orElse("").equalsIgnoreCase(sid2), true);

				assertEquals(osAccount3.getRealm().getRealmName().orElse("").equalsIgnoreCase(realmName1), true);
				assertEquals(osAccount3.getRealm().getRealmAddr().orElse("").equalsIgnoreCase(realmAddr1), true);
				assertEquals(osAccount3.isAdmin().orElse(Boolean.FALSE).equals(Boolean.FALSE), true);
				assertEquals(osAccount3.getUniqueIdWithinRealm().orElse("").equalsIgnoreCase(sid3), true);
			}
			
			
			
		
			// TEST create accounts with special SIDs on host2
			{
				String hostname2 = "host222";
				Host host2 = caseDB.getHostManager().createHost(hostname2);

				String specialSid1 = "S-1-5-18";
				String specialSid2 = "S-1-5-19";
				String specialSid3 = "S-1-5-20";

				OsAccount specialAccount1 = caseDB.getOsAccountManager().createWindowsAccount(specialSid1, null, null, host2, OsAccountRealm.RealmScope.UNKNOWN);
				OsAccount specialAccount2 = caseDB.getOsAccountManager().createWindowsAccount(specialSid2, null, null, host2, OsAccountRealm.RealmScope.UNKNOWN);
				OsAccount specialAccount3 = caseDB.getOsAccountManager().createWindowsAccount(specialSid3, null, null, host2, OsAccountRealm.RealmScope.UNKNOWN);

				assertEquals(specialAccount1.getRealm().getRealmAddr().orElse("").equalsIgnoreCase(SPECIAL_WINDOWS_REALM_ADDR), true);
				assertEquals(specialAccount2.getRealm().getRealmAddr().orElse("").equalsIgnoreCase(SPECIAL_WINDOWS_REALM_ADDR), true);
				assertEquals(specialAccount3.getRealm().getRealmAddr().orElse("").equalsIgnoreCase(SPECIAL_WINDOWS_REALM_ADDR), true);
			}
			
			
			// TEST create accounts with special SIDs on host3 - should create their own realm 
			{
				String hostname3 = "host333";
				Host host3 = caseDB.getHostManager().createHost(hostname3);

				String specialSid1 = "S-1-5-18";
				String specialSid2 = "S-1-5-19";
				String specialSid3 = "S-1-5-20";

				OsAccount specialAccount1 = caseDB.getOsAccountManager().createWindowsAccount(specialSid1, null, null, host3, OsAccountRealm.RealmScope.UNKNOWN);
				OsAccount specialAccount2 = caseDB.getOsAccountManager().createWindowsAccount(specialSid2, null, null, host3, OsAccountRealm.RealmScope.UNKNOWN);
				OsAccount specialAccount3 = caseDB.getOsAccountManager().createWindowsAccount(specialSid3, null, null, host3, OsAccountRealm.RealmScope.UNKNOWN);

				assertEquals(specialAccount1.getRealm().getRealmAddr().orElse("").equalsIgnoreCase(SPECIAL_WINDOWS_REALM_ADDR), true);
				assertEquals(specialAccount2.getRealm().getRealmAddr().orElse("").equalsIgnoreCase(SPECIAL_WINDOWS_REALM_ADDR), true);
				assertEquals(specialAccount3.getRealm().getRealmAddr().orElse("").equalsIgnoreCase(SPECIAL_WINDOWS_REALM_ADDR), true);
				
				// verify a new local realm with host3 was created for these account even they've been seen previously on another host
				assertEquals(specialAccount1.getRealm().getScopeHost().orElse(null).getName().equalsIgnoreCase(hostname3), true);
				assertEquals(specialAccount1.getRealm().getScopeHost().orElse(null).getName().equalsIgnoreCase(hostname3), true);
				assertEquals(specialAccount1.getRealm().getScopeHost().orElse(null).getName().equalsIgnoreCase(hostname3), true);
			}

			
			// Test some other special account.
			{
				String hostname4 = "host444";
				Host host4 = caseDB.getHostManager().createHost(hostname4);

				String specialSid1 = "S-1-5-80-3696737894-3623014651-202832235-645492566-13622391";
				String specialSid2 = "S-1-5-82-4003674586-223046494-4022293810-2417516693-151509167";
				String specialSid3 = "S-1-5-90-0-2";
				String specialSid4 = "S-1-5-96-0-3";
				

				OsAccount specialAccount1 = caseDB.getOsAccountManager().createWindowsAccount(specialSid1, null, null, host4, OsAccountRealm.RealmScope.UNKNOWN);
				OsAccount specialAccount2 = caseDB.getOsAccountManager().createWindowsAccount(specialSid2, null, null, host4, OsAccountRealm.RealmScope.UNKNOWN);
				OsAccount specialAccount3 = caseDB.getOsAccountManager().createWindowsAccount(specialSid3, null, null, host4, OsAccountRealm.RealmScope.UNKNOWN);
				OsAccount specialAccount4 = caseDB.getOsAccountManager().createWindowsAccount(specialSid4, null, null, host4, OsAccountRealm.RealmScope.UNKNOWN);
				

				assertEquals(specialAccount1.getRealm().getRealmAddr().orElse("").equalsIgnoreCase(SPECIAL_WINDOWS_REALM_ADDR), true);
				assertEquals(specialAccount2.getRealm().getRealmAddr().orElse("").equalsIgnoreCase(SPECIAL_WINDOWS_REALM_ADDR), true);
				assertEquals(specialAccount3.getRealm().getRealmAddr().orElse("").equalsIgnoreCase(SPECIAL_WINDOWS_REALM_ADDR), true);
				assertEquals(specialAccount4.getRealm().getRealmAddr().orElse("").equalsIgnoreCase(SPECIAL_WINDOWS_REALM_ADDR), true);
				
				
			}
			
		}
		
		finally {
			
		}

	}
	
	
	@Test
	public void osAccountInstanceTests() throws TskCoreException {

		String ownerUid1 = "S-1-5-32-111111111-222222222-3333333333-0001";
		String realmName1 = "realm1111";

		String hostname1 = "host1111";
		Host host1 = caseDB.getHostManager().createHost(hostname1);

		OsAccountRealm localRealm1 = caseDB.getOsAccountRealmManager().createWindowsRealm(ownerUid1, realmName1, host1, OsAccountRealm.RealmScope.LOCAL);
		OsAccount osAccount1 = caseDB.getOsAccountManager().createWindowsAccount(ownerUid1, null, realmName1, host1, OsAccountRealm.RealmScope.LOCAL);

		// Test: add an instance
		caseDB.getOsAccountManager().createOsAccountInstance(osAccount1, host1, image, OsAccount.OsAccountInstanceType.PERFORMED_ACTION_ON);

		// Test: add an existing instance - should be a no-op.
		caseDB.getOsAccountManager().createOsAccountInstance(osAccount1, host1, image, OsAccount.OsAccountInstanceType.PERFORMED_ACTION_ON);

		// Test: create account instance on a new host
		String hostname2 = "host2222";
		Host host2 = caseDB.getHostManager().createHost(hostname2);
		caseDB.getOsAccountManager().createOsAccountInstance(osAccount1, host2, image, OsAccount.OsAccountInstanceType.REFERENCED_ON);
	
		
		List<OsAccountAttribute> accountAttributes = new ArrayList<>();
		Long resetTime1 = 1611859999L;	
		
		// TBD: perhaps add some files to the case and then use one of the files as the source of attributes.
		
		OsAccountAttribute attrib1 = new OsAccountAttribute(caseDB.getAttributeType(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_PASSWORD_RESET.getTypeID()), resetTime1, osAccount1, null, image);
		accountAttributes.add(attrib1);
		
		String hint = "HINT";
		OsAccountAttribute attrib2 = new OsAccountAttribute(caseDB.getAttributeType(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PASSWORD_HINT.getTypeID()), hint, osAccount1, host2, image);
		accountAttributes.add(attrib2);
		
		// add attributes to account.
		osAccount1.addAttributes(accountAttributes);
		
		
		// now get the account with same sid,  and get its attribuites and verify.
		Optional<OsAccount> existingAccount1 = caseDB.getOsAccountManager().getOsAccountByUniqueId(osAccount1.getUniqueIdWithinRealm().get(), osAccount1.getRealm());
		List<OsAccountAttribute> existingAccountAttribs  = existingAccount1.get().getOsAccountAttributes();
		
		
		assertEquals(existingAccountAttribs.size(), 2);
		for (OsAccountAttribute attr: existingAccountAttribs) {
			if (attr.getAttributeType().getTypeID() == BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_PASSWORD_RESET.getTypeID()) {
				assertEquals(attr.getValueLong(), resetTime1.longValue() );
				
			} else if (attr.getAttributeType().getTypeID() == BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PASSWORD_HINT.getTypeID()) {
				assertEquals(attr.getValueString().equalsIgnoreCase(hint), true );
			}
			
		}
		
		
	}
	
	
}
