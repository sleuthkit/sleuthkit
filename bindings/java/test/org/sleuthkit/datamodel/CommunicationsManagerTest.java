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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Tests the CommunicationsManager API along with filters
 *
 * Setup: - Make a SleuthkitCase SQLite databse in a temp folder
 * - Add three Virtual Directories as data sources (DS1, DS2, DS3). We should specify the
 * device IDs for consistency.
 * - We want to have at least two account types and 3 accounts per type with different forms of relationships. 
 * Something like: 
 * -- DS1 (assume it is EMAIL A): 
 * --- Email Msg from A (EMAIL_ACCT_TYPE) to B (EMAIL_ACCT_TYPE) on Jan 1, 2017
 * --- Email Msg from A to B and C on Mar 1, 2017
 * --- Email Msg from C to A on July 1, 2017
 * --- CallLog from DEVICE to 2 (PHONE_ACCT_TYPE) on Jan 1, 2017
 * --- CallLog from 2 (PHONE_ACCT_TYPE) to DEVICE on Mar 1, 2017
 * --- CallLog from 3 to DEVICE on July 1, 2017
 * --- Msg from DEVICE to 2 (PHONE_ACCT_TYPE) on Jan 1, 2017
 * --- Msg from 2 (PHONE_ACCT_TYPE) to DEVICE on Mar 1, 2017
 * --- Msg from 3 (PHONE_ACCT_TYPE) to DEVICE on July 1, 2017 
 * -- DS2 : Has no email messages
 * --- CallLog from DEVICE to 1 (PHONE_ACCT_TYPE) on Jan 1, 2017
 * --- CallLog from 2 (PHONE_ACCT_TYPE) to DEVICE on Mar 1, 2017
 * --- CallLog from 4 to DEVICE on July 1, 2017
 * --- Msg from DEVICE to 2 (PHONE_ACCT_TYPE) on Jan 1, 2017
 * --- Msg from 2 (PHONE_ACCT_TYPE) to DEVICE on Mar 1, 2017
 * --- Msg from 4 (PHONE_ACCT_TYPE) to DEVICE on July 1, 2017
 * -- DS3: Has no communications / accounts, etc.
 *
 * Tests:
 * - getAccountDeviceInstances:
 * -- No filters. verify count.
 * -- Device
 * filter for DS1 and DS2. Verify count (same as previous)
 * -- Device filter for
 * DS2. Verify count.
 * -- Device filter for DS3. Verify nothing is returned
 * -- AccountType of Email. Verify Count
 * -- AccountType of PHONE. Verify Count.
 * -- AccountType of Email and Phone. Verify count
 * -- AccountType of CreditCard. Verify nothing is returned.
 * -- Device of DS1 and AccountType of Email. Verify count.
 * -- Device of DS1 and AccountType of Phone. Verify count.
 * -- Device of
 * DS2 and AccountType of Email. Verify nothing is returned
 * -- Device of DS1 and AccountTypes of Email and Phone. Verify
 * -- Device of DS2 and AccountTypes of Email and Phone. Verify count
 * -- Device of DS1 & DS2 and AccountTypes of Email. Verify count
 * -- Device of DS1 & DS2 and AccountTypes of Phone. Verify count
 * -- Device of DS1 & DS2 and AccountTypes of Phone & Email. Verify count
 * -- Device of DS1 & DS2 & DS3 and AccountTypes of Phone & Email. Verify count
 *
 * - getRelationshipsCount:
 * -- Email Account A: No filters. verify count.
 * -- Email Account A: DS1. verify count (same as previous)
 * -- Email Account A: DS1 & EMAIL. verify count (same as previous)
 * -- Email Account B: DS1. verify count
 * -- Email Account B: DS1 & DS2. verify count (same as previous)
 * -- Email Account C: DS1 & DS2. verify count (same as previous)
 * -- Phone2: DS1. verify count
 * -- Phone2: DS2. verify count
 * -- Phone2: DS1 & DS2. verify count
 * -- Phone3: DS1. verify count
 * -- Phone3: DS1 & DS2. verify count
 * -- Phone3: DS1. verify count
 * -- Phone1: DS1. verify count
 * -- Phone1: DS2. verify count
 * -- Phone1: DS1 & DS2. verify count
 * -- Phone4: DS1. verify count
 * -- Phone4: DS2. verify count
 * -- Phone4: DS1 & DS2. verify count
 */
public class CommunicationsManagerTest {

	private static final Logger LOGGER = Logger.getLogger(CommunicationsManagerTest.class.getName());
	private static final String MODULE_NAME = "CommsMgrTest";

	private static final String DS1_DEVICEID = "d36d3f74-f7cd-4936-b6a5-ac6a54be285c";
	private static final String DS2_DEVICEID = "c1077bb0-bda8-4360-b63b-cfc72c29fadc";
	private static final String DS3_DEVICEID = "aa60489e-cfd7-4d65-bab7-ad755d982c10";

	private static final String ROOTDIR_1 = "rootdir_1";
	private static final String ROOTDIR_2 = "rootdir_2";
	private static final String ROOTDIR_3 = "rootdir_3";

	private static SleuthkitCase caseDB;
	private static CommunicationsManager commsMgr;

	private final static String TEST_DB = "CommsMgrTest.db";

	private static final String EMAIL_A = "AAA@yahoo.com";
	private static final String EMAIL_B = "BBB@gmail.com";
	private static final String EMAIL_C = "CCCCC@funmail.com";

	private static final String PHONENUM_1 = "111 777 1111";
	private static final String PHONENUM_2 = "222 333 7777";
	private static final String PHONENUM_3 = "333 123 4567";
	private static final String PHONENUM_4 = "4444 4444";

	private static final String NAME_1 = "James Bond";
	private static final String NAME_2 = "Sherlock Holmes";
	private static final String NAME_3 = "Captain America";
	private static final String NAME_4 = "Iron Man";

	private static final long JAN_1_2107 = 1483272732;
	private static final long MAR_1_2107 = 1488370332;
	private static final long JUL_1_2107 = 1498922115;

	private static String dbPath = null;

	public CommunicationsManagerTest() {
	}

	@BeforeClass
	public static void setUpClass() {
		
		String tempDirPath = System.getProperty("java.io.tmpdir");
		tempDirPath = tempDirPath.substring(0, tempDirPath.length() - 1);
		try {
			dbPath = tempDirPath + java.io.File.separator + TEST_DB;
			
			// Delete the DB file, in case 
			java.io.File dbFile = new java.io.File(dbPath);
			dbFile.delete();

			// Create new case db
			caseDB = SleuthkitCase.newCase(dbPath);
			commsMgr = caseDB.getCommunicationsManager();

			System.out.println("CommsMgr Test DB created at: " + dbPath);

			SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();

			LocalFilesDataSource dataSource_1 = caseDB.addLocalFilesDataSource(DS1_DEVICEID, ROOTDIR_1, "", trans);
			LocalFilesDataSource dataSource_2 = caseDB.addLocalFilesDataSource(DS2_DEVICEID, ROOTDIR_2, "", trans);
			LocalFilesDataSource dataSource_3 = caseDB.addLocalFilesDataSource(DS3_DEVICEID, ROOTDIR_3, "", trans);

			trans.commit();

			// Create some commmunication artiacts from DS1
			{
				VirtualDirectory rootDirectory_1 = dataSource_1.getRootDirectory();
				AbstractFile sourceContent_1 = rootDirectory_1;	// Let the root dorectory be the source for all artifacts

				// Create a Device accocunt for Device1
				AccountInstance deviceAccount_1 = caseDB.getCommunicationsManager().createAccountInstance(Account.Type.DEVICE, DS1_DEVICEID, MODULE_NAME, rootDirectory_1);

				// Create some email message artifacts
				addEmailMsgArtifact(EMAIL_A, EMAIL_B, "", "",
						JAN_1_2107, "",
						"Text Body", "HTML Body", "RTF Body",
						"Hey There",
						1001,
						sourceContent_1);

				addEmailMsgArtifact(EMAIL_A, EMAIL_B + "; " + EMAIL_C, "", "",
						MAR_1_2107, "",
						"Message2 Message2 Message2", "", "",
						"You've won a million dollars",
						1002,
						sourceContent_1);

				addEmailMsgArtifact(EMAIL_C, EMAIL_A, "", "",
						JUL_1_2107, "",
						"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua", "", "",
						"Faux Latin",
						1003,
						sourceContent_1);

				// Add some Call logs
				addCalllogArtifact(deviceAccount_1, NAME_2, PHONENUM_2, JAN_1_2107, 100, "Outgoing", sourceContent_1);
				addCalllogArtifact(deviceAccount_1, NAME_2, PHONENUM_2, MAR_1_2107, 57, "Incoming", sourceContent_1);
				addCalllogArtifact(deviceAccount_1, NAME_3, PHONENUM_3, JUL_1_2107, 57, "Incoming", sourceContent_1);

				// Add some Messages 
				addMessageArtifact(deviceAccount_1, PHONENUM_2, JAN_1_2107, "Outgoing", "Hey there", "This is a SMS", sourceContent_1);
				addMessageArtifact(deviceAccount_1, PHONENUM_2, MAR_1_2107, "Incoming", "", "Im going to be home late :(", sourceContent_1);
				addMessageArtifact(deviceAccount_1, PHONENUM_3, JUL_1_2107, "Incoming", "New Year", "We wish you a Happy New Year", sourceContent_1);
			}

			// Create some commmunication artiacts from DS2
			{
				VirtualDirectory rootDirectory_2 = dataSource_2.getRootDirectory();
				AbstractFile sourceContent_2 = rootDirectory_2;	// Let the root directory be the source for all artifacts

				// Create a Device accocunt for Device1
				AccountInstance deviceAccount_2 = caseDB.getCommunicationsManager().createAccountInstance(Account.Type.DEVICE, DS2_DEVICEID, MODULE_NAME, sourceContent_2);

				// Add some Call logs
				addCalllogArtifact(deviceAccount_2, NAME_1, PHONENUM_1, 1483272732, 100, "Outgoing", sourceContent_2);
				addCalllogArtifact(deviceAccount_2, NAME_2, PHONENUM_2, 1488370332, 57, "Incoming", sourceContent_2);
				addCalllogArtifact(deviceAccount_2, NAME_4, PHONENUM_4, 1498922115, 57, "Incoming", sourceContent_2);

				// Add some Messages 
				addMessageArtifact(deviceAccount_2, PHONENUM_2, JAN_1_2107, "Outgoing", "Ashley", "I must have the wrong number. Is this not Ashton?", sourceContent_2);
				addMessageArtifact(deviceAccount_2, PHONENUM_2, MAR_1_2107, "Incoming", "", "The darned train arrived almost an hour late", sourceContent_2);
				addMessageArtifact(deviceAccount_2, PHONENUM_4, JUL_1_2107, "Incoming", "List", "Milk, tomatoes, mustard, toohthpaste.", sourceContent_2);
			}
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
	public void deviceFilterTests() throws TskCoreException {
		System.out.println("CommsMgr API - Device Filters test");

		// Test no filters - pass null for CommunicationsFilter
		{
			List<AccountDeviceInstance> accountDeviceInstances2 = commsMgr.getAccountDeviceInstancesWithRelationships(null);
			assertEquals(10, accountDeviceInstances2.size());
		}

		// Test no filters - empty DeviceFilter
		{
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(),
					null);
			
			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(10, accountDeviceInstances.size());
		}

		// Test filter - filter for DS1 and DS2
		{
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID, DS2_DEVICEID)),
					null);
			
			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(10, accountDeviceInstances.size());
		}

		// Test filter - filter for DS3 - it has no accounts
		{
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS3_DEVICEID)),
					null);
			
			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(0, accountDeviceInstances.size());
		}

	}

	@Test
	public void accountTypeFilterTests() throws TskCoreException {

		System.out.println("CommsMgr API - AccountType filters test");

		// Test empty AccountTypeFilter
		{
			CommunicationsFilter commsFilter = buildCommsFilter(
					null,
					new HashSet<Account.Type>());
			
			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(10, accountDeviceInstances.size());
		}

		// Test AccountTypeFilter - Email
		{
			CommunicationsFilter commsFilter = buildCommsFilter(
					null,
					new HashSet<Account.Type>(Arrays.asList(Account.Type.EMAIL)));
			
			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(3, accountDeviceInstances.size());
		}

		// Test AccountTypeFilter - Phone
		{
			CommunicationsFilter commsFilter = buildCommsFilter(
					null,
					new HashSet<Account.Type>(Arrays.asList(Account.Type.PHONE)));
			
			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(5, accountDeviceInstances.size());
		}

		// Test AccountTypeFilter - Email & Phone
		{
			CommunicationsFilter commsFilter = buildCommsFilter(
					null,
					new HashSet<Account.Type>(Arrays.asList(Account.Type.PHONE, Account.Type.EMAIL)));
			
			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(8, accountDeviceInstances.size());
		}

		// Test AccountTypeFilter - CreditCard
		{
			CommunicationsFilter commsFilter = buildCommsFilter(
					null,
					new HashSet<Account.Type>(Arrays.asList(Account.Type.CREDIT_CARD)));
			
			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(0, accountDeviceInstances.size());
		}

	}

	@Test
	public void deviceAndAccounttypeFilterTests() throws TskCoreException {

		System.out.println("CommsMgr API - Device & AccountType filters test");

		// Test Device & AccountType filter - DS1 & EMAIL
		{
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID)),
					new HashSet<Account.Type>(Arrays.asList(Account.Type.EMAIL)));

			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(3, accountDeviceInstances.size());
		}

		// Test Device & AccountType filter - DS1 & PHONE
		{
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID)),
					new HashSet<Account.Type>(Arrays.asList(Account.Type.PHONE)));
			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(2, accountDeviceInstances.size());
		}

		// Test AccountTypeFilter - DS2 & EMAIL
		{
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS2_DEVICEID)),
					new HashSet<Account.Type>(Arrays.asList(Account.Type.EMAIL)));

			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(0, accountDeviceInstances.size());
		}

		// Test Device & AccountType filter - DS1 & PHONE or EMAIL
		{
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID)),
					new HashSet<Account.Type>(Arrays.asList(Account.Type.PHONE, Account.Type.EMAIL)));

			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(5, accountDeviceInstances.size());
		}

		// Test Device & AccountType filter - DS2 & PHONE or EMAIL
		{
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS2_DEVICEID)),
					new HashSet<Account.Type>(Arrays.asList(Account.Type.PHONE, Account.Type.EMAIL)));

			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(3, accountDeviceInstances.size());
		}

		// Test Device & AccountType filter - DS2 or DS1 & EMAIL
		{
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID, DS2_DEVICEID)),
					new HashSet<Account.Type>(Arrays.asList(Account.Type.EMAIL)));

			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(3, accountDeviceInstances.size());
		}

		// Test Device & AccountType filter - DS2 or DS1 & Phone
		{
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID, DS2_DEVICEID)),
					new HashSet<Account.Type>(Arrays.asList(Account.Type.PHONE)));

			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(5, accountDeviceInstances.size());
		}

		// Test Device & AccountType filter - DS2 or DS1 & Phone or Email
		{
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID, DS2_DEVICEID)),
					new HashSet<Account.Type>(Arrays.asList(Account.Type.PHONE, Account.Type.EMAIL)));

			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(8, accountDeviceInstances.size());
		}

		// Test Device & AccountType filter - DS1 or DS2 & Phone or Email
		{
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID, DS2_DEVICEID)),
					new HashSet<Account.Type>(Arrays.asList(Account.Type.PHONE, Account.Type.EMAIL)));

			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(8, accountDeviceInstances.size());
		}

		// Test Device & AccountType filter - DS1 or DS2 or DS3 & Phone or Email
		{
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID, DS2_DEVICEID, DS3_DEVICEID)),
					new HashSet<Account.Type>(Arrays.asList(Account.Type.PHONE, Account.Type.EMAIL)));

			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(8, accountDeviceInstances.size());
		}

	}

	@Test
	public void relationshipCountsWithFilterTests() throws TskCoreException {

		System.out.println("CommsMgr API - Relationship counts test");

		// Relationships count for Email Account A: No Filters
		{
			Account account_email_A = commsMgr.getAccount(Account.Type.EMAIL, EMAIL_A);
			long count = commsMgr.getRelationshipsCount(account_email_A, null);
			assertEquals(4, count);
		}

		// Relationships count for Email Account A, Filter on DS1
		{
			Account account_email_A = commsMgr.getAccount(Account.Type.EMAIL, EMAIL_A);
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID)),
					null);

			long count = commsMgr.getRelationshipsCount(account_email_A, commsFilter);
			assertEquals(4, count);
		}

		// Relationships count for Email Account A: Filter on DS1 & EMAIL
		{
			Account account_email_A = commsMgr.getAccount(Account.Type.EMAIL, EMAIL_A);
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID)),
					new HashSet<Account.Type>(Arrays.asList(Account.Type.EMAIL)));

			long count = commsMgr.getRelationshipsCount(account_email_A, commsFilter);
			assertEquals(4, count);
		}

		// Relationships count for Email Account B, Filter on DS1
		{
			Account account_email_B = commsMgr.getAccount(Account.Type.EMAIL, EMAIL_B);
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID)),
					null);

			long count = commsMgr.getRelationshipsCount(account_email_B, commsFilter);
			assertEquals(3, count);
		}

		// Relationships count for Email Account B, Filter on DS1 & DS2
		{
			Account account_email_B = commsMgr.getAccount(Account.Type.EMAIL, EMAIL_B);
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID, DS2_DEVICEID)),
					null);

			long count = commsMgr.getRelationshipsCount(account_email_B, commsFilter);
			assertEquals(3, count);
		}

		// Relationships count for Email Account C, Filter on DS1 & DS2
		{
			Account account_email_C = commsMgr.getAccount(Account.Type.EMAIL, EMAIL_C);
			AccountDeviceInstance adi_emailC_ds1 = new AccountDeviceInstance(account_email_C, DS1_DEVICEID);

			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID, DS2_DEVICEID)),
					null);

			long count = commsMgr.getRelationshipsCount(account_email_C, commsFilter);
			assertEquals(3, count);
		}

		// Relationships count for Phone2, Filter on DS1
		{
			Account account_phone2 = commsMgr.getAccount(Account.Type.PHONE, PHONENUM_2);
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID)),
					null);

			long count = commsMgr.getRelationshipsCount(account_phone2, commsFilter);
			assertEquals(4, count);
		}

		// Relationships count for Phone2, Filter on DS2 - expect 0 
		{
			Account account_phone2 = commsMgr.getAccount(Account.Type.PHONE, PHONENUM_2);
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS2_DEVICEID)),
					null);

			long count = commsMgr.getRelationshipsCount(account_phone2, commsFilter);
			assertEquals(3, count);
		}

		// Relationships count for Phone2, Filter on DS1, DS2
		{
			Account account_phone2 = commsMgr.getAccount(Account.Type.PHONE, PHONENUM_2);
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID, DS2_DEVICEID)),
					null);

			long count = commsMgr.getRelationshipsCount(account_phone2, commsFilter);
			assertEquals(7, count);
		}

		// Relationships count for Phone3, Filter on DS1
		{
			Account account_phone3 = commsMgr.getAccount(Account.Type.PHONE, PHONENUM_3);
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID)),
					null);

			long count = commsMgr.getRelationshipsCount(account_phone3, commsFilter);
			assertEquals(2, count);
		}

		// Relationships count for Phone3, Filter on DS1 & DS2
		{
			Account account_phone3 = commsMgr.getAccount(Account.Type.PHONE, PHONENUM_3);
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID, DS2_DEVICEID)),
					null);

			long count = commsMgr.getRelationshipsCount(account_phone3, commsFilter);
			assertEquals(2, count);
		}

		// Relationships count for Phone1, Filter on DS1, expect 0
		{
			Account account_phone1 = commsMgr.getAccount(Account.Type.PHONE, PHONENUM_1);
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID)),
					null);

			long count = commsMgr.getRelationshipsCount(account_phone1, commsFilter);
			assertEquals(0, count);
		}

		// Relationships count for Phone1, Filter on DS2
		{
			Account account_phone1 = commsMgr.getAccount(Account.Type.PHONE, PHONENUM_1);
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS2_DEVICEID)),
					null);

			long count = commsMgr.getRelationshipsCount(account_phone1, commsFilter);
			assertEquals(1, count);
		}

		// Relationships count for Phone1, Filter on DS1 & DS2
		{
			Account account_phone1 = commsMgr.getAccount(Account.Type.PHONE, PHONENUM_1);
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS2_DEVICEID, DS2_DEVICEID)),
					null);

			long count = commsMgr.getRelationshipsCount(account_phone1, commsFilter);
			assertEquals(1, count);
		}

		// Relationships count for Phone4, Filter on DS1, expect 0
		{
			Account account_phone4 = commsMgr.getAccount(Account.Type.PHONE, PHONENUM_4);
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID)),
					null);

			long count = commsMgr.getRelationshipsCount(account_phone4, commsFilter);
			assertEquals(0, count);
		}

		// Relationships count for Phone4, Filter on DS2
		{
			Account account_phone4 = commsMgr.getAccount(Account.Type.PHONE, PHONENUM_4);
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS2_DEVICEID)),
					null);

			long count = commsMgr.getRelationshipsCount(account_phone4, commsFilter);
			assertEquals(2, count);
		}

		// Relationships count for Phone4, Filter on DS1 & DS2
		{
			Account account_phone4 = commsMgr.getAccount(Account.Type.PHONE, PHONENUM_4);
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID, DS2_DEVICEID)),
					null);

			long count = commsMgr.getRelationshipsCount(account_phone4, commsFilter);
			assertEquals(2, count);
		}

	}

	/**
	 * Builds CommunicationsFilter, with the given subfilters.
	 * @param deviceSet
	 * @param accountTypeSet
	 * @return 
	 */
	private static CommunicationsFilter buildCommsFilter(Set<String> deviceSet, Set<Account.Type> accountTypeSet) {

		if ((null == deviceSet) && (null == accountTypeSet)) {
			return null;
		}

		CommunicationsFilter commsFilter = new CommunicationsFilter();
		if (null != deviceSet) {
			commsFilter.addAndFilter(new DeviceFilter(deviceSet));
		}
		if (null != accountTypeSet) {
			commsFilter.addAndFilter(new AccountTypeFilter(accountTypeSet));
		}

		return commsFilter;
	}

	/*
	 * Adds an Email msg artifact. Also creates Email AccountInstances, if
	 * needed, and adds relationships between the accounts.
	 */
	private static BlackboardArtifact addEmailMsgArtifact(String fromAddr, String toList, String ccList, String bccList,
			long dateSent, String headers,
			String textBody, String htmlBody, String rtfBody, String subject,
			long msgID,
			AbstractFile abstractFile) {
		BlackboardArtifact bbart = null;
		List<BlackboardAttribute> bbattributes = new ArrayList<BlackboardAttribute>();

		List<String> senderAddressList = new ArrayList<String>();
		String senderAddress;
		senderAddressList.addAll(findEmailAddresess(fromAddr));

		AccountInstance senderAccountInstance = null;
		if (senderAddressList.size() == 1) {
			senderAddress = senderAddressList.get(0);
			try {
				senderAccountInstance = commsMgr.createAccountInstance(Account.Type.EMAIL, senderAddress, MODULE_NAME, abstractFile);
			} catch (TskCoreException ex) {
				LOGGER.log(Level.WARNING, "Failed to create account for email address  " + senderAddress, ex); //NON-NLS
			}
		} else {
			LOGGER.log(Level.WARNING, "Failed to find sender address, from  = " + fromAddr); //NON-NLS
		}

		List<String> recipientAddresses = new ArrayList<String>();
		recipientAddresses.addAll(findEmailAddresess(toList));
		recipientAddresses.addAll(findEmailAddresess(ccList));
		recipientAddresses.addAll(findEmailAddresess(bccList));

		List<AccountInstance> recipientAccountInstances = new ArrayList<AccountInstance>();
		for (String addr : recipientAddresses) {
			try {
				AccountInstance recipientAccountInstance
						= commsMgr.createAccountInstance(Account.Type.EMAIL, addr,
								MODULE_NAME, abstractFile);
				recipientAccountInstances.add(recipientAccountInstance);
			} catch (TskCoreException ex) {
				LOGGER.log(Level.WARNING, "Failed to create account for email address  " + addr, ex); //NON-NLS
			}
		}

		addEmailAttribute(headers, BlackboardAttribute.ATTRIBUTE_TYPE.TSK_HEADERS, bbattributes);
		addEmailAttribute(fromAddr, BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL_FROM, bbattributes);
		addEmailAttribute(toList, BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL_TO, bbattributes);
		addEmailAttribute(subject, BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SUBJECT, bbattributes);

		addEmailAttribute(dateSent, BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_RCVD, bbattributes);
		addEmailAttribute(dateSent, BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_SENT, bbattributes);
		addEmailAttribute(textBody, BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL_CONTENT_PLAIN, bbattributes);
		addEmailAttribute((String.valueOf(msgID)), BlackboardAttribute.ATTRIBUTE_TYPE.TSK_MSG_ID, bbattributes);

		addEmailAttribute(ccList, BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL_CC, bbattributes);
		addEmailAttribute(bccList, BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL_BCC, bbattributes);
		addEmailAttribute(htmlBody, BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL_CONTENT_HTML, bbattributes);
		addEmailAttribute(rtfBody, BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL_CONTENT_RTF, bbattributes);

		try {
			// Add Email artifact
			bbart = abstractFile.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_EMAIL_MSG);
			bbart.addAttributes(bbattributes);

			// Add account relationships
			commsMgr.addRelationships(senderAccountInstance, recipientAccountInstances, bbart);

		} catch (TskCoreException ex) {
			LOGGER.log(Level.SEVERE, "Failed to add Email artifact", ex);
		}

		return bbart;
	}

	private static void addEmailAttribute(String stringVal, BlackboardAttribute.ATTRIBUTE_TYPE attrType, Collection<BlackboardAttribute> bbattributes) {
		if (stringVal.isEmpty() == false) {
			bbattributes.add(new BlackboardAttribute(attrType, MODULE_NAME, stringVal));
		}
	}

	private static void addEmailAttribute(long longVal, BlackboardAttribute.ATTRIBUTE_TYPE attrType, Collection<BlackboardAttribute> bbattributes) {
		if (longVal > 0) {
			bbattributes.add(new BlackboardAttribute(attrType, MODULE_NAME, longVal));
		}
	}

	/**
	 * Finds and returns a set of unique email addresses found in the input
	 * string.
	 *
	 * @param input        - input string, like the To/CC line from an email
	 *                     header.
	 *
	 * @param Set<String>: set of email addresses found in the input string.
	 */
	private static Set<String> findEmailAddresess(String input) {
		System.out.println("findEmailAddresess: input string = " + input);
		Pattern p = Pattern.compile("\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,4}\\b",
				Pattern.CASE_INSENSITIVE);
		Matcher m = p.matcher(input);
		Set<String> emailAddresses = new HashSet<String>();
		while (m.find()) {
			System.out.println("findEmailAddresess: founf addr = " + m.group());
			emailAddresses.add(m.group());
		}
		System.out.println("findEmailAddresess: returning addresses = " + emailAddresses.toString());
		return emailAddresses;
	}

	/*
	 * Adds an CallLog artifact. Also creates PHONE account for the given phone
	 * number and creates a relationship between the device account and the
	 * Phone account AccountInstances, if needed, and adds relationships between
	 * the accounts.
	 */
	private static void addCalllogArtifact(AccountInstance deviceAccount, String name, String phoneNumber, long date, long duration, String direction, AbstractFile abstractFile) {

		try {
			BlackboardArtifact bbart = abstractFile.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_CALLLOG); //create a call log and then add attributes from result set.
			if (direction.equalsIgnoreCase("outgoing")) { //NON-NLS
				bbart.addAttribute(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_TO, MODULE_NAME, phoneNumber));
			} else { /// Covers INCOMING and MISSED
				bbart.addAttribute(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_FROM, MODULE_NAME, phoneNumber));
			}
			bbart.addAttribute(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_START, MODULE_NAME, date));
			bbart.addAttribute(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_END, MODULE_NAME, duration + date));
			bbart.addAttribute(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DIRECTION, MODULE_NAME, direction));
			bbart.addAttribute(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME, MODULE_NAME, name));

			// Create a phone number account for the phone number
			AccountInstance phoneNumAccount = commsMgr.createAccountInstance(Account.Type.PHONE, phoneNumber, MODULE_NAME, abstractFile);
			List<AccountInstance> accountInstanceList = new ArrayList<AccountInstance>();
			accountInstanceList.add(phoneNumAccount);

			//  Create a Call Log relationship
			commsMgr.addRelationships(deviceAccount, accountInstanceList, bbart);

		} catch (TskCoreException ex) {
			LOGGER.log(Level.SEVERE, "Unable to add CallLog artifact ", ex); //NON-NLS
		}
	}

	private static void addMessageArtifact(AccountInstance deviceAccount, String phoneNumber, long date, String direction, String subject, String message, AbstractFile abstractFile) {

		try {
			BlackboardArtifact bbart = abstractFile.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_MESSAGE); //create Message artifact and then add attributes from result set.

			if (direction.equalsIgnoreCase("incoming")) {
				bbart.addAttribute(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_FROM, MODULE_NAME, phoneNumber));
			} else {

				bbart.addAttribute(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_TO, MODULE_NAME, phoneNumber));
			}

			bbart.addAttribute(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DIRECTION, MODULE_NAME, direction));
			bbart.addAttribute(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME, MODULE_NAME, date));
			bbart.addAttribute(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SUBJECT, MODULE_NAME, subject));
			bbart.addAttribute(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TEXT, MODULE_NAME, message));
			bbart.addAttribute(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_MESSAGE_TYPE, MODULE_NAME, "SMS"));

			// Create a phone number account for the phone number
			AccountInstance phoneNumAccount = commsMgr.createAccountInstance(Account.Type.PHONE, phoneNumber, MODULE_NAME, abstractFile);
			List<AccountInstance> accountInstanceList = new ArrayList<AccountInstance>();
			accountInstanceList.add(phoneNumAccount);

			//  Create a Message relationship
			commsMgr.addRelationships(deviceAccount, accountInstanceList, bbart);

		} catch (TskCoreException ex) {
			LOGGER.log(Level.SEVERE, "Unable to add TSK_MESSAGE artifact ", ex); //NON-NLS
		}
	}
}
