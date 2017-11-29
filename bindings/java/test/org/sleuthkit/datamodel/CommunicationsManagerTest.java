/*
 * Sleuth Kit Data Model
 *
 * Copyright 2017 Basis Technology Corp.
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
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests the CommunicationsManager API along with filters.
 *
 * Setup: - Make a SleuthkitCase SQLite database in a temp folder
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
 * --- Contact for Phone 2
*  --- Contact for Phone 5
 * -- DS2 : Has no email messages
 * --- CallLog from DEVICE to 1 (PHONE_ACCT_TYPE) on Jan 1, 2017
 * --- CallLog from 2 (PHONE_ACCT_TYPE) to DEVICE on Mar 1, 2017
 * --- CallLog from 4 to DEVICE on July 1, 2017
 * --- Msg from DEVICE to 2 (PHONE_ACCT_TYPE) on Jan 1, 2017
 * --- Msg from 2 (PHONE_ACCT_TYPE) to DEVICE on Mar 1, 2017
 * --- Msg from 4 (PHONE_ACCT_TYPE) to DEVICE on July 1, 2017
 * --- Contact for Phone 2
 * --- Contact for Phone 3
 * --- Contact for Phone 4
 * -- DS3: Has no communications / accounts, etc.
 *
 * Tests:
 * - getAccountDeviceInstances:
 * -- No filters. verify count.
 * -- Device filter for DS1 and DS2. Verify count (same as previous)
 * -- Device filter for DS2. Verify count.
 * -- Device filter for DS3. Verify nothing is returned
 * -- AccountType of Email. Verify Count
 * -- AccountType of PHONE. Verify Count.
 * -- AccountType of Email and Phone. Verify count
 * -- AccountType of CreditCard. Verify nothing is returned.
 * -- Device of DS1 and AccountType of Email. Verify count.
 * -- Device of DS1 and AccountType of Phone. Verify count.
 * -- Device of DS2 and AccountType of Email. Verify nothing is returned
 * -- Device of DS1 and AccountTypes of Email and Phone. Verify
 * -- Device of DS2 and AccountTypes of Email and Phone. Verify count
 * -- Device of DS1 & DS2 and AccountTypes of Email. Verify count
 * -- Device of DS1 & DS2 and AccountTypes of Phone. Verify count
 * -- Device of DS1 & DS2 and AccountTypes of Phone & Email. Verify count
 * -- Device of DS1 & DS2 & DS3 and AccountTypes of Phone & Email. Verify count
 *
 * - getCommunicationsCount:
 * -- Email Account A/DS1: No filters. verify count.
 * -- Email Account A/DS1: DS1. verify count (same as previous)
 * -- Email Account A/DS1: DS1 & EMAIL. verify count (same as previous)
 * -- Email Account B/DS1: DS1. verify count
 * -- Email Account B/DS1: DS1 & DS2. verify count (same as previous)
 * -- Email Account C/DS1: DS1 & DS2. verify count (same as previous)
 *
 * -- Phone2/DS1: verify count
 * -- Phone2/DS2. verify count, should be 0
 * -- Phone2/DS1: DS1 & DS2. verify count
 * -- Phone3/DS1: DS1 verify count
 * -- Phone3/DS1: DS1 & DS2. verify count
 * -- Phone1/DS1. verify count
 * -- Phone1/DS2. verify count
 * -- Phone1/DS2: DS1 & DS2. verify count
 * -- Phone4/DS1: verify count
 * -- Phone4/DS2: DS2. verify count
 * -- Phone4/DS2: DS1 & DS2. verify count
 * 
 * - getCommunications:
 * -- Email Account A/DS1: no filters.
 * -- Email Account B/DS1: no filters.
 * -- Email Accounts A/DS1 & C/DS1: no filters.
 * -- Email Accounts A/DS1 B/DS1 & C/DS1: no filters
 * 
 * -- Email Accounts A/DS1 B/DS1 & C/DS1: Filter on messages before Jan 01, 2017
 * -- Email Accounts A/DS1 B/DS1 & C/DS1: Filter on messages after Jan 01, 2017
 * -- Email Accounts A/DS1 B/DS1 & C/DS1: Filter on messages before Mar 01, 2017
 * -- Email Accounts A/DS1 B/DS1 & C/DS1: Filter on messages before Jul 01, 2017
 * -- Email Accounts A/DS1 B/DS1 & C/DS1: Filter on messages between Feb 01, 2017 & Aug 01, 2017
 * -- Email Accounts A/DS1 B/DS1 & C/DS1: Filter on messages after Jul 01, 2017
 * 
 * -- Phone 1/DS2: No filters
 * -- Phone 1/DS2: filter on CallLogs
 * -- Phone 1/DS2: filter on Contacts
 * -- Phone 1/DS2: filter on messages
 * -- Phone 2/DS1: filter on CallLogs
 * -- Phone 2/DS2: filter on CallLogs & Messages
 * -- Phone 1/DS2 & Phone2/DS1: filter on Messages & CallLogs
 * -- Phone 2/DS1 3/DS1 4/DS1 & 5/DS1:
 * -- Phone 2/DS1 3/DS1 4/DS1 & 5/DS1: filter on Messages
 * 
 * -- Phone 1/DS2, 2/DS2, 3/DS2, 4/DS2, 5/DS2
 * -- Phone 1/DS2, 2/DS2, 3/DS2, 4/DS2, 5/DS2:  filter on CallLogs & Messages
 * -- Phone 1/DS2, 2/DS2, 3/DS2, 4/DS2, 5/DS2:  filter on CallLogs & Messages before Jan 01 2017
 * -- Phone 1/DS2, 2/DS2, 3/DS2, 4/DS2, 5/DS2:  filter on CallLogs & Messages After Jan 01 2017
 * -- Phone 1/DS2, 2/DS2, 3/DS2, 4/DS2, 5/DS2:  filter on CallLogs & Messages before Mar 01 2017
 * -- Phone 1/DS2, 2/DS2, 3/DS2, 4/DS2, 5/DS2:  filter on CallLogs & Messages After Mar 01 2017
 * -- Phone 1/DS2, 2/DS2, 3/DS2, 4/DS2, 5/DS2:  filter on CallLogs & Messages before Jul 01 2017
 * -- Phone 1/DS2, 2/DS2, 3/DS2, 4/DS2, 5/DS2:  filter on CallLogs & Messages after Jul 01 2017
 * -- Phone 1/DS2, 2/DS2, 3/DS2, 4/DS2, 5/DS2:  filter on CallLogs & Messages between Feb 01 2017 & Aug 01, 2017
 * 
 * -- Email Account A/DS1, Phone 1/DS2, Phone 2/DS1: No filters
 * -- 
 *
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
	private static final String PHONENUM_5 = "555 111 5555";

	private static final String NAME_1 = "James Bond";
	private static final String NAME_2 = "Sherlock Holmes";
	private static final String NAME_3 = "Captain America";
	private static final String NAME_4 = "Iron Man";
	private static final String NAME_5 = "Wonder Woman";

	private static final long JAN_1_2017 = 1483228800;  // Jan 01 2017, 12:00:00 AM GMT
	private static final long MAR_1_2017 = 1488326400;
	private static final long JUL_1_2017 = 1498867200;

	private static final long FEB_1_2017 = 1485907200;
	private static final long AUG_1_2017 = 1501545600;
	private static final long DEC_31_2017 = 1514678400;
	private static final long DEC_31_2016 = 1483142400;

	private static String dbPath = null;

	private static final List<BlackboardArtifact> emailMessages = new ArrayList<BlackboardArtifact>();

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

				// Create a Device account for Device1
				AccountFileInstance deviceAccount_1 = caseDB.getCommunicationsManager().createAccountFileInstance(Account.Type.DEVICE, DS1_DEVICEID, MODULE_NAME, rootDirectory_1);

				// Create some email message artifacts
				BlackboardArtifact emailMsg = addEmailMsgArtifact(EMAIL_A, EMAIL_B, "", "",
						JAN_1_2017, "",
						"Text Body", "HTML Body", "RTF Body",
						"Hey There",
						1001,
						sourceContent_1);
				emailMessages.add(emailMsg);

				emailMsg = addEmailMsgArtifact(EMAIL_A, EMAIL_B + "; " + EMAIL_C, "", "",
						MAR_1_2017, "",
						"Message2 Message2 Message2", "", "",
						"You've won a million dollars",
						1002,
						sourceContent_1);
				emailMessages.add(emailMsg);

				emailMsg = addEmailMsgArtifact(EMAIL_C, EMAIL_A, "", "",
						JUL_1_2017, "",
						"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua", "", "",
						"Faux Latin",
						1003,
						sourceContent_1);
				emailMessages.add(emailMsg);

				// Add some Call logs
				addCalllogArtifact(deviceAccount_1, NAME_2, PHONENUM_2, JAN_1_2017, 100, "Outgoing", sourceContent_1);
				addCalllogArtifact(deviceAccount_1, NAME_2, PHONENUM_2, MAR_1_2017, 57, "Incoming", sourceContent_1);
				addCalllogArtifact(deviceAccount_1, NAME_3, PHONENUM_3, JUL_1_2017, 57, "Incoming", sourceContent_1);

				// Add some Messages 
				addMessageArtifact(deviceAccount_1, PHONENUM_2, JAN_1_2017, "Outgoing", "Hey there", "This is a SMS", sourceContent_1);
				addMessageArtifact(deviceAccount_1, PHONENUM_2, MAR_1_2017, "Incoming", "", "Im going to be home late :(", sourceContent_1);
				addMessageArtifact(deviceAccount_1, PHONENUM_3, JUL_1_2017, "Incoming", "New Year", "We wish you a Happy New Year", sourceContent_1);

				// Add some contacts
				addContactArtifact(deviceAccount_1, NAME_2, PHONENUM_2, "", sourceContent_1);
				addContactArtifact(deviceAccount_1, NAME_5, PHONENUM_5, "", sourceContent_1);
			}

			// Create some commmunication artiacts from DS2
			{
				VirtualDirectory rootDirectory_2 = dataSource_2.getRootDirectory();
				AbstractFile sourceContent_2 = rootDirectory_2;	// Let the root directory be the source for all artifacts

				// Create a Device accocunt for Device1
				AccountFileInstance deviceAccount_2 = caseDB.getCommunicationsManager().createAccountFileInstance(Account.Type.DEVICE, DS2_DEVICEID, MODULE_NAME, sourceContent_2);

				// Add some Call logs
				addCalllogArtifact(deviceAccount_2, NAME_1, PHONENUM_1, 1483272732, 100, "Outgoing", sourceContent_2);
				addCalllogArtifact(deviceAccount_2, NAME_2, PHONENUM_2, 1488370332, 57, "Incoming", sourceContent_2);
				addCalllogArtifact(deviceAccount_2, NAME_4, PHONENUM_4, 1498922115, 57, "Incoming", sourceContent_2);

				// Add some Messages 
				addMessageArtifact(deviceAccount_2, PHONENUM_2, JAN_1_2017, "Outgoing", "Ashley", "I must have the wrong number. Is this not Ashton?", sourceContent_2);
				addMessageArtifact(deviceAccount_2, PHONENUM_2, MAR_1_2017, "Incoming", "", "The darned train arrived almost an hour late", sourceContent_2);
				addMessageArtifact(deviceAccount_2, PHONENUM_4, JUL_1_2017, "Incoming", "List", "Milk, tomatoes, mustard, toohthpaste.", sourceContent_2);

				// Add some contacts
				addContactArtifact(deviceAccount_2, NAME_2, PHONENUM_2, "", sourceContent_2);
				addContactArtifact(deviceAccount_2, NAME_3, PHONENUM_3, "", sourceContent_2);
				addContactArtifact(deviceAccount_2, NAME_4, PHONENUM_4, "", sourceContent_2);
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
			List<AccountDeviceInstance> accountDeviceInstances2 = commsMgr.getAccountDeviceInstancesWithCommunications(null);
			assertEquals(10, accountDeviceInstances2.size());
		}

		// Test no filters - empty DeviceFilter
		{
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(),
					null);

			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithCommunications(commsFilter);
			assertEquals(10, accountDeviceInstances.size());
		}

		// Test filter - filter for DS1 and DS2
		{
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID, DS2_DEVICEID)),
					null);

			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithCommunications(commsFilter);
			assertEquals(10, accountDeviceInstances.size());
		}

		// Test filter - filter for DS3 - it has no accounts
		{
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS3_DEVICEID)),
					null);

			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithCommunications(commsFilter);
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

			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithCommunications(commsFilter);
			assertEquals(10, accountDeviceInstances.size());
		}

		// Test AccountTypeFilter - Email
		{
			CommunicationsFilter commsFilter = buildCommsFilter(
					null,
					new HashSet<Account.Type>(Arrays.asList(Account.Type.EMAIL)));

			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithCommunications(commsFilter);
			assertEquals(3, accountDeviceInstances.size());
		}

		// Test AccountTypeFilter - Phone
		{
			CommunicationsFilter commsFilter = buildCommsFilter(
					null,
					new HashSet<Account.Type>(Arrays.asList(Account.Type.PHONE)));

			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithCommunications(commsFilter);

			// @TODO EUR-884: RAMAN dont know why this returns 6, expect 5 here
			// The above call returns PHONE_NUM3/DS2 extra - it has no communication on DS2
			assertEquals(5, accountDeviceInstances.size());
		}

		// Test AccountTypeFilter - Email & Phone
		{
			CommunicationsFilter commsFilter = buildCommsFilter(
					null,
					new HashSet<Account.Type>(Arrays.asList(Account.Type.PHONE, Account.Type.EMAIL)));

			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithCommunications(commsFilter);

			// @TODO EUR-884: RAMAN dont know why this returns 9, expect 8 here
			assertEquals(8, accountDeviceInstances.size());
		}

		// Test AccountTypeFilter - CreditCard
		{
			CommunicationsFilter commsFilter = buildCommsFilter(
					null,
					new HashSet<Account.Type>(Arrays.asList(Account.Type.CREDIT_CARD)));

			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithCommunications(commsFilter);
			assertEquals(0, accountDeviceInstances.size());
		}

	}

	@Test
	public void getAccountDeviceInstanceWithFilterTests() throws TskCoreException {

		System.out.println("CommsMgr API - getAccountDeviceInstance With Filters tests");

		// Test Device & AccountType filter - DS1 & EMAIL
		{
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID)),
					new HashSet<Account.Type>(Arrays.asList(Account.Type.EMAIL)));

			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithCommunications(commsFilter);
			assertEquals(3, accountDeviceInstances.size());
		}

		// Test Device & AccountType filter - DS1 & PHONE
		{
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID)),
					new HashSet<Account.Type>(Arrays.asList(Account.Type.PHONE)));
			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithCommunications(commsFilter);
			assertEquals(2, accountDeviceInstances.size());
		}

		// Test AccountTypeFilter - DS2 & EMAIL
		{
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS2_DEVICEID)),
					new HashSet<Account.Type>(Arrays.asList(Account.Type.EMAIL)));

			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithCommunications(commsFilter);
			assertEquals(0, accountDeviceInstances.size());
		}

		// Test Device & AccountType filter - DS1 & PHONE or EMAIL
		{
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID)),
					new HashSet<Account.Type>(Arrays.asList(Account.Type.PHONE, Account.Type.EMAIL)));

			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithCommunications(commsFilter);
			assertEquals(5, accountDeviceInstances.size());
		}

		// Test Device & AccountType filter - DS2 & PHONE or EMAIL
		{
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS2_DEVICEID)),
					new HashSet<Account.Type>(Arrays.asList(Account.Type.PHONE, Account.Type.EMAIL)));

			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithCommunications(commsFilter);
			assertEquals(3, accountDeviceInstances.size());
		}

		// Test Device & AccountType filter - DS2 or DS1 & EMAIL
		{
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID, DS2_DEVICEID)),
					new HashSet<Account.Type>(Arrays.asList(Account.Type.EMAIL)));

			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithCommunications(commsFilter);
			assertEquals(3, accountDeviceInstances.size());
		}

		// Test Device & AccountType filter - DS2 or DS1 & Phone
		{
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID, DS2_DEVICEID)),
					new HashSet<Account.Type>(Arrays.asList(Account.Type.PHONE)));

			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithCommunications(commsFilter);
			assertEquals(5, accountDeviceInstances.size());
		}

		// Test Device & AccountType filter - DS2 or DS1 & Phone or Email
		{
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID, DS2_DEVICEID)),
					new HashSet<Account.Type>(Arrays.asList(Account.Type.PHONE, Account.Type.EMAIL)));

			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithCommunications(commsFilter);
			assertEquals(8, accountDeviceInstances.size());
		}

		

		// Test Device & AccountType filter - DS1 or DS2 or DS3 & Phone or Email, Date Range: communications on or BEFORE Dec 31, 2016
		{
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID, DS2_DEVICEID, DS3_DEVICEID)),
					new HashSet<Account.Type>(Arrays.asList(Account.Type.PHONE, Account.Type.EMAIL)),
					null,
					0, DEC_31_2016);

			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithCommunications(commsFilter);
			assertEquals(0, accountDeviceInstances.size());
		}

		// Test Device & AccountType filter - DS1 or DS2 or DS3 & Phone or Email, Date Range: communications on or After Jul 1, 2017
		{
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID, DS2_DEVICEID, DS3_DEVICEID)),
					new HashSet<Account.Type>(Arrays.asList(Account.Type.PHONE, Account.Type.EMAIL)),
					null,
					JUL_1_2017, 0);

			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithCommunications(commsFilter);

			// TBD EUR-884: we expect 4 account device instances here but get 5. Phone 3/DS2 is returned even though it has a Contact entry and no coummincations,
			assertEquals(4, accountDeviceInstances.size());
		}

		// Test Device & AccountType filter - DS1 or DS2 or DS3 & Phone or Email
		{
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID, DS2_DEVICEID, DS3_DEVICEID)),
					new HashSet<Account.Type>(Arrays.asList(Account.Type.PHONE, Account.Type.EMAIL)));

			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithCommunications(commsFilter);
			assertEquals(8, accountDeviceInstances.size());
		}

	}

	@Test
	public void communicationCountsWithFilterTests() throws TskCoreException {

		System.out.println("CommsMgr API - Communications count test");

		// Communications count for Email Account A/DS1: No Filters
		{
			Account account_email_A = commsMgr.getAccount(Account.Type.EMAIL, EMAIL_A);
			long count = commsMgr.getCommunicationsCount(new AccountDeviceInstance(account_email_A, DS1_DEVICEID), null);
			assertEquals(3, count);
		}

		// Communications count for Email Account A/DS1: filter on DS1 (filter doesnt apply)
		{
			Account account_email_A = commsMgr.getAccount(Account.Type.EMAIL, EMAIL_A);
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID)),
					null);

			long count = commsMgr.getCommunicationsCount(new AccountDeviceInstance(account_email_A, DS1_DEVICEID), commsFilter);
			assertEquals(3, count);
		}

		// Communications count for Email Account A/DS1: Filter on DS1 & EMAIL
		{
			Account account_email_A = commsMgr.getAccount(Account.Type.EMAIL, EMAIL_A);
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID)),
					new HashSet<Account.Type>(Arrays.asList(Account.Type.EMAIL)));

			long count = commsMgr.getCommunicationsCount(new AccountDeviceInstance(account_email_A, DS1_DEVICEID), commsFilter);
			assertEquals(3, count);
		}

		// Communications count for Email Account B/DS1, Filter on DS1
		{
			Account account_email_B = commsMgr.getAccount(Account.Type.EMAIL, EMAIL_B);
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID)),
					null);

			long count = commsMgr.getCommunicationsCount(new AccountDeviceInstance(account_email_B, DS1_DEVICEID), commsFilter);
			assertEquals(2, count);
		}

		// Communications count for Email Account B/DS1, Filter on DS1 & DS2 Device filter is NA
		{
			Account account_email_B = commsMgr.getAccount(Account.Type.EMAIL, EMAIL_B);
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID, DS2_DEVICEID)),
					null);

			long count = commsMgr.getCommunicationsCount(new AccountDeviceInstance(account_email_B, DS1_DEVICEID), commsFilter);
			assertEquals(2, count);
		}

		// Communications count for Email Account C/DS1, Filter on DS1 & DS2
		{
			Account account_email_C = commsMgr.getAccount(Account.Type.EMAIL, EMAIL_C);

			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID, DS2_DEVICEID)),
					null);

			long count = commsMgr.getCommunicationsCount(new AccountDeviceInstance(account_email_C, DS1_DEVICEID), commsFilter);
			assertEquals(2, count);
		}

		// Communications count for Phone2/DS1
		{
			Account account_phone2 = commsMgr.getAccount(Account.Type.PHONE, PHONENUM_2);
			CommunicationsFilter commsFilter = buildCommsFilter(
					null,
					null);

			long count = commsMgr.getCommunicationsCount(new AccountDeviceInstance(account_phone2, DS1_DEVICEID), commsFilter);
			assertEquals(4, count);
		}

		// Communications count for Phone2/DS2
		{
			Account account_phone2 = commsMgr.getAccount(Account.Type.PHONE, PHONENUM_2);
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS2_DEVICEID)),
					null);

			long count = commsMgr.getCommunicationsCount(new AccountDeviceInstance(account_phone2, DS2_DEVICEID), commsFilter);
			assertEquals(3, count);
		}

		// Communications count for Phone2/DS1, Filter on DS1, DS2, device filter is N/A
		{
			Account account_phone2 = commsMgr.getAccount(Account.Type.PHONE, PHONENUM_2);
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID, DS2_DEVICEID)),
					null);

			long count = commsMgr.getCommunicationsCount(new AccountDeviceInstance(account_phone2, DS1_DEVICEID), commsFilter);
			assertEquals(4, count);
		}

		// Communications count for Phone3/DS1
		{
			Account account_phone3 = commsMgr.getAccount(Account.Type.PHONE, PHONENUM_3);
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID)),
					null);

			long count = commsMgr.getCommunicationsCount(new AccountDeviceInstance(account_phone3, DS1_DEVICEID), commsFilter);
			assertEquals(2, count);
		}

		// Communications count for Phone3/DS1, Filter on DS1 & DS2, filter is N/A
		{
			Account account_phone3 = commsMgr.getAccount(Account.Type.PHONE, PHONENUM_3);
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID, DS2_DEVICEID)),
					null);

			long count = commsMgr.getCommunicationsCount(new AccountDeviceInstance(account_phone3, DS1_DEVICEID), commsFilter);
			assertEquals(2, count);
		}

		// Communications count for Phone1/DS1, expect 0
		{
			Account account_phone1 = commsMgr.getAccount(Account.Type.PHONE, PHONENUM_1);
			CommunicationsFilter commsFilter = buildCommsFilter(
					null,
					null);

			long count = commsMgr.getCommunicationsCount(new AccountDeviceInstance(account_phone1, DS1_DEVICEID), commsFilter);
			assertEquals(0, count);
		}

		// Communications count for Phone1/DS2
		{
			Account account_phone1 = commsMgr.getAccount(Account.Type.PHONE, PHONENUM_1);
			CommunicationsFilter commsFilter = buildCommsFilter(
					null,
					null);

			long count = commsMgr.getCommunicationsCount(new AccountDeviceInstance(account_phone1, DS2_DEVICEID), commsFilter);
			assertEquals(1, count);
		}

		// Communications count for Phone1/DS2, Filter on DS1 & DS2, filter is NA
		{
			Account account_phone1 = commsMgr.getAccount(Account.Type.PHONE, PHONENUM_1);
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID, DS2_DEVICEID)),
					null);

			long count = commsMgr.getCommunicationsCount(new AccountDeviceInstance(account_phone1, DS2_DEVICEID), commsFilter);
			assertEquals(1, count);
		}

		// Communications count for Phone4/DS1, expect 0
		{
			Account account_phone4 = commsMgr.getAccount(Account.Type.PHONE, PHONENUM_4);
			CommunicationsFilter commsFilter = buildCommsFilter(
					null,
					null);

			long count = commsMgr.getCommunicationsCount(new AccountDeviceInstance(account_phone4, DS1_DEVICEID), commsFilter);
			assertEquals(0, count);
		}

		// Communications count for Phone4/DS2, Filter on DS2
		{
			Account account_phone4 = commsMgr.getAccount(Account.Type.PHONE, PHONENUM_4);
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS2_DEVICEID)),
					null);

			long count = commsMgr.getCommunicationsCount(new AccountDeviceInstance(account_phone4, DS2_DEVICEID), commsFilter);
			assertEquals(2, count);
		}

		// Communications count for Phone4/DS2, Filter on DS1 & DS2, filter is NA
		{
			Account account_phone4 = commsMgr.getAccount(Account.Type.PHONE, PHONENUM_4);
			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS1_DEVICEID, DS2_DEVICEID)),
					null);

			long count = commsMgr.getCommunicationsCount(new AccountDeviceInstance(account_phone4, DS2_DEVICEID), commsFilter);
			assertEquals(2, count);
		}

	}

	@Test
	public void communicationsWithFilterTests() throws TskCoreException {

		System.out.println("CommsMgr API - Get Communications test");

		// Communications for Email Account A/DS1: No Filters
		{
			Set<AccountDeviceInstance> accountDeviceInstanceList = new HashSet<AccountDeviceInstance>(Arrays.asList(
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.EMAIL, EMAIL_A), DS1_DEVICEID)
			));

			Set<BlackboardArtifact> communications = commsMgr.getCommunications(accountDeviceInstanceList, null);
			assertEquals(3, communications.size());

			long count = commsMgr.getCommunicationsCount(accountDeviceInstanceList.iterator().next(), null);
			assertEquals(count, communications.size());
		}

		// Communications for Email Account B/DS1: No Filters
		{
			Set<AccountDeviceInstance> accountDeviceInstanceList = new HashSet<AccountDeviceInstance>(Arrays.asList(
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.EMAIL, EMAIL_B), DS1_DEVICEID)
			));

			Set<BlackboardArtifact> communications = commsMgr.getCommunications(accountDeviceInstanceList, null);
			assertEquals(2, communications.size());
		}

		// Communications for Email Account A/DS1 & C/DS1: No Filters
		{
			Set<AccountDeviceInstance> accountDeviceInstanceList = new HashSet<AccountDeviceInstance>(Arrays.asList(
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.EMAIL, EMAIL_A), DS1_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.EMAIL, EMAIL_C), DS1_DEVICEID)
			));

			Set<BlackboardArtifact> communications = commsMgr.getCommunications(accountDeviceInstanceList, null);
			assertEquals(3, communications.size());
		}

		// Communications for Email Account A/DS1 B/DS1 & C/DS1: No Filters
		{
			Set<AccountDeviceInstance> accountDeviceInstanceList = new HashSet<AccountDeviceInstance>(Arrays.asList(
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.EMAIL, EMAIL_A), DS1_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.EMAIL, EMAIL_B), DS1_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.EMAIL, EMAIL_C), DS1_DEVICEID)
			));

			Set<BlackboardArtifact> communications = commsMgr.getCommunications(accountDeviceInstanceList, null);
			assertEquals(3, communications.size());
		}

		// Communications for Email Account A/DS1 B/DS1 & C/DS1: Filter on DS2, filter is N/A
		{
			Set<AccountDeviceInstance> accountDeviceInstanceList = new HashSet<AccountDeviceInstance>(Arrays.asList(
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.EMAIL, EMAIL_A), DS1_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.EMAIL, EMAIL_B), DS1_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.EMAIL, EMAIL_C), DS1_DEVICEID)
			));

			CommunicationsFilter commsFilter = buildCommsFilter(
					new HashSet<String>(Arrays.asList(DS2_DEVICEID)),
					null);

			Set<BlackboardArtifact> communications = commsMgr.getCommunications(accountDeviceInstanceList, commsFilter);
			assertEquals(3, communications.size());
		}

		// Communications for Email Account A/DS1 B/DS1 & C/DS1: Filter on messages  on or before Jan 1, 2017
		{
			Set<AccountDeviceInstance> accountDeviceInstanceList = new HashSet<AccountDeviceInstance>(Arrays.asList(
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.EMAIL, EMAIL_A), DS1_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.EMAIL, EMAIL_B), DS1_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.EMAIL, EMAIL_C), DS1_DEVICEID)
			));

			CommunicationsFilter commsFilter = buildCommsFilter(
					null,
					null,
					null,
					0, JAN_1_2017);

			Set<BlackboardArtifact> communications = commsMgr.getCommunications(accountDeviceInstanceList, commsFilter);
			assertEquals(1, communications.size());
		}

		// Communications for Email Account A/DS1 B/DS1 & C/DS1: Filter on messages on or after Jan 1, 2017
		{
			Set<AccountDeviceInstance> accountDeviceInstanceList = new HashSet<AccountDeviceInstance>(Arrays.asList(
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.EMAIL, EMAIL_A), DS1_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.EMAIL, EMAIL_B), DS1_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.EMAIL, EMAIL_C), DS1_DEVICEID)
			));

			CommunicationsFilter commsFilter = buildCommsFilter(
					null,
					null,
					null,
					JAN_1_2017, 0);

			Set<BlackboardArtifact> communications = commsMgr.getCommunications(accountDeviceInstanceList, commsFilter);
			assertEquals(3, communications.size());
		}

		// Communications for Email Account A/DS1 B/DS1 & C/DS1: Filter on messages on or before Mar 1, 2017
		{
			Set<AccountDeviceInstance> accountDeviceInstanceList = new HashSet<AccountDeviceInstance>(Arrays.asList(
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.EMAIL, EMAIL_A), DS1_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.EMAIL, EMAIL_B), DS1_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.EMAIL, EMAIL_C), DS1_DEVICEID)
			));

			CommunicationsFilter commsFilter = buildCommsFilter(
					null,
					null,
					null,
					0, MAR_1_2017);

			Set<BlackboardArtifact> communications = commsMgr.getCommunications(accountDeviceInstanceList, commsFilter);
			assertEquals(2, communications.size());
		}

		// Communications for Email Account A/DS1 B/DS1 & C/DS1: Filter on messages on or before Jul 1, 2017
		{
			Set<AccountDeviceInstance> accountDeviceInstanceList = new HashSet<AccountDeviceInstance>(Arrays.asList(
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.EMAIL, EMAIL_A), DS1_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.EMAIL, EMAIL_B), DS1_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.EMAIL, EMAIL_C), DS1_DEVICEID)
			));

			CommunicationsFilter commsFilter = buildCommsFilter(
					null,
					null,
					null,
					0, JUL_1_2017);

			Set<BlackboardArtifact> communications = commsMgr.getCommunications(accountDeviceInstanceList, commsFilter);
			assertEquals(3, communications.size());
		}

		// Communications for Email Account A/DS1 B/DS1 & C/DS1: Filter on messages between  Feb 1, 2017 & Aug 01 2017
		{
			Set<AccountDeviceInstance> accountDeviceInstanceList = new HashSet<AccountDeviceInstance>(Arrays.asList(
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.EMAIL, EMAIL_A), DS1_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.EMAIL, EMAIL_B), DS1_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.EMAIL, EMAIL_C), DS1_DEVICEID)
			));

			CommunicationsFilter commsFilter = buildCommsFilter(
					null,
					null,
					null,
					FEB_1_2017, AUG_1_2017);

			Set<BlackboardArtifact> communications = commsMgr.getCommunications(accountDeviceInstanceList, commsFilter);
			assertEquals(2, communications.size());
		}

		// Communications for Email Account A/DS1 B/DS1 & C/DS1: Filter on messages on or After  Jul 1, 2017 
		{
			Set<AccountDeviceInstance> accountDeviceInstanceList = new HashSet<AccountDeviceInstance>(Arrays.asList(
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.EMAIL, EMAIL_A), DS1_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.EMAIL, EMAIL_B), DS1_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.EMAIL, EMAIL_C), DS1_DEVICEID)
			));

			CommunicationsFilter commsFilter = buildCommsFilter(
					null,
					null,
					null,
					JUL_1_2017, 0);

			Set<BlackboardArtifact> communications = commsMgr.getCommunications(accountDeviceInstanceList, commsFilter);
			assertEquals(1, communications.size());
		}

		// Communications for Phone 1/DS2: No Filters
		{
			Set<AccountDeviceInstance> accountDeviceInstanceList = new HashSet<AccountDeviceInstance>(Arrays.asList(
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_1), DS2_DEVICEID)
			));

			Set<BlackboardArtifact> communications = commsMgr.getCommunications(accountDeviceInstanceList, null);
			assertEquals(1, communications.size());
		}

		// Communications for Phone 1/DS2: Filter on CallLogs
		{
			Set<AccountDeviceInstance> accountDeviceInstanceList = new HashSet<AccountDeviceInstance>(Arrays.asList(
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_1), DS2_DEVICEID)
			));

			CommunicationsFilter commsFilter = buildCommsFilter(
					null,
					null,
					EnumSet.of(BlackboardArtifact.ARTIFACT_TYPE.TSK_CALLLOG));

			Set<BlackboardArtifact> communications = commsMgr.getCommunications(accountDeviceInstanceList, commsFilter);
			assertEquals(1, communications.size());
		}

		// Communications for Phone 1/DS2: Filter on Contacts
		{
			Set<AccountDeviceInstance> accountDeviceInstanceList = new HashSet<AccountDeviceInstance>(Arrays.asList(
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_1), DS2_DEVICEID)
			));

			CommunicationsFilter commsFilter = buildCommsFilter(
					null,
					null,
					EnumSet.of(BlackboardArtifact.ARTIFACT_TYPE.TSK_CONTACT));

			Set<BlackboardArtifact> communications = commsMgr.getCommunications(accountDeviceInstanceList, commsFilter);
			assertEquals(0, communications.size());
		}

		// Communications for Phone 1/DS2: Filter on Message
		{
			Set<AccountDeviceInstance> accountDeviceInstanceList = new HashSet<AccountDeviceInstance>(Arrays.asList(
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_1), DS2_DEVICEID)
			));

			CommunicationsFilter commsFilter = buildCommsFilter(
					null,
					null,
					EnumSet.of(BlackboardArtifact.ARTIFACT_TYPE.TSK_MESSAGE));

			Set<BlackboardArtifact> communications = commsMgr.getCommunications(accountDeviceInstanceList, commsFilter);
			assertEquals(0, communications.size());
		}

		// Communications for Phone 2/DS1: Filter on Calllogs
		{
			Set<AccountDeviceInstance> accountDeviceInstanceList = new HashSet<AccountDeviceInstance>(Arrays.asList(
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_2), DS1_DEVICEID)
			));

			CommunicationsFilter commsFilter = buildCommsFilter(
					null,
					null,
					EnumSet.of(BlackboardArtifact.ARTIFACT_TYPE.TSK_CALLLOG));

			Set<BlackboardArtifact> communications = commsMgr.getCommunications(accountDeviceInstanceList, commsFilter);
			assertEquals(2, communications.size());
		}

		// Communications for Phone 2/DS2: Filter on Calllogs & Messages
		{
			Set<AccountDeviceInstance> accountDeviceInstanceList = new HashSet<AccountDeviceInstance>(Arrays.asList(
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_2), DS2_DEVICEID)
			));

			CommunicationsFilter commsFilter = buildCommsFilter(
					null,
					null,
					EnumSet.of(BlackboardArtifact.ARTIFACT_TYPE.TSK_MESSAGE, BlackboardArtifact.ARTIFACT_TYPE.TSK_CALLLOG));

			Set<BlackboardArtifact> communications = commsMgr.getCommunications(accountDeviceInstanceList, commsFilter);
			assertEquals(3, communications.size());
		}

		// Communications for Phone 1/DS2 & 2/DS1: Filter on Messages, Calllogs
		{
			Set<AccountDeviceInstance> accountDeviceInstanceList = new HashSet<AccountDeviceInstance>(Arrays.asList(
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_1), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_2), DS1_DEVICEID)
			));

			CommunicationsFilter commsFilter = buildCommsFilter(
					null,
					null,
					EnumSet.of(BlackboardArtifact.ARTIFACT_TYPE.TSK_MESSAGE, BlackboardArtifact.ARTIFACT_TYPE.TSK_CALLLOG));

			Set<BlackboardArtifact> communications = commsMgr.getCommunications(accountDeviceInstanceList, commsFilter);
			assertEquals(5, communications.size());
		}

		// Communications for Phone 2/DS1 3/DS1 4/DS1 & 5/DS1
		{
			Set<AccountDeviceInstance> accountDeviceInstanceList = new HashSet<AccountDeviceInstance>(Arrays.asList(
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_2), DS1_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_3), DS1_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_4), DS1_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_5), DS1_DEVICEID)
			));

			CommunicationsFilter commsFilter = buildCommsFilter(
					null,
					null,
					null);

			Set<BlackboardArtifact> communications = commsMgr.getCommunications(accountDeviceInstanceList, commsFilter);
			assertEquals(6, communications.size());
		}

		// Communications for Phone 2/DS1 3/DS1 4/DS1 & 5/DS1: Filter on Message
		{
			Set<AccountDeviceInstance> accountDeviceInstanceList = new HashSet<AccountDeviceInstance>(Arrays.asList(
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_2), DS1_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_3), DS1_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_4), DS1_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_5), DS1_DEVICEID)
			));
			CommunicationsFilter commsFilter = buildCommsFilter(
					null,
					null,
					EnumSet.of(BlackboardArtifact.ARTIFACT_TYPE.TSK_MESSAGE));

			Set<BlackboardArtifact> communications = commsMgr.getCommunications(accountDeviceInstanceList, commsFilter);
			assertEquals(3, communications.size());
		}

		// Communications for Phone 1/DS2 2/DS2 3/DS2 4/DS2 & 5/DS2
		{
			Set<AccountDeviceInstance> accountDeviceInstanceList = new HashSet<AccountDeviceInstance>(Arrays.asList(
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_1), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_2), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_3), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_4), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_5), DS2_DEVICEID)
			));

			CommunicationsFilter commsFilter = buildCommsFilter(
					null,
					null,
					null);

			Set<BlackboardArtifact> communications = commsMgr.getCommunications(accountDeviceInstanceList, commsFilter);
			assertEquals(6, communications.size());
		}

		// Communications for Phone 1/DS2 2/DS2 3/DS2 4/DS2 & 5/DS2: Filter on Calllogs, Messages
		{
			Set<AccountDeviceInstance> accountDeviceInstanceList = new HashSet<AccountDeviceInstance>(Arrays.asList(
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_1), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_2), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_3), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_4), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_5), DS2_DEVICEID)
			));

			CommunicationsFilter commsFilter = buildCommsFilter(
					null,
					null,
					EnumSet.of(BlackboardArtifact.ARTIFACT_TYPE.TSK_CALLLOG,
							BlackboardArtifact.ARTIFACT_TYPE.TSK_MESSAGE));

			Set<BlackboardArtifact> communications = commsMgr.getCommunications(accountDeviceInstanceList, commsFilter);
			assertEquals(6, communications.size());
		}

		// Communications for Phone 1/DS2 2/DS2 3/DS2 4/DS2 & 5/DS2: Filter on Calllogs, Messages, on or before Jan 01, 2017
		{
			Set<AccountDeviceInstance> accountDeviceInstanceList = new HashSet<AccountDeviceInstance>(Arrays.asList(
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_1), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_2), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_3), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_4), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_5), DS2_DEVICEID)
			));

			CommunicationsFilter commsFilter = buildCommsFilter(
					null,
					null,
					EnumSet.of(BlackboardArtifact.ARTIFACT_TYPE.TSK_CALLLOG,
							BlackboardArtifact.ARTIFACT_TYPE.TSK_MESSAGE),
					0, JAN_1_2017);

			Set<BlackboardArtifact> communications = commsMgr.getCommunications(accountDeviceInstanceList, commsFilter);
			assertEquals(2, communications.size());
		}

		// Communications for Phone 1/DS2 2/DS2 3/DS2 4/DS2 & 5/DS2: Filter on Calllogs, Messages, on or after Jan 01, 2017
		{
			Set<AccountDeviceInstance> accountDeviceInstanceList = new HashSet<AccountDeviceInstance>(Arrays.asList(
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_1), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_2), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_3), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_4), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_5), DS2_DEVICEID)
			));

			CommunicationsFilter commsFilter = buildCommsFilter(
					null,
					null,
					EnumSet.of(BlackboardArtifact.ARTIFACT_TYPE.TSK_CALLLOG,
							BlackboardArtifact.ARTIFACT_TYPE.TSK_MESSAGE),
					JAN_1_2017, 0);

			Set<BlackboardArtifact> communications = commsMgr.getCommunications(accountDeviceInstanceList, commsFilter);
			assertEquals(6, communications.size());
		}

		// Communications for Phone 1/DS2 2/DS2 3/DS2 4/DS2 & 5/DS2: Filter on Calllogs, Messages, on or before Mar 01, 2017
		{
			Set<AccountDeviceInstance> accountDeviceInstanceList = new HashSet<AccountDeviceInstance>(Arrays.asList(
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_1), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_2), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_3), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_4), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_5), DS2_DEVICEID)
			));

			CommunicationsFilter commsFilter = buildCommsFilter(
					null,
					null,
					EnumSet.of(BlackboardArtifact.ARTIFACT_TYPE.TSK_CALLLOG,
							BlackboardArtifact.ARTIFACT_TYPE.TSK_MESSAGE),
					0, MAR_1_2017);

			Set<BlackboardArtifact> communications = commsMgr.getCommunications(accountDeviceInstanceList, commsFilter);
			assertEquals(4, communications.size());
		}

		// Communications for Phone 1/DS2 2/DS2 3/DS2 4/DS2 & 5/DS2: Filter on Calllogs, Messages, on or after Mar 01, 2017
		{
			Set<AccountDeviceInstance> accountDeviceInstanceList = new HashSet<AccountDeviceInstance>(Arrays.asList(
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_1), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_2), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_3), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_4), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_5), DS2_DEVICEID)
			));

			CommunicationsFilter commsFilter = buildCommsFilter(
					null,
					null,
					EnumSet.of(BlackboardArtifact.ARTIFACT_TYPE.TSK_CALLLOG,
							BlackboardArtifact.ARTIFACT_TYPE.TSK_MESSAGE),
					MAR_1_2017, 0);

			Set<BlackboardArtifact> communications = commsMgr.getCommunications(accountDeviceInstanceList, commsFilter);
			assertEquals(4, communications.size());
		}

		// Communications for Phone 1/DS2 2/DS2 3/DS2 4/DS2 & 5/DS2: Filter on Calllogs, Messages, on or after Mar 01, 2017
		{
			Set<AccountDeviceInstance> accountDeviceInstanceList = new HashSet<AccountDeviceInstance>(Arrays.asList(
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_1), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_2), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_3), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_4), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_5), DS2_DEVICEID)
			));

			CommunicationsFilter commsFilter = buildCommsFilter(
					null,
					null,
					EnumSet.of(BlackboardArtifact.ARTIFACT_TYPE.TSK_CALLLOG,
							BlackboardArtifact.ARTIFACT_TYPE.TSK_MESSAGE),
					MAR_1_2017, 0);

			Set<BlackboardArtifact> communications = commsMgr.getCommunications(accountDeviceInstanceList, commsFilter);
			assertEquals(4, communications.size());
		}

		// Communications for Phone 1/DS2 2/DS2 3/DS2 4/DS2 & 5/DS2: Filter on Calllogs, Messages, on or before Jul 01, 2017
		{
			Set<AccountDeviceInstance> accountDeviceInstanceList = new HashSet<AccountDeviceInstance>(Arrays.asList(
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_1), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_2), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_3), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_4), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_5), DS2_DEVICEID)
			));

			CommunicationsFilter commsFilter = buildCommsFilter(
					null,
					null,
					EnumSet.of(BlackboardArtifact.ARTIFACT_TYPE.TSK_CALLLOG,
							BlackboardArtifact.ARTIFACT_TYPE.TSK_MESSAGE),
					0, JUL_1_2017);

			Set<BlackboardArtifact> communications = commsMgr.getCommunications(accountDeviceInstanceList, commsFilter);
			assertEquals(6, communications.size());
		}

		// Communications for Phone 1/DS2 2/DS2 3/DS2 4/DS2 & 5/DS2: Filter on Calllogs, Messages, on or after Jul 01, 2017
		{
			Set<AccountDeviceInstance> accountDeviceInstanceList = new HashSet<AccountDeviceInstance>(Arrays.asList(
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_1), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_2), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_3), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_4), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_5), DS2_DEVICEID)
			));

			CommunicationsFilter commsFilter = buildCommsFilter(
					null,
					null,
					EnumSet.of(BlackboardArtifact.ARTIFACT_TYPE.TSK_CALLLOG,
							BlackboardArtifact.ARTIFACT_TYPE.TSK_MESSAGE),
					JUL_1_2017, 0);

			Set<BlackboardArtifact> communications = commsMgr.getCommunications(accountDeviceInstanceList, commsFilter);
			assertEquals(2, communications.size());
		}

		// Communications for Phone 1/DS2 2/DS2 3/DS2 4/DS2 & 5/DS2: Filter on Calllogs, Messages, between Feb 01 2017, and Aug 01, 2017
		{
			Set<AccountDeviceInstance> accountDeviceInstanceList = new HashSet<AccountDeviceInstance>(Arrays.asList(
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_1), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_2), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_3), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_4), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_5), DS2_DEVICEID)
			));

			CommunicationsFilter commsFilter = buildCommsFilter(
					null,
					null,
					EnumSet.of(BlackboardArtifact.ARTIFACT_TYPE.TSK_CALLLOG,
							BlackboardArtifact.ARTIFACT_TYPE.TSK_MESSAGE),
					FEB_1_2017, AUG_1_2017);

			Set<BlackboardArtifact> communications = commsMgr.getCommunications(accountDeviceInstanceList, commsFilter);
			assertEquals(4, communications.size());
		}

		// Communications for Email A/DS1, Phone 1/DS2  2/DS1: No Filters
		{
			Set<AccountDeviceInstance> accountDeviceInstanceList = new HashSet<AccountDeviceInstance>(Arrays.asList(
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.EMAIL, EMAIL_A), DS1_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_1), DS2_DEVICEID),
					new AccountDeviceInstance(commsMgr.getAccount(Account.Type.PHONE, PHONENUM_2), DS1_DEVICEID)
			));

			Set<BlackboardArtifact> communications = commsMgr.getCommunications(accountDeviceInstanceList, null);
			assertEquals(8, communications.size());
		}

	}

	/**
	 * Builds CommunicationsFilter
	 *
	 * @param deviceSet      - set of device ids for DeviceFilter
	 * @param accountTypeSet - set of account types for AccountTypefilter
	 *
	 * @return
	 */
	private static CommunicationsFilter buildCommsFilter(Set<String> deviceSet, Set<Account.Type> accountTypeSet) {

		return buildCommsFilter(deviceSet, accountTypeSet, null);
	}

	/**
	 * Builds CommunicationsFilter.
	 *
	 * @param deviceSet           - set of device ids for DeviceFilter
	 * @param accountTypeSet      - set of account types for AccountTypefilter
	 * @param relationshipTypeSet - set of blackboard artifact types for
	 *                            relationship filters
	 *
	 * @return
	 */
	private static CommunicationsFilter buildCommsFilter(Set<String> deviceSet, Set<Account.Type> accountTypeSet, Set<BlackboardArtifact.ARTIFACT_TYPE> relationshipTypeSet) {
		return buildCommsFilter(deviceSet, accountTypeSet, relationshipTypeSet, 0, 0);
	}

	/**
	 * Builds CommunicationsFilter.
	 *
	 * @param deviceSet           - set of device ids for DeviceFilter
	 * @param accountTypeSet      - set of account types for AccountTypefilter
	 * @param relationshipTypeSet - set of blackboard artifact types for
	 *                            relationship filters
	 * @param startDate           - start date for DateRangeFilter
	 * @param endDate             - end date for DateRangeFilter
	 *
	 * @return
	 */
	private static CommunicationsFilter buildCommsFilter(Set<String> deviceSet, Set<Account.Type> accountTypeSet, 
			Set<BlackboardArtifact.ARTIFACT_TYPE> relationshipTypeSet, long startDate, long endDate) {

		if ((null == deviceSet) && (null == accountTypeSet) && (null == relationshipTypeSet) && (0 == startDate) && (0 == endDate)) {
			return null;
		}

		CommunicationsFilter commsFilter = new CommunicationsFilter();
		if (null != deviceSet) {
			commsFilter.addAndFilter(new org.sleuthkit.datamodel.CommunicationsFilter.DeviceFilter(deviceSet));
		}
		if (null != accountTypeSet) {
			commsFilter.addAndFilter(new org.sleuthkit.datamodel.CommunicationsFilter.AccountTypeFilter(accountTypeSet));
		}
		if (null != relationshipTypeSet) {
			commsFilter.addAndFilter(new org.sleuthkit.datamodel.CommunicationsFilter.RelationshipTypeFilter(relationshipTypeSet));
		}
		if ((0 != startDate) || (0 != endDate)) {
			commsFilter.addAndFilter(new org.sleuthkit.datamodel.CommunicationsFilter.DateRangeFilter(startDate, endDate));
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

		AccountFileInstance senderAccountInstance = null;
		if (senderAddressList.size() == 1) {
			senderAddress = senderAddressList.get(0);
			try {
				senderAccountInstance = commsMgr.createAccountFileInstance(Account.Type.EMAIL, senderAddress, MODULE_NAME, abstractFile);
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

		List<AccountFileInstance> recipientAccountInstances = new ArrayList<AccountFileInstance>();
		for (String addr : recipientAddresses) {
			try {
				AccountFileInstance recipientAccountInstance
						= commsMgr.createAccountFileInstance(Account.Type.EMAIL, addr,
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
			commsMgr.addRelationships(senderAccountInstance, recipientAccountInstances, bbart, dateSent);

		} catch (TskCoreException ex) {
			LOGGER.log(Level.SEVERE, "Failed to add Email artifact", ex);
		} catch (TskDataException ex) {
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

		Pattern p = Pattern.compile("\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,4}\\b",
				Pattern.CASE_INSENSITIVE);
		Matcher m = p.matcher(input);
		Set<String> emailAddresses = new HashSet<String>();
		while (m.find()) {
			emailAddresses.add(m.group());
		}
		return emailAddresses;
	}

	/*
	 * Adds an CallLog artifact. Also creates PHONE account for the given phone
	 * number and creates a relationship between the device account and the
	 * Phone account AccountInstances, if needed, and adds relationships between
	 * the accounts.
	 */
	private static void addCalllogArtifact(AccountFileInstance deviceAccount, String name, String phoneNumber, long date, long duration, String direction, AbstractFile abstractFile) {

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
			AccountFileInstance phoneNumAccount = commsMgr.createAccountFileInstance(Account.Type.PHONE, phoneNumber, MODULE_NAME, abstractFile);
			List<AccountFileInstance> accountInstanceList = new ArrayList<AccountFileInstance>();
			accountInstanceList.add(phoneNumAccount);

			//  Create a Call Log relationship
			commsMgr.addRelationships(deviceAccount, accountInstanceList, bbart, date);

		} catch (TskCoreException ex) {
			LOGGER.log(Level.SEVERE, "Unable to add CallLog artifact ", ex); //NON-NLS
		} catch (TskDataException ex) {
			LOGGER.log(Level.SEVERE, "Unable to add CallLog artifact ", ex); //NON-NLS
		}
	}

	private static void addMessageArtifact(AccountFileInstance deviceAccount, String phoneNumber, long date, String direction, String subject, String message, AbstractFile abstractFile) {

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
			AccountFileInstance phoneNumAccount = commsMgr.createAccountFileInstance(Account.Type.PHONE, phoneNumber, MODULE_NAME, abstractFile);
			List<AccountFileInstance> accountInstanceList = new ArrayList<AccountFileInstance>();
			accountInstanceList.add(phoneNumAccount);

			//  Create a Message relationship
			commsMgr.addRelationships(deviceAccount, accountInstanceList, bbart, date);

		} catch (TskCoreException ex) {
			LOGGER.log(Level.SEVERE, "Unable to add TSK_MESSAGE artifact ", ex); //NON-NLS
		} catch (TskDataException ex) {
			LOGGER.log(Level.SEVERE, "Unable to add TSK_MESSAGE artifact ", ex); //NON-NLS
		}
	}

	private static void addContactArtifact(AccountFileInstance deviceAccount, String name, String phoneNumber, String emailAddr, AbstractFile abstractFile) {

		try {
			BlackboardArtifact bbart = abstractFile.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_CONTACT); // create a CONTACT artifact

			bbart.addAttribute(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME, MODULE_NAME, name));

			bbart.addAttribute(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PHONE_NUMBER, MODULE_NAME, phoneNumber));
			bbart.addAttribute(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL, MODULE_NAME, emailAddr));

			// Create a phone number account for the phone number
			AccountFileInstance phoneNumAccount = commsMgr.createAccountFileInstance(Account.Type.PHONE, phoneNumber, MODULE_NAME, abstractFile);
			List<AccountFileInstance> accountInstanceList = new ArrayList<AccountFileInstance>();
			accountInstanceList.add(phoneNumAccount);

			//  Create a CONTACT relationship
			commsMgr.addRelationships(deviceAccount, accountInstanceList, bbart, 0);

		} catch (TskCoreException ex) {
			LOGGER.log(Level.SEVERE, "Unable to add Contact artifact ", ex); //NON-NLS
		} catch (TskDataException ex) {
			LOGGER.log(Level.SEVERE, "Unable to add Contact artifact ", ex); //NON-NLS
		}
	}

}
