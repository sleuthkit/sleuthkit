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
import java.util.Collections;
import static java.util.Collections.singleton;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
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
import static org.sleuthkit.datamodel.Account.Type.CREDIT_CARD;
import static org.sleuthkit.datamodel.Account.Type.EMAIL;
import static org.sleuthkit.datamodel.Account.Type.PHONE;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_CALLLOG;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_CONTACT;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_EMAIL_MSG;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_MESSAGE;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_END;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_RCVD;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_SENT;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_START;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DIRECTION;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL_BCC;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL_CC;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL_CONTENT_HTML;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL_CONTENT_PLAIN;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL_CONTENT_RTF;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL_FROM;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL_TO;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_HEADERS;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_MESSAGE_TYPE;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_MSG_ID;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PHONE_NUMBER;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_FROM;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_TO;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SUBJECT;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TEXT;
import static org.sleuthkit.datamodel.CollectionUtils.hashSetOf;
import org.sleuthkit.datamodel.CommunicationsFilter.AccountTypeFilter;
import org.sleuthkit.datamodel.CommunicationsFilter.DateRangeFilter;
import org.sleuthkit.datamodel.CommunicationsFilter.DeviceFilter;
import org.sleuthkit.datamodel.CommunicationsFilter.RelationshipTypeFilter;
import static org.sleuthkit.datamodel.Relationship.Type.CALL_LOG;
import static org.sleuthkit.datamodel.Relationship.Type.CONTACT;
import static org.sleuthkit.datamodel.Relationship.Type.MESSAGE;

/**
 * Tests the CommunicationsManager API along with filters.
 *
 * Setup: - Make a SleuthkitCase SQLite database in a temp folder - Add three
 * Virtual Directories as data sources (DS1, DS2, DS3). We should specify the
 * device IDs for consistency. - We want to have at least two account types and
 * 3 accounts per type with different forms of relationships. Something like: --
 * DS1 (assume it is EMAIL A): --- Email Msg from A (EMAIL_ACCT_TYPE) to B
 * (EMAIL_ACCT_TYPE) on Jan 1, 2017 --- Email Msg from A to B and C on Mar 1,
 * 2017 --- Email Msg from C to A on July 1, 2017 --- CallLog from DEVICE to 2
 * (PHONE_ACCT_TYPE) on Jan 1, 2017 --- CallLog from 2 (PHONE_ACCT_TYPE) to
 * DEVICE on Mar 1, 2017 --- CallLog from 3 to DEVICE on July 1, 2017 --- Msg
 * from DEVICE to 2 (PHONE_ACCT_TYPE) on Jan 1, 2017 --- Msg from 2
 * (PHONE_ACCT_TYPE) to DEVICE on Mar 1, 2017 --- Msg from 3 (PHONE_ACCT_TYPE)
 * to DEVICE on July 1, 2017 --- Contact for Phone 2 --- Contact for Phone 5 --
 * DS2 : Has no email messages --- CallLog from DEVICE to 1 (PHONE_ACCT_TYPE) on
 * Jan 1, 2017 --- CallLog from 2 (PHONE_ACCT_TYPE) to DEVICE on Mar 1, 2017 ---
 * CallLog from 4 to DEVICE on July 1, 2017 --- Msg from DEVICE to 2
 * (PHONE_ACCT_TYPE) on Jan 1, 2017 --- Msg from 2 (PHONE_ACCT_TYPE) to DEVICE
 * on Mar 1, 2017 --- Msg from 4 (PHONE_ACCT_TYPE) to DEVICE on July 1, 2017 ---
 * Contact for Phone 2 --- Contact for Phone 3 --- Contact for Phone 4 -- DS3:
 * Has no communications / accounts, etc.
 *
 * Tests: - getAccountDeviceInstances: -- No filters. verify count. -- Device
 * filter for DS1 and DS2. Verify count (same as previous) -- Device filter for
 * DS2. Verify count. -- Device filter for DS3. Verify nothing is returned --
 * AccountType of Email. Verify Count -- AccountType of PHONE. Verify Count. --
 * AccountType of Email and Phone. Verify count -- AccountType of CreditCard.
 * Verify nothing is returned. -- Device of DS1 and AccountType of Email. Verify
 * count. -- Device of DS1 and AccountType of Phone. Verify count. -- Device of
 * DS2 and AccountType of Email. Verify nothing is returned -- Device of DS1 and
 * AccountTypes of Email and Phone. Verify -- Device of DS2 and AccountTypes of
 * Email and Phone. Verify count -- Device of DS1 & DS2 and AccountTypes of
 * Email. Verify count -- Device of DS1 & DS2 and AccountTypes of Phone. Verify
 * count -- Device of DS1 & DS2 and AccountTypes of Phone & Email. Verify count
 * -- Device of DS1 & DS2 & DS3 and AccountTypes of Phone & Email. Verify count
 *
 * - getRelationshipSourcesCount: -- Email Account A/DS1: No filters. verify
 * count. -- Email Account A/DS1: DS1. verify count (same as previous) -- Email
 * Account A/DS1: DS1 & EMAIL. verify count (same as previous) -- Email Account
 * B/DS1: DS1. verify count -- Email Account B/DS1: DS1 & DS2. verify count
 * (same as previous) -- Email Account C/DS1: DS1 & DS2. verify count (same as
 * previous)
 *
 * -- Phone2/DS1: verify count -- Phone2/DS2. verify count, should be 0 --
 * Phone2/DS1: DS1 & DS2. verify count -- Phone3/DS1: DS1 verify count --
 * Phone3/DS1: DS1 & DS2. verify count -- Phone1/DS1. verify count --
 * Phone1/DS2. verify count -- Phone1/DS2: DS1 & DS2. verify count --
 * Phone4/DS1: verify count -- Phone4/DS2: DS2. verify count -- Phone4/DS2: DS1
 * & DS2. verify count
 *
 * - getRelationshipSources: -- Email Account A/DS1: no filters. -- Email
 * Account B/DS1: no filters. -- Email Accounts A/DS1 & C/DS1: no filters. --
 * Email Accounts A/DS1 B/DS1 & C/DS1: no filters
 *
 * -- Email Accounts A/DS1 B/DS1 & C/DS1: Filter on messages before Jan 01, 2017
 * -- Email Accounts A/DS1 B/DS1 & C/DS1: Filter on messages after Jan 01, 2017
 * -- Email Accounts A/DS1 B/DS1 & C/DS1: Filter on messages before Mar 01, 2017
 * -- Email Accounts A/DS1 B/DS1 & C/DS1: Filter on messages before Jul 01, 2017
 * -- Email Accounts A/DS1 B/DS1 & C/DS1: Filter on messages between Feb 01,
 * 2017 & Aug 01, 2017 -- Email Accounts A/DS1 B/DS1 & C/DS1: Filter on messages
 * after Jul 01, 2017
 *
 * -- Phone 1/DS2: No filters -- Phone 1/DS2: filter on CallLogs -- Phone 1/DS2:
 * filter on Contacts -- Phone 1/DS2: filter on messages -- Phone 2/DS1: filter
 * on CallLogs -- Phone 2/DS2: filter on CallLogs & Messages -- Phone 1/DS2 &
 * Phone2/DS1: filter on Messages & CallLogs -- Phone 2/DS1 3/DS1 4/DS1 & 5/DS1:
 * -- Phone 2/DS1 3/DS1 4/DS1 & 5/DS1: filter on Messages
 *
 * -- Phone 1/DS2, 2/DS2, 3/DS2, 4/DS2, 5/DS2 -- Phone 1/DS2, 2/DS2, 3/DS2,
 * 4/DS2, 5/DS2: filter on CallLogs & Messages -- Phone 1/DS2, 2/DS2, 3/DS2,
 * 4/DS2, 5/DS2: filter on CallLogs & Messages before Jan 01 2017 -- Phone
 * 1/DS2, 2/DS2, 3/DS2, 4/DS2, 5/DS2: filter on CallLogs & Messages After Jan 01
 * 2017 -- Phone 1/DS2, 2/DS2, 3/DS2, 4/DS2, 5/DS2: filter on CallLogs &
 * Messages before Mar 01 2017 -- Phone 1/DS2, 2/DS2, 3/DS2, 4/DS2, 5/DS2:
 * filter on CallLogs & Messages After Mar 01 2017 -- Phone 1/DS2, 2/DS2, 3/DS2,
 * 4/DS2, 5/DS2: filter on CallLogs & Messages before Jul 01 2017 -- Phone
 * 1/DS2, 2/DS2, 3/DS2, 4/DS2, 5/DS2: filter on CallLogs & Messages after Jul 01
 * 2017 -- Phone 1/DS2, 2/DS2, 3/DS2, 4/DS2, 5/DS2: filter on CallLogs &
 * Messages between Feb 01 2017 & Aug 01, 2017
 *
 * -- Email Account A/DS1, Phone 1/DS2, Phone 2/DS1: No filters --
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

	private static final RelationshipTypeFilter COMMUNICATIONS_RELATIONSHIP_TYPE_FILTER
			= new RelationshipTypeFilter(Relationship.Type.getPredefinedCommunicationTypes());

	private static AccountDeviceInstance EMAIL_A_DS1;
	private static AccountDeviceInstance EMAIL_B_DS1;
	private static AccountDeviceInstance EMAIL_C_DS1;
	private static AccountDeviceInstance PHONE_1_DS1;
	private static AccountDeviceInstance PHONE_2_DS1;
	private static AccountDeviceInstance PHONE_1_DS2;
	private static AccountDeviceInstance PHONE_2_DS2;
	private static AccountDeviceInstance PHONE_3_DS1;
	private static AccountDeviceInstance PHONE_3_DS2;
	private static AccountDeviceInstance PHONE_4_DS1;
	private static AccountDeviceInstance PHONE_4_DS2;
	private static AccountDeviceInstance PHONE_5_DS1;
	private static AccountDeviceInstance PHONE_5_DS2;

	private static HashSet<AccountDeviceInstance> EMAILS_ABC_DS1;
	private static HashSet<AccountDeviceInstance> PHONES_2345_DS1;
	private static HashSet<AccountDeviceInstance> PHONES_12345_DS2;
	private static AccountFileInstance deviceAccount_1;
	private static AccountFileInstance deviceAccount_2;
	private static AccountDeviceInstance ds1DeviceAccount;
	private static AccountDeviceInstance ds2DeviceAccount;

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
				VirtualDirectory rootDirectory_1 = dataSource_1;
				AbstractFile sourceContent_1 = rootDirectory_1;	// Let the root dorectory be the source for all artifacts

				// Create a Device account for Device1
				deviceAccount_1 = caseDB.getCommunicationsManager().createAccountFileInstance(Account.Type.DEVICE, DS1_DEVICEID, MODULE_NAME, rootDirectory_1);
				ds1DeviceAccount = new AccountDeviceInstance(deviceAccount_1.getAccount(), DS1_DEVICEID);

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
				VirtualDirectory rootDirectory_2 = dataSource_2;
				AbstractFile sourceContent_2 = rootDirectory_2;	// Let the root directory be the source for all artifacts

				// Create a Device accocunt for Device1
				deviceAccount_2 = caseDB.getCommunicationsManager().createAccountFileInstance(Account.Type.DEVICE, DS2_DEVICEID, MODULE_NAME, sourceContent_2);
				ds2DeviceAccount = new AccountDeviceInstance(deviceAccount_2.getAccount(), DS2_DEVICEID);

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

			EMAIL_A_DS1 = new AccountDeviceInstance(commsMgr.getAccount(EMAIL, EMAIL_A), DS1_DEVICEID);
			EMAIL_B_DS1 = new AccountDeviceInstance(commsMgr.getAccount(EMAIL, EMAIL_B), DS1_DEVICEID);
			EMAIL_C_DS1 = new AccountDeviceInstance(commsMgr.getAccount(EMAIL, EMAIL_C), DS1_DEVICEID);

			EMAILS_ABC_DS1 = hashSetOf(EMAIL_A_DS1, EMAIL_B_DS1, EMAIL_C_DS1);

			PHONE_1_DS1 = new AccountDeviceInstance(commsMgr.getAccount(PHONE, PHONENUM_1), DS1_DEVICEID);
			PHONE_1_DS2 = new AccountDeviceInstance(commsMgr.getAccount(PHONE, PHONENUM_1), DS2_DEVICEID);
			PHONE_2_DS1 = new AccountDeviceInstance(commsMgr.getAccount(PHONE, PHONENUM_2), DS1_DEVICEID);
			PHONE_2_DS2 = new AccountDeviceInstance(commsMgr.getAccount(PHONE, PHONENUM_2), DS2_DEVICEID);
			PHONE_3_DS1 = new AccountDeviceInstance(commsMgr.getAccount(PHONE, PHONENUM_3), DS1_DEVICEID);
			PHONE_3_DS2 = new AccountDeviceInstance(commsMgr.getAccount(PHONE, PHONENUM_3), DS2_DEVICEID);
			PHONE_4_DS1 = new AccountDeviceInstance(commsMgr.getAccount(PHONE, PHONENUM_4), DS1_DEVICEID);
			PHONE_4_DS2 = new AccountDeviceInstance(commsMgr.getAccount(PHONE, PHONENUM_4), DS2_DEVICEID);
			PHONE_5_DS1 = new AccountDeviceInstance(commsMgr.getAccount(PHONE, PHONENUM_5), DS1_DEVICEID);
			PHONE_5_DS2 = new AccountDeviceInstance(commsMgr.getAccount(PHONE, PHONENUM_5), DS2_DEVICEID);

			PHONES_2345_DS1 = hashSetOf(PHONE_2_DS1, PHONE_3_DS1, PHONE_4_DS1, PHONE_5_DS1);
			PHONES_12345_DS2 = hashSetOf(PHONE_1_DS2, PHONE_2_DS2, PHONE_3_DS2, PHONE_4_DS2, PHONE_5_DS2);

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
			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithRelationships(null);
			assertEquals(12, accountDeviceInstances.size());

			// Test no filters - (Call or message)
			CommunicationsFilter filter = new CommunicationsFilter(Arrays.asList(COMMUNICATIONS_RELATIONSHIP_TYPE_FILTER));
			accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithRelationships(filter);
			assertEquals(10, accountDeviceInstances.size());
		}

		// Test no filters - empty DeviceFilter
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new DeviceFilter(Collections.<String>emptySet())
			));
			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(12, accountDeviceInstances.size());

			// Test no filters - empty DeviceFilter  & (call or message)
			commsFilter.addAndFilter(COMMUNICATIONS_RELATIONSHIP_TYPE_FILTER);
			accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(10, accountDeviceInstances.size());
		}

		// Test filter - filter for DS1 and DS2
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new DeviceFilter(Arrays.asList(DS1_DEVICEID, DS2_DEVICEID))
			));
			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(12, accountDeviceInstances.size());

			// Test filter - filter for DS1 and DS2 & (call or message)
			commsFilter.addAndFilter(COMMUNICATIONS_RELATIONSHIP_TYPE_FILTER);
			accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(10, accountDeviceInstances.size());
		}

		// Test filter - filter for DS3 - it has no accounts
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new DeviceFilter(Arrays.asList(DS3_DEVICEID))
			));
			List<AccountDeviceInstance> accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(0, accountDeviceInstances.size());
		}
	}

	@Test
	public void accountTypeFilterTests() throws TskCoreException {

		System.out.println("CommsMgr API - AccountType filters test");

		// Test empty AccountTypeFilter
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new AccountTypeFilter(Collections.<Account.Type>emptyList())
			));
			List<AccountDeviceInstance> accountDeviceInstances
					= commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(12, accountDeviceInstances.size());

			// Test empty AccountTypeFilter  & (call or message)
			commsFilter.addAndFilter(COMMUNICATIONS_RELATIONSHIP_TYPE_FILTER);
			accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(10, accountDeviceInstances.size());
		}

		// Test AccountTypeFilter - Email
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new AccountTypeFilter(singleton(EMAIL))
			));
			List<AccountDeviceInstance> accountDeviceInstances
					= commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(3, accountDeviceInstances.size());
		}

		// Test AccountTypeFilter - Phone
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new AccountTypeFilter(singleton(PHONE))
			));
			List<AccountDeviceInstance> accountDeviceInstances
					= commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);

			// The above call returns PHONE_NUM3/DS2 extra - it has no communication on DS2
			assertEquals(7, accountDeviceInstances.size());

			// Test AccountTypeFilter - Phone &(call or message)
			commsFilter.addAndFilter(COMMUNICATIONS_RELATIONSHIP_TYPE_FILTER);
			accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(5, accountDeviceInstances.size());
		}

		// Test AccountTypeFilter - Email & Phone
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new AccountTypeFilter(Arrays.asList(PHONE, EMAIL))
			));
			List<AccountDeviceInstance> accountDeviceInstances
					= commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(10, accountDeviceInstances.size());

			// Test AccountTypeFilter - Email & Phone (Call or message)
			commsFilter.addAndFilter(COMMUNICATIONS_RELATIONSHIP_TYPE_FILTER);
			accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(8, accountDeviceInstances.size());
		}

		// Test AccountTypeFilter - CreditCard
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new AccountTypeFilter(Arrays.asList(CREDIT_CARD))
			));

			List<AccountDeviceInstance> accountDeviceInstances
					= commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(0, accountDeviceInstances.size());
		}
	}

	@Test
	public void getRelationshipsTests() throws TskCoreException {

		System.out.println("CommsMgr API - getRelationships With Filters tests");

		// Test  DS1: EMAIL A <-> EMAIL B, no filters
		{

			List<Content> accountDeviceInstances
					= commsMgr.getRelationshipSources(EMAIL_A_DS1, EMAIL_B_DS1, null);
			assertEquals(2, accountDeviceInstances.size());
		}

		// Test  DS1: EMAIL A <-> EMAIL c, no filters
		{

			List<Content> accountDeviceInstances
					= commsMgr.getRelationshipSources(EMAIL_A_DS1, EMAIL_C_DS1, null);
			assertEquals(2, accountDeviceInstances.size());
		}

		// Test  DS1: EMAIL B <-> EMAIL C, no filters
		{

			List<Content> accountDeviceInstances
					= commsMgr.getRelationshipSources(EMAIL_B_DS1, EMAIL_C_DS1, null);
			assertEquals(1, accountDeviceInstances.size());
		}

		// Test  DS1: EMAIL B <-> EMAIL C, contacts
		{
			CommunicationsFilter communicationsFilter = new CommunicationsFilter(Arrays.asList(
					new RelationshipTypeFilter(singleton(Relationship.Type.CONTACT))));
			List<Content> accountDeviceInstances
					= commsMgr.getRelationshipSources(EMAIL_B_DS1, EMAIL_C_DS1, communicationsFilter);
			assertEquals(0, accountDeviceInstances.size());
		}
	}

	@Test
	public void getRelatedAccountDeviceInstancesWithFilterTests() throws TskCoreException {

		System.out.println("CommsMgr API - getRelatedAccountDeviceInstances With Filters tests");

		// Test  DS1: EMAIL A, no filters
		{
			List<AccountDeviceInstance> accountDeviceInstances
					= commsMgr.getRelatedAccountDeviceInstances(EMAIL_A_DS1, null);
			assertEquals(2, accountDeviceInstances.size());

		}

		// Test  DS1: EMAIL A, filter on device and email accounts
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new DeviceFilter(singleton(DS1_DEVICEID)),
					new AccountTypeFilter(singleton(EMAIL))
			));
			List<AccountDeviceInstance> accountDeviceInstances
					= commsMgr.getRelatedAccountDeviceInstances(EMAIL_A_DS1, commsFilter);
			assertEquals(2, accountDeviceInstances.size());

		}

		// Test  DS1: EMAIL A, filter - DS2 & EMAIL
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new DeviceFilter(singleton(DS2_DEVICEID)),
					new AccountTypeFilter(singleton(EMAIL))
			));
			List<AccountDeviceInstance> accountDeviceInstances
					= commsMgr.getRelatedAccountDeviceInstances(EMAIL_A_DS1, commsFilter);
			assertEquals(0, accountDeviceInstances.size());

		}

		// Test DS1: Phone 2  , call logs
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new RelationshipTypeFilter(Arrays.asList(CALL_LOG))
			));
			List<AccountDeviceInstance> accountDeviceInstances
					= commsMgr.getRelatedAccountDeviceInstances(PHONE_2_DS1, commsFilter);
			System.out.println(accountDeviceInstances);
			assertEquals(1, accountDeviceInstances.size());
		}

		// Test DS2: Phone 1  , msgs + call logs
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new RelationshipTypeFilter(Arrays.asList(CALL_LOG, MESSAGE))
			));
			List<AccountDeviceInstance> accountDeviceInstances
					= commsMgr.getRelatedAccountDeviceInstances(PHONE_2_DS2, commsFilter);
			System.out.println(accountDeviceInstances);
			assertEquals(1, accountDeviceInstances.size());
		}
	}

	@Test
	public void getAccountDeviceInstanceWithFilterTests() throws TskCoreException {

		System.out.println("CommsMgr API - getAccountDeviceInstance With Filters tests");

		// Test Device & AccountType filter - DS1 & EMAIL
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new DeviceFilter(singleton(DS1_DEVICEID)),
					new AccountTypeFilter(singleton(EMAIL))
			));
			List<AccountDeviceInstance> accountDeviceInstances
					= commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(3, accountDeviceInstances.size());
		}

		// Test Device & AccountType filter - DS1 & PHONE
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new DeviceFilter(singleton(DS1_DEVICEID)),
					new AccountTypeFilter(singleton(PHONE))
			));
			List<AccountDeviceInstance> accountDeviceInstances
					= commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(3, accountDeviceInstances.size());

			// Test Device & AccountType filter - DS1 & PHONE & (Call or message)
			commsFilter.addAndFilter(COMMUNICATIONS_RELATIONSHIP_TYPE_FILTER);
			accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(2, accountDeviceInstances.size());
		}

		// Test AccountTypeFilter - DS2 & EMAIL
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new DeviceFilter(singleton(DS2_DEVICEID)),
					new AccountTypeFilter(singleton(EMAIL))
			));
			List<AccountDeviceInstance> accountDeviceInstances
					= commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(0, accountDeviceInstances.size());
		}

		// Test Device & AccountType filter - DS1 & PHONE or EMAIL
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new DeviceFilter(singleton(DS1_DEVICEID)),
					new AccountTypeFilter(Arrays.asList(PHONE, EMAIL))
			));
			List<AccountDeviceInstance> accountDeviceInstances
					= commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(6, accountDeviceInstances.size());

			// Test Device & AccountType filter - DS1 & (PHONE or EMAIL) & (call or message)
			commsFilter.addAndFilter(COMMUNICATIONS_RELATIONSHIP_TYPE_FILTER);
			accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(5, accountDeviceInstances.size());
		}

		// Test Device & AccountType filter - DS2 & PHONE or EMAIL
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new DeviceFilter(singleton(DS2_DEVICEID)),
					new AccountTypeFilter(Arrays.asList(PHONE, EMAIL))
			));
			List<AccountDeviceInstance> accountDeviceInstances
					= commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(4, accountDeviceInstances.size());

			// Test Device & AccountType filter - DS2 & (PHONE or EMAIL) &( call or message)
			commsFilter.addAndFilter(COMMUNICATIONS_RELATIONSHIP_TYPE_FILTER);
			accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(3, accountDeviceInstances.size());
		}

		// Test Device & AccountType filter - DS2 or DS1 & EMAIL
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new DeviceFilter(Arrays.asList(DS1_DEVICEID, DS2_DEVICEID)),
					new AccountTypeFilter(singleton(EMAIL))
			));
			List<AccountDeviceInstance> accountDeviceInstances
					= commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(3, accountDeviceInstances.size());
		}

		// Test Device & AccountType filter - DS2 or DS1 & Phone
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new DeviceFilter(Arrays.asList(DS1_DEVICEID, DS2_DEVICEID)),
					new AccountTypeFilter(singleton(PHONE))
			));
			List<AccountDeviceInstance> accountDeviceInstances
					= commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(7, accountDeviceInstances.size());

			// Test Device & AccountType filter - (DS2 or DS1) & Phone &(call or message)
			commsFilter.addAndFilter(COMMUNICATIONS_RELATIONSHIP_TYPE_FILTER);
			accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(5, accountDeviceInstances.size());
		}

		// Test Device & AccountType filter - DS2 or DS1 & Phone or Email
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new DeviceFilter(Arrays.asList(DS1_DEVICEID, DS2_DEVICEID)),
					new AccountTypeFilter(Arrays.asList(PHONE, EMAIL))
			));

			List<AccountDeviceInstance> accountDeviceInstances
					= commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(10, accountDeviceInstances.size());

			// Test Device & AccountType filter - (DS2 or DS1) & (Phone or Email) and (call or message)
			commsFilter.addAndFilter(COMMUNICATIONS_RELATIONSHIP_TYPE_FILTER);
			accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(8, accountDeviceInstances.size());
		}

		/*
		 * JIRA-906 non communication relationships (ie contact entries) get a
		 * date time of 0. This means they pass filters with no start dates, and
		 * won't pass filters with reasonable start dates. Is this the desired
		 * behaviour?
		 *
		 */
		// Test Device & AccountType filter - DS1 or DS2 or DS3 & Phone or Email, Date Range: relationships on or BEFORE Dec 31, 2016
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new DeviceFilter(Arrays.asList(DS1_DEVICEID, DS2_DEVICEID, DS3_DEVICEID)),
					new AccountTypeFilter(Arrays.asList(PHONE, EMAIL)),
					new CommunicationsFilter.DateRangeFilter(0, DEC_31_2016)
			));
			List<AccountDeviceInstance> accountDeviceInstances
					= commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(5, accountDeviceInstances.size());

			// Test Device & AccountType filter - DS1 or DS2 or DS3 & Phone or Email, Date Range: communications on or BEFORE Dec 31, 2016
			commsFilter.addAndFilter(COMMUNICATIONS_RELATIONSHIP_TYPE_FILTER);
			accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(0, accountDeviceInstances.size());
		}

		// Test Device & AccountType filter - DS1 or DS2 or DS3 & Phone or Email, Date Range: communications on or After Jul 1, 2017
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new DeviceFilter(Arrays.asList(DS1_DEVICEID, DS2_DEVICEID, DS3_DEVICEID)),
					new AccountTypeFilter(Arrays.asList(PHONE, EMAIL)),
					new CommunicationsFilter.DateRangeFilter(JUL_1_2017, 0)
			));
			List<AccountDeviceInstance> accountDeviceInstances
					= commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(8, accountDeviceInstances.size());
		}

		// Test Device & AccountType filter - DS1 or DS2 or DS3 & Phone or Email
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new DeviceFilter(Arrays.asList(DS1_DEVICEID, DS2_DEVICEID, DS3_DEVICEID)),
					new AccountTypeFilter(Arrays.asList(PHONE, EMAIL))
			));
			List<AccountDeviceInstance> accountDeviceInstances
					= commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(10, accountDeviceInstances.size());

			// Test Device & AccountType filter - (DS1 or DS2 or DS3 )& (Phone or Email) & (call or message) 
			commsFilter.addAndFilter(COMMUNICATIONS_RELATIONSHIP_TYPE_FILTER);
			accountDeviceInstances = commsMgr.getAccountDeviceInstancesWithRelationships(commsFilter);
			assertEquals(8, accountDeviceInstances.size());
		}
	}

	@Test
	public void getRelationshipSourcesCountWithFilterTests() throws TskCoreException {

		System.out.println("CommsMgr API - Communications count test");

		// relationships count for Email Account A/DS1: No Filters
		{
			long count = commsMgr.getRelationshipSourcesCount(EMAIL_A_DS1, null);
			assertEquals(3, count);
		}

		// Communications count for Email Account A/DS1: filter on DS1 (filter doesnt apply)
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new DeviceFilter(singleton(DS1_DEVICEID)))
			);
			long count = commsMgr.getRelationshipSourcesCount(EMAIL_A_DS1, commsFilter);
			assertEquals(3, count);
		}

		// Communications count for Email Account A/DS1: Filter on DS1 & EMAIL
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new DeviceFilter(singleton(DS1_DEVICEID)),
					new AccountTypeFilter(singleton(EMAIL))
			));
			long count = commsMgr.getRelationshipSourcesCount(EMAIL_A_DS1, commsFilter);
			assertEquals(3, count);
		}

		// Communications count for Email Account B/DS1, Filter on DS1
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new DeviceFilter(singleton(DS1_DEVICEID))
			));
			long count = commsMgr.getRelationshipSourcesCount(EMAIL_B_DS1, commsFilter);
			assertEquals(2, count);
		}

		// Communications count for Email Account B/DS1, Filter on DS1 & DS2 Device filter is NA
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new DeviceFilter(Arrays.asList(DS1_DEVICEID, DS2_DEVICEID))
			));
			long count = commsMgr.getRelationshipSourcesCount(EMAIL_B_DS1, commsFilter);
			assertEquals(2, count);
		}

		// Communications count for Email Account C/DS1, Filter on DS1 & DS2
		{

			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new DeviceFilter(Arrays.asList(DS1_DEVICEID, DS2_DEVICEID))
			));
			long count = commsMgr.getRelationshipSourcesCount(EMAIL_C_DS1, commsFilter);
			assertEquals(2, count);
		}

		// relationships count for Phone2/DS1
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter();
			long count = commsMgr.getRelationshipSourcesCount(PHONE_2_DS1, commsFilter);
			assertEquals(5, count);

			// Communications count for Phone2/DS1
			commsFilter.addAndFilter(COMMUNICATIONS_RELATIONSHIP_TYPE_FILTER);
			count = commsMgr.getRelationshipSourcesCount(PHONE_2_DS1, commsFilter);
			assertEquals(4, count);
		}

		// relationships count for Phone2/DS2
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter();
			long count = commsMgr.getRelationshipSourcesCount(PHONE_2_DS2, commsFilter);
			assertEquals(4, count);

			// communications count for Phone2/DS2
			commsFilter.addAndFilter(COMMUNICATIONS_RELATIONSHIP_TYPE_FILTER);
			count = commsMgr.getRelationshipSourcesCount(PHONE_2_DS2, commsFilter);
			assertEquals(3, count);
		}

		// relationships count for Phone2/DS1, Filter on DS1, DS2, device filter is N/A
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new DeviceFilter(Arrays.asList(DS1_DEVICEID, DS2_DEVICEID))
			));
			long count = commsMgr.getRelationshipSourcesCount(PHONE_2_DS1, commsFilter);
			assertEquals(5, count);

			// communications count for Phone2/DS1, Filter on DS1, DS2, device filter is N/A
			commsFilter.addAndFilter(COMMUNICATIONS_RELATIONSHIP_TYPE_FILTER);
			count = commsMgr.getRelationshipSourcesCount(PHONE_2_DS1, commsFilter);
			assertEquals(4, count);

		}

		// Communications count for Phone3/DS1
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new DeviceFilter(singleton(DS1_DEVICEID))
			));
			long count = commsMgr.getRelationshipSourcesCount(PHONE_3_DS1, commsFilter);
			assertEquals(2, count);
		}

		// Communications count for Phone3/DS1, Filter on DS1 & DS2, filter is N/A
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new DeviceFilter(Arrays.asList(DS1_DEVICEID, DS2_DEVICEID))
			));
			long count = commsMgr.getRelationshipSourcesCount(PHONE_3_DS1, commsFilter);
			assertEquals(2, count);
		}

		// Communications count for Phone1/DS1, expect 0
		{
			long count = commsMgr.getRelationshipSourcesCount(PHONE_1_DS1, null);
			assertEquals(0, count);
		}

		// Communications count for Phone1/DS2
		{
			long count = commsMgr.getRelationshipSourcesCount(PHONE_1_DS2, null);
			assertEquals(1, count);
		}

		// Communications count for Phone1/DS2, Filter on DS1 & DS2, filter is NA
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new DeviceFilter(Arrays.asList(DS1_DEVICEID, DS2_DEVICEID))
			));
			long count = commsMgr.getRelationshipSourcesCount(PHONE_1_DS2, commsFilter);
			assertEquals(1, count);
		}

		// Communications count for Phone4/DS1, expect 0
		{
			long count = commsMgr.getRelationshipSourcesCount(PHONE_4_DS1, null);
			assertEquals(0, count);
		}

		// relationships count for Phone4/DS2, Filter on DS2
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new DeviceFilter(singleton(DS2_DEVICEID))
			));

			long count = commsMgr.getRelationshipSourcesCount(PHONE_4_DS2, commsFilter);
			assertEquals(3, count);

			// Communications count for Phone4/DS2, Filter on DS2
			commsFilter.addAndFilter(COMMUNICATIONS_RELATIONSHIP_TYPE_FILTER);
			count = commsMgr.getRelationshipSourcesCount(PHONE_4_DS2, commsFilter);
			assertEquals(2, count);

		}

		// relationships count for Phone4/DS2, Filter on DS1 & DS2, filter is NA
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new DeviceFilter(Arrays.asList(DS1_DEVICEID, DS2_DEVICEID))
			));
			long count = commsMgr.getRelationshipSourcesCount(PHONE_4_DS2, commsFilter);
			assertEquals(3, count);

			// Communications count for Phone4/DS2, Filter on DS1 & DS2, filter is NA
			commsFilter.addAndFilter(COMMUNICATIONS_RELATIONSHIP_TYPE_FILTER);
			count = commsMgr.getRelationshipSourcesCount(PHONE_4_DS2, commsFilter);
			assertEquals(2, count);
		}
	}

	@Test
	public void communicationsWithFilterTests() throws TskCoreException {

		System.out.println("CommsMgr API - Get Communications test");

		// Communications for Email Account A/DS1: No Filters
		{
			Set<AccountDeviceInstance> accountDeviceInstances = singleton(EMAIL_A_DS1);

			Set<Content> communications
					= commsMgr.getRelationshipSources(accountDeviceInstances, null);
			assertEquals(3, communications.size());

			for (AccountDeviceInstance adi : accountDeviceInstances) {
				long count = commsMgr.getRelationshipSourcesCount(accountDeviceInstances.iterator().next(), null);
				final String typeSpecificID = adi.getAccount().getTypeSpecificID();

				if (EMAIL_A.equals(typeSpecificID)) {
					assertEquals(3, count);
				} else if (EMAIL_B.equals(typeSpecificID)) {
					assertEquals(2, count);
				} else if (EMAIL_C.equals(typeSpecificID)) {
					assertEquals(1, count);
				}
			}
		}

		// Communications for Email Account B/DS1: No Filters
		{
			Set<AccountDeviceInstance> accountDeviceInstances = hashSetOf(EMAIL_B_DS1);
			Set<Content> communications = commsMgr.getRelationshipSources(accountDeviceInstances, null);
			assertEquals(2, communications.size());
		}

		// Communications for Email Account A/DS1 & C/DS1: No Filters
		{
			Set<AccountDeviceInstance> accountDeviceInstances
					= hashSetOf(EMAIL_A_DS1, EMAIL_C_DS1);

			Set<Content> communications
					= commsMgr.getRelationshipSources(accountDeviceInstances, null);
			assertEquals(3, communications.size());
		}

		// Communications for Email Account A/DS1 B/DS1 & C/DS1: No Filters
		{

			Set<Content> communications
					= commsMgr.getRelationshipSources(EMAILS_ABC_DS1, null);
			assertEquals(3, communications.size());
		}

		// Communications for Email Account A/DS1 B/DS1 & C/DS1: Filter on DS2, filter is N/A
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new DeviceFilter(singleton(DS2_DEVICEID))
			));
			Set<Content> communications
					= commsMgr.getRelationshipSources(EMAILS_ABC_DS1, commsFilter);
			assertEquals(3, communications.size());
		}

		// Communications for Email Account A/DS1 B/DS1 & C/DS1: Filter on messages  on or before Jan 1, 2017
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new DateRangeFilter(0, JAN_1_2017)));
			Set<Content> communications
					= commsMgr.getRelationshipSources(EMAILS_ABC_DS1, commsFilter);
			assertEquals(1, communications.size());
		}

		// Communications for Email Account A/DS1 B/DS1 & C/DS1: Filter on messages on or after Jan 1, 2017
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new DateRangeFilter(JAN_1_2017, 0)));
			Set<Content> communications
					= commsMgr.getRelationshipSources(EMAILS_ABC_DS1, commsFilter);
			assertEquals(3, communications.size());
		}

		// Communications for Email Account A/DS1 B/DS1 & C/DS1: Filter on messages on or before Mar 1, 2017
		{

			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new DateRangeFilter(0, MAR_1_2017)));
			Set<Content> communications
					= commsMgr.getRelationshipSources(EMAILS_ABC_DS1, commsFilter);
			assertEquals(2, communications.size());
		}

		// Communications for Email Account A/DS1 B/DS1 & C/DS1: Filter on messages on or before Jul 1, 2017
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new DateRangeFilter(0, JUL_1_2017)));
			Set<Content> communications
					= commsMgr.getRelationshipSources(EMAILS_ABC_DS1, commsFilter);
			assertEquals(3, communications.size());
		}

		// Communications for Email Account A/DS1 B/DS1 & C/DS1: Filter on messages between  Feb 1, 2017 & Aug 01 2017
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new DateRangeFilter(FEB_1_2017, AUG_1_2017)));
			Set<Content> communications
					= commsMgr.getRelationshipSources(EMAILS_ABC_DS1, commsFilter);
			assertEquals(2, communications.size());
		}

		// Communications for Email Account A/DS1 B/DS1 & C/DS1: Filter on messages on or After  Jul 1, 2017 
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new DateRangeFilter(JUL_1_2017, 0)));
			Set<Content> communications
					= commsMgr.getRelationshipSources(EMAILS_ABC_DS1, commsFilter);
			assertEquals(1, communications.size());
		}

		// Communications for Phone 1/DS2: No Filters
		{
			Set<AccountDeviceInstance> accountDeviceInstances
					= hashSetOf(PHONE_1_DS2);
			Set<Content> communications
					= commsMgr.getRelationshipSources(accountDeviceInstances, null);
			assertEquals(1, communications.size());
		}

		// Communications for Phone 1/DS2: Filter on CallLogs
		{
			Set<AccountDeviceInstance> accountDeviceInstances = hashSetOf(PHONE_1_DS2);
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new RelationshipTypeFilter(singleton(CALL_LOG))));
			Set<Content> communications
					= commsMgr.getRelationshipSources(accountDeviceInstances, commsFilter);
			assertEquals(1, communications.size());
		}

		// Communications for Phone 1/DS2: Filter on Contacts
		{
			Set<AccountDeviceInstance> accountDeviceInstances = hashSetOf(PHONE_1_DS2);
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new RelationshipTypeFilter(singleton(CONTACT))));
			Set<Content> communications
					= commsMgr.getRelationshipSources(accountDeviceInstances, commsFilter);
			assertEquals(0, communications.size());
		}

		// Communications for Phone 1/DS2: Filter on Message
		{
			Set<AccountDeviceInstance> accountDeviceInstances = hashSetOf(PHONE_1_DS2);
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new RelationshipTypeFilter(singleton(MESSAGE))
			));
			Set<Content> communications
					= commsMgr.getRelationshipSources(accountDeviceInstances, commsFilter);
			assertEquals(0, communications.size());
		}

		// Communications for Phone 2/DS1: Filter on Calllogs
		{
			Set<AccountDeviceInstance> accountDeviceInstances = hashSetOf(PHONE_2_DS1);
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new RelationshipTypeFilter(singleton(CALL_LOG))));
			Set<Content> communications
					= commsMgr.getRelationshipSources(accountDeviceInstances, commsFilter);
			assertEquals(2, communications.size());
		}

		// Communications for Phone 2/DS2: Filter on Calllogs & Messages
		{
			Set<AccountDeviceInstance> accountDeviceInstances = hashSetOf(PHONE_2_DS2);
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					COMMUNICATIONS_RELATIONSHIP_TYPE_FILTER));
			Set<Content> communications
					= commsMgr.getRelationshipSources(accountDeviceInstances, commsFilter);
			assertEquals(3, communications.size());
		}

		// Communications for Phone 1/DS2 & 2/DS1: Filter on Messages, Calllogs
		{
			Set<AccountDeviceInstance> accountDeviceInstances = hashSetOf(PHONE_1_DS2, PHONE_2_DS1);
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					COMMUNICATIONS_RELATIONSHIP_TYPE_FILTER));
			Set<Content> communications
					= commsMgr.getRelationshipSources(accountDeviceInstances, commsFilter);
			assertEquals(5, communications.size());
		}

		// Communications for Phone 2/DS1 3/DS1 4/DS1 & 5/DS1
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter();
			Set<Content> communications
					= commsMgr.getRelationshipSources(PHONES_2345_DS1, commsFilter);
			assertEquals(8, communications.size());

			// Communications for Phone 2/DS1 3/DS1 4/DS1 & 5/DS1 & (Call or message)
			commsFilter.addAndFilter(COMMUNICATIONS_RELATIONSHIP_TYPE_FILTER);
			communications = commsMgr.getRelationshipSources(PHONES_2345_DS1, commsFilter);
			assertEquals(6, communications.size());
		}

		// Communications for Phone 2/DS1 3/DS1 4/DS1 & 5/DS1: Filter on Message
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new RelationshipTypeFilter(singleton(MESSAGE))));
			Set<Content> communications
					= commsMgr.getRelationshipSources(PHONES_2345_DS1, commsFilter);
			assertEquals(3, communications.size());
		}

		// relationships for Phone 1/DS2 2/DS2 3/DS2 4/DS2 & 5/DS2
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter();
			Set<Content> communications
					= commsMgr.getRelationshipSources(PHONES_12345_DS2, commsFilter);
			assertEquals(9, communications.size());

			// Communications for Phone 1/DS2 2/DS2 3/DS2 4/DS2 & 5/DS2
			commsFilter.addAndFilter(COMMUNICATIONS_RELATIONSHIP_TYPE_FILTER);
			communications = commsMgr.getRelationshipSources(PHONES_12345_DS2, commsFilter);
			assertEquals(6, communications.size());

		}

		// Communications for Phone 1/DS2 2/DS2 3/DS2 4/DS2 & 5/DS2: Filter on Calllogs, Messages
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					COMMUNICATIONS_RELATIONSHIP_TYPE_FILTER));
			Set<Content> communications
					= commsMgr.getRelationshipSources(PHONES_12345_DS2, commsFilter);
			assertEquals(6, communications.size());
		}

		// Communications for Phone 1/DS2 2/DS2 3/DS2 4/DS2 & 5/DS2: Filter on Calllogs, Messages, on or before Jan 01, 2017
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					COMMUNICATIONS_RELATIONSHIP_TYPE_FILTER,
					new CommunicationsFilter.DateRangeFilter(0, JAN_1_2017)
			));
			Set<Content> communications
					= commsMgr.getRelationshipSources(PHONES_12345_DS2, commsFilter);
			assertEquals(2, communications.size());
		}

		// Communications for Phone 1/DS2 2/DS2 3/DS2 4/DS2 & 5/DS2: Filter on Calllogs, Messages, on or after Jan 01, 2017
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					COMMUNICATIONS_RELATIONSHIP_TYPE_FILTER,
					new CommunicationsFilter.DateRangeFilter(JAN_1_2017, 0)
			));
			Set<Content> communications
					= commsMgr.getRelationshipSources(PHONES_12345_DS2, commsFilter);
			assertEquals(6, communications.size());
		}

		// Communications for Phone 1/DS2 2/DS2 3/DS2 4/DS2 & 5/DS2: Filter on Calllogs, Messages, on or before Mar 01, 2017
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					COMMUNICATIONS_RELATIONSHIP_TYPE_FILTER,
					new CommunicationsFilter.DateRangeFilter(0, MAR_1_2017)
			));
			Set<Content> communications
					= commsMgr.getRelationshipSources(PHONES_12345_DS2, commsFilter);
			assertEquals(4, communications.size());
		}

		// Communications for Phone 1/DS2 2/DS2 3/DS2 4/DS2 & 5/DS2: Filter on Calllogs, Messages, on or after Mar 01, 2017
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					COMMUNICATIONS_RELATIONSHIP_TYPE_FILTER,
					new CommunicationsFilter.DateRangeFilter(MAR_1_2017, 0)
			));
			Set<Content> communications
					= commsMgr.getRelationshipSources(PHONES_12345_DS2, commsFilter);
			assertEquals(4, communications.size());
		}

		// Communications for Phone 1/DS2 2/DS2 3/DS2 4/DS2 & 5/DS2: Filter on Calllogs, Messages, on or after Mar 01, 2017
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					COMMUNICATIONS_RELATIONSHIP_TYPE_FILTER,
					new CommunicationsFilter.DateRangeFilter(MAR_1_2017, 0)
			));
			Set<Content> communications
					= commsMgr.getRelationshipSources(PHONES_12345_DS2, commsFilter);
			assertEquals(4, communications.size());
		}

		// Communications for Phone 1/DS2 2/DS2 3/DS2 4/DS2 & 5/DS2: Filter on Calllogs, Messages, on or before Jul 01, 2017
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					COMMUNICATIONS_RELATIONSHIP_TYPE_FILTER,
					new CommunicationsFilter.DateRangeFilter(0, JUL_1_2017)
			));
			Set<Content> communications
					= commsMgr.getRelationshipSources(PHONES_12345_DS2, commsFilter);
			assertEquals(6, communications.size());
		}

		// Communications for Phone 1/DS2 2/DS2 3/DS2 4/DS2 & 5/DS2: Filter on Calllogs, Messages, on or after Jul 01, 2017
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					COMMUNICATIONS_RELATIONSHIP_TYPE_FILTER,
					new CommunicationsFilter.DateRangeFilter(JUL_1_2017, 0)
			));
			Set<Content> communications
					= commsMgr.getRelationshipSources(PHONES_12345_DS2, commsFilter);
			assertEquals(2, communications.size());
		}

		// Communications for Phone 1/DS2 2/DS2 3/DS2 4/DS2 & 5/DS2: Filter on Calllogs, Messages, between Feb 01 2017, and Aug 01, 2017
		{
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					COMMUNICATIONS_RELATIONSHIP_TYPE_FILTER,
					new CommunicationsFilter.DateRangeFilter(FEB_1_2017, AUG_1_2017)
			));
			Set<Content> communications
					= commsMgr.getRelationshipSources(PHONES_12345_DS2, commsFilter);
			assertEquals(4, communications.size());
		}

		// relationships for Email A/DS1, Phone 1/DS2  2/DS1: No Filters
		{
			Set<AccountDeviceInstance> accountDeviceInstances
					= hashSetOf(EMAIL_A_DS1, PHONE_1_DS2, PHONE_2_DS1);
			Set<Content> communications
					= commsMgr.getRelationshipSources(accountDeviceInstances, null);
			assertEquals(9, communications.size());

			// Communications for Email A/DS1, Phone 1/DS2  2/DS1: No Filters
			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(COMMUNICATIONS_RELATIONSHIP_TYPE_FILTER));
			communications = commsMgr.getRelationshipSources(accountDeviceInstances, commsFilter);
			assertEquals(8, communications.size());
		}
	}

	@Test
	public void getRelationshipCountsPairwiseTests() throws TskCoreException {
		System.out.println("CommsMgr API - Get RelationshipCountsBetween test");

		// Counts  for DS1 and PHONES 2,3,4,5, no Filter 
		{
			final Set<AccountDeviceInstance> accounts = new HashSet<AccountDeviceInstance>();
			accounts.add(ds1DeviceAccount);
			accounts.addAll(PHONES_2345_DS1);

			Map<AccountPair, Long> counts = commsMgr.getRelationshipCountsPairwise(accounts, null);

			assertEquals(3, counts.size());
			assertEquals(Long.valueOf(5), counts.get(new AccountPair(ds1DeviceAccount, PHONE_2_DS1)));
			assertEquals(Long.valueOf(2), counts.get(new AccountPair(ds1DeviceAccount, PHONE_3_DS1)));
			assertEquals(Long.valueOf(1), counts.get(new AccountPair(ds1DeviceAccount, PHONE_5_DS1)));
			assertNull(counts.get(new AccountPair(ds1DeviceAccount, PHONE_4_DS1)));

		}

		// Counts  for DS1 Email A and B and PHONES 2,3,4,5, no Filter 
		{
			final Set<AccountDeviceInstance> accounts = new HashSet<AccountDeviceInstance>();
			accounts.add(ds1DeviceAccount);
			accounts.add(EMAIL_A_DS1);
			accounts.add(EMAIL_B_DS1);
			accounts.addAll(PHONES_2345_DS1);

			Map<AccountPair, Long> counts
					= commsMgr.getRelationshipCountsPairwise(accounts, null);
			assertEquals(4, counts.size());
			assertEquals(Long.valueOf(5), counts.get(new AccountPair(ds1DeviceAccount, PHONE_2_DS1)));
			assertEquals(Long.valueOf(2), counts.get(new AccountPair(ds1DeviceAccount, PHONE_3_DS1)));
			assertEquals(Long.valueOf(1), counts.get(new AccountPair(ds1DeviceAccount, PHONE_5_DS1)));
			assertEquals(Long.valueOf(2), counts.get(new AccountPair(EMAIL_A_DS1, EMAIL_B_DS1)));
			assertNull(counts.get(new AccountPair(ds1DeviceAccount, PHONE_4_DS1)));
		}

		// Counts  for DS1, DS2,  PHONES 1, 2,3,4,5;  Filter on DS2 
		{
			final Set<AccountDeviceInstance> accounts = new HashSet<AccountDeviceInstance>();
			accounts.add(ds1DeviceAccount);
			accounts.add(ds2DeviceAccount);
			accounts.addAll(PHONES_12345_DS2);

			CommunicationsFilter commsFilter = new CommunicationsFilter(Arrays.asList(
					new DeviceFilter(singleton(DS2_DEVICEID))
			));
			Map<AccountPair, Long> counts
					= commsMgr.getRelationshipCountsPairwise(accounts, commsFilter);
			assertEquals(4, counts.size());
			assertNull(counts.get(new AccountPair(ds1DeviceAccount, PHONE_2_DS1)));
			assertNull(counts.get(new AccountPair(ds1DeviceAccount, PHONE_3_DS1)));
			assertNull(counts.get(new AccountPair(ds1DeviceAccount, PHONE_5_DS1)));
			assertNull(counts.get(new AccountPair(EMAIL_A_DS1, EMAIL_B_DS1)));
			assertNull(counts.get(new AccountPair(ds1DeviceAccount, PHONE_4_DS1)));

			assertEquals(Long.valueOf(1), counts.get(new AccountPair(ds2DeviceAccount, PHONE_1_DS2)));
			assertEquals(Long.valueOf(4), counts.get(new AccountPair(ds2DeviceAccount, PHONE_2_DS2)));
			assertEquals(Long.valueOf(1), counts.get(new AccountPair(ds2DeviceAccount, PHONE_3_DS2)));
			assertEquals(Long.valueOf(3), counts.get(new AccountPair(ds2DeviceAccount, PHONE_4_DS2)));
		}
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
				senderAccountInstance = commsMgr.createAccountFileInstance(EMAIL, senderAddress, MODULE_NAME, abstractFile);
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
						= commsMgr.createAccountFileInstance(EMAIL, addr,
								MODULE_NAME, abstractFile);
				recipientAccountInstances.add(recipientAccountInstance);
			} catch (TskCoreException ex) {
				LOGGER.log(Level.WARNING, "Failed to create account for email address  " + addr, ex); //NON-NLS
			}
		}

		addEmailAttribute(headers, TSK_HEADERS, bbattributes);
		addEmailAttribute(fromAddr, TSK_EMAIL_FROM, bbattributes);
		addEmailAttribute(toList, TSK_EMAIL_TO, bbattributes);
		addEmailAttribute(subject, TSK_SUBJECT, bbattributes);

		addEmailAttribute(dateSent, TSK_DATETIME_RCVD, bbattributes);
		addEmailAttribute(dateSent, TSK_DATETIME_SENT, bbattributes);
		addEmailAttribute(textBody, TSK_EMAIL_CONTENT_PLAIN, bbattributes);
		addEmailAttribute((String.valueOf(msgID)), TSK_MSG_ID, bbattributes);

		addEmailAttribute(ccList, TSK_EMAIL_CC, bbattributes);
		addEmailAttribute(bccList, TSK_EMAIL_BCC, bbattributes);
		addEmailAttribute(htmlBody, TSK_EMAIL_CONTENT_HTML, bbattributes);
		addEmailAttribute(rtfBody, TSK_EMAIL_CONTENT_RTF, bbattributes);

		try {
			// Add Email artifact
			bbart = abstractFile.newArtifact(TSK_EMAIL_MSG);
			bbart.addAttributes(bbattributes);

			// Add account relationships
			commsMgr.addRelationships(senderAccountInstance, recipientAccountInstances, bbart, MESSAGE, dateSent);

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
	 * @param input input string, like the To/CC line from an email header.
	 *
	 * @return set of email addresses found in the input string.
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
			BlackboardArtifact bbart = abstractFile.newArtifact(TSK_CALLLOG); //create a call log and then add attributes from result set.
			if (direction.equalsIgnoreCase("outgoing")) { //NON-NLS
				bbart.addAttribute(new BlackboardAttribute(TSK_PHONE_NUMBER_TO, MODULE_NAME, phoneNumber));
			} else { /// Covers INCOMING and MISSED
				bbart.addAttribute(new BlackboardAttribute(TSK_PHONE_NUMBER_FROM, MODULE_NAME, phoneNumber));
			}
			bbart.addAttribute(new BlackboardAttribute(TSK_DATETIME_START, MODULE_NAME, date));
			bbart.addAttribute(new BlackboardAttribute(TSK_DATETIME_END, MODULE_NAME, duration + date));
			bbart.addAttribute(new BlackboardAttribute(TSK_DIRECTION, MODULE_NAME, direction));
			bbart.addAttribute(new BlackboardAttribute(TSK_NAME, MODULE_NAME, name));

			// Create a phone number account for the phone number
			AccountFileInstance phoneNumAccount = commsMgr.createAccountFileInstance(PHONE, phoneNumber, MODULE_NAME, abstractFile);
			List<AccountFileInstance> accountInstanceList = new ArrayList<AccountFileInstance>();
			accountInstanceList.add(phoneNumAccount);

			//  Create a Call Log relationship
			commsMgr.addRelationships(deviceAccount, accountInstanceList, bbart, CALL_LOG, date);

		} catch (TskCoreException ex) {
			LOGGER.log(Level.SEVERE, "Unable to add CallLog artifact ", ex); //NON-NLS
		} catch (TskDataException ex) {
			LOGGER.log(Level.SEVERE, "Unable to add CallLog artifact ", ex); //NON-NLS
		}
	}

	private static void addMessageArtifact(AccountFileInstance deviceAccount, String phoneNumber, long date, String direction, String subject, String message, AbstractFile abstractFile) {

		try {
			BlackboardArtifact bbart = abstractFile.newArtifact(TSK_MESSAGE); //create Message artifact and then add attributes from result set.

			if (direction.equalsIgnoreCase("incoming")) {
				bbart.addAttribute(new BlackboardAttribute(TSK_PHONE_NUMBER_FROM, MODULE_NAME, phoneNumber));
			} else {
				bbart.addAttribute(new BlackboardAttribute(TSK_PHONE_NUMBER_TO, MODULE_NAME, phoneNumber));
			}

			bbart.addAttribute(new BlackboardAttribute(TSK_DIRECTION, MODULE_NAME, direction));
			bbart.addAttribute(new BlackboardAttribute(TSK_DATETIME, MODULE_NAME, date));
			bbart.addAttribute(new BlackboardAttribute(TSK_SUBJECT, MODULE_NAME, subject));
			bbart.addAttribute(new BlackboardAttribute(TSK_TEXT, MODULE_NAME, message));
			bbart.addAttribute(new BlackboardAttribute(TSK_MESSAGE_TYPE, MODULE_NAME, "SMS"));

			// Create a phone number account for the phone number
			AccountFileInstance phoneNumAccount = commsMgr.createAccountFileInstance(PHONE, phoneNumber, MODULE_NAME, abstractFile);
			List<AccountFileInstance> accountInstanceList = new ArrayList<AccountFileInstance>();
			accountInstanceList.add(phoneNumAccount);

			//  Create a Message relationship
			commsMgr.addRelationships(deviceAccount, accountInstanceList, bbart, MESSAGE, date);

		} catch (TskCoreException ex) {
			LOGGER.log(Level.SEVERE, "Unable to add TSK_MESSAGE artifact ", ex); //NON-NLS
		} catch (TskDataException ex) {
			LOGGER.log(Level.SEVERE, "Unable to add TSK_MESSAGE artifact ", ex); //NON-NLS
		}
	}

	private static void addContactArtifact(AccountFileInstance deviceAccount, String name, String phoneNumber, String emailAddr, AbstractFile abstractFile) {

		try {
			BlackboardArtifact bbart = abstractFile.newArtifact(TSK_CONTACT); // create a CONTACT artifact

			bbart.addAttribute(new BlackboardAttribute(TSK_NAME, MODULE_NAME, name));

			bbart.addAttribute(new BlackboardAttribute(TSK_PHONE_NUMBER, MODULE_NAME, phoneNumber));
			bbart.addAttribute(new BlackboardAttribute(TSK_EMAIL, MODULE_NAME, emailAddr));

			// Create a phone number account for the phone number
			AccountFileInstance phoneNumAccount = commsMgr.createAccountFileInstance(PHONE, phoneNumber, MODULE_NAME, abstractFile);
			List<AccountFileInstance> accountInstanceList = new ArrayList<AccountFileInstance>();
			accountInstanceList.add(phoneNumAccount);

			//  Create a CONTACT relationship
			commsMgr.addRelationships(deviceAccount, accountInstanceList, bbart, CONTACT, 0);

		} catch (TskCoreException ex) {
			LOGGER.log(Level.SEVERE, "Unable to add Contact artifact ", ex); //NON-NLS
		} catch (TskDataException ex) {
			LOGGER.log(Level.SEVERE, "Unable to add Contact artifact ", ex); //NON-NLS
		}
	}
}
