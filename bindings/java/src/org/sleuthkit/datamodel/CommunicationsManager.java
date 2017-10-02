/*
 * Sleuth Kit Data Model
 *
 * Copyright 2011-2017 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.datamodel;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Provides an API to create Accounts and communications/relationships between
 * accounts
 */
public class CommunicationsManager {

	private static final Logger LOGGER = Logger.getLogger(CommunicationsManager.class.getName());

	private final SleuthkitCase db;
	
	CommunicationsManager(SleuthkitCase db) {
		this.db = db;
	}
	
	
	/**
	 * Add an account type
	 *
	 * @param accountTypeName account type name
	 * @param displayName     account type display name
	 *
	 * @return Account.Type
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	public Account.Type addAccountType(String accountTypeName, String displayName) throws TskCoreException {
		return db.addAccountType(accountTypeName, displayName);
	}

	/**
	 * Create an AccountInstance with the given account type and account ID, and
	 * sourceObj. if it doesn't exist already
	 *
	 *
	 * @param accountType     account type
	 * @param accountUniqueID unique account identifier
	 * @param moduleName      module creating the account
	 * @param sourceObj       source content
	 *
	 * @return AccountInstance
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	public AccountInstance createAccountInstance(Account.Type accountType, String accountUniqueID, String moduleName, Content sourceObj) throws TskCoreException {
		AccountInstance accountInstance = null;
		long accountId = db.getOrCreateAccount(accountType, normalizeAccountID(accountType, accountUniqueID)).getAccountId();

		BlackboardArtifact accountArtifact = db.getOrCreateAccountInstanceArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_ACCOUNT, accountType, normalizeAccountID(accountType, accountUniqueID), moduleName, sourceObj);
		accountInstance = new AccountInstance(this.db, accountArtifact.getArtifactID(), accountId);

		// add a row to Accounts to Instances mapping table
		db.addAccountInstanceMapping(accountId, accountArtifact.getArtifactID());

		return accountInstance;
	}

	/**
	 * Get the Account with the given account type and account ID.
	 *
	 * @param accountType     account type
	 * @param accountUniqueID unique account identifier
	 *
	 * @return Account, returns NULL is no matching account found
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	public Account getAccount(Account.Type accountType, String accountUniqueID) throws TskCoreException {

		return db.getAccount(accountType, normalizeAccountID(accountType, accountUniqueID));
	}

	/**
	 * Returns an account instance for the given account instance artifact
	 *
	 * @param artifact
	 *
	 * @return Account, returns NULL is no matching account found
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 *
	 */
	public AccountInstance getAccountInstance(BlackboardArtifact artifact) throws TskCoreException {
		AccountInstance accountInstance = null;
		if (artifact.getArtifactTypeID() == BlackboardArtifact.ARTIFACT_TYPE.TSK_ACCOUNT.getTypeID()) {
			String accountTypeStr = artifact.getAttribute(new BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_ACCOUNT_TYPE)).getValueString();
			String accountID = artifact.getAttribute(new BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_ID)).getValueString();
			Account.Type accountType = db.getAccountType(accountTypeStr);

			Account account = db.getAccount(accountType, accountID);
			accountInstance = new AccountInstance(this.db, artifact, account);
		}

		return accountInstance;
	}

	/**
	 * Get all account types in use
	 *
	 * @return List <Account.Type>, list of account types in use
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	public List<Account.Type> getAccountTypesInUse() throws TskCoreException {
		return db.getAccountTypesInUse();
	}

	/**
	 * Get all accounts of given type
	 *
	 * @param accountType account type
	 *
	 * @return List <Account.Type>, list of accounts
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	public List<Account> getAccounts(Account.Type accountType) throws TskCoreException {
		List<Account> accounts = db.getAccounts(accountType);
		return accounts;
	}

	/**
	 * Get all account instances of a given type
	 *
	 * @param accountType account type
	 *
	 * @return List <Account.Type>, list of accounts
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	public List<AccountInstance> getAccountInstances(Account.Type accountType) throws TskCoreException {

		List<AccountInstance> accountInstances = new ArrayList<AccountInstance>();

		// First get all account of the type
		List<Account> accounts = db.getAccounts(accountType);

		// get all instances for each account
		for (Account account : accounts) {
			List<Long> accountInstanceIds = db.getAccountInstanceIds(account.getAccountId());

			for (long artifact_id : accountInstanceIds) {
				accountInstances.add(new AccountInstance(db, artifact_id, account.getAccountId()));
			}
		}
		return accountInstances;
	}

	/**
	 * Reject the given account instance
	 *
	 * @param accountInstance account instance to reject
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	/**
	 * Get all accounts that have a relationship with the given account
	 *
	 * @param account account for which to search relationships
	 *
	 * @return list of accounts with relationships to the given account
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	public List<Account> getAccountsWithRelationship(Account account) throws TskCoreException {
		return db.getAccountsWithRelationship(account.getAccountId());
	}

	/**
	 * Add a relationship between the given sender and recipient account
	 * instances.
	 *
	 * @param sender                sender account
	 * @param recipients            list of recipients
	 * @param communicationArtifact communication item
	 */
	public void addRelationships(AccountInstance sender, List<AccountInstance> recipients, BlackboardArtifact communicationArtifact) {

		// Currently we do not save the direction of communication
		List<Long> accountIDs = new ArrayList<Long>();
		if (null != sender) {
			accountIDs.add(sender.getAccountId());
		}

		for (AccountInstance recipient : recipients) {
			accountIDs.add(recipient.getAccountId());
		}

		Set<UnorderedAccountPair> relationships = listToUnorderedPairs(accountIDs);
		Iterator<UnorderedAccountPair> iter = relationships.iterator();

		while (iter.hasNext()) {
			try {
				UnorderedAccountPair accountPair = iter.next();
				db.addAccountsRelationship(accountPair.getFirst(), accountPair.getSecond(), communicationArtifact.getArtifactID());
			} catch (TskCoreException ex) {
				LOGGER.log(Level.WARNING, "Could not get timezone for image", ex); //NON-NLS
			}
		}

	}

	/**
	 * Returns unique relation types between two accounts
	 *
	 * @param account1 account
	 * @param account2 account
	 *
	 * @return list of unique relationship types between two accounts
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	public List<BlackboardArtifact.Type> getRelationshipTypes(Account account1, Account account2) throws TskCoreException {
		return db.getRelationshipTypes(account1.getAccountId(), account2.getAccountId());
	}

	/**
	 * Returns relationships between two accounts
	 *
	 * @param account1 account
	 * @param account2 account
	 *
	 * @return relationships between two accounts
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	public List<BlackboardArtifact> getRelationships(Account account1, Account account2) throws TskCoreException {

		return db.getRelationships(account1.getAccountId(), account2.getAccountId());
	}

	/**
	 * Returns relationships of specified type between two accounts
	 *
	 * @param account1     one account in relationship
	 * @param account2     other account in relationship
	 * @param artifactType relationship type
	 *
	 * @return list of relationships
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	public List<BlackboardArtifact> getRelationshipsOfType(Account account1, Account account2, BlackboardArtifact.Type artifactType) throws TskCoreException {

		return db.getRelationshipsOfType(account1.getAccountId(), account2.getAccountId(), artifactType);
	}

	/**
	 * Return folders found in the email source file
	 *
	 * @param srcObjID pbjectID of the email PST/Mbox source file
	 *
	 * @return list of message folders
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	public List<MessageFolder> getMessageFolders(long srcObjID) throws TskCoreException {
		return db.getMessageFolders(srcObjID);
	}

	/**
	 * Return subfolders found in the email source file under the specified
	 * folder
	 *
	 * @param srcObjID     objectID of the email PST/Mbox source file
	 * @param parentfolder parent folder of messages to return
	 *
	 * @return list of message sub-folders
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	public List<MessageFolder> getMessageFolders(long srcObjID, MessageFolder parentfolder) throws TskCoreException {
		return db.getMessageFolders(srcObjID, parentfolder);
	}

	/**
	 * Return email messages under given folder
	 *
	 * @param parentfolder parent folder of messages to return
	 *
	 * @return list of messages
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	public List<BlackboardArtifact> getMessages(MessageFolder parentfolder) throws TskCoreException {
		return db.getMessages(parentfolder);
	}

	/**
	 * Converts a list of accountIDs into a set of possible unordered pairs
	 *
	 * @param accountIDs - list of accountID
	 *
	 * @return Set<UnorderedPair<Long>>
	 */
	private Set<UnorderedAccountPair> listToUnorderedPairs(List<Long> account_ids) {
		Set<UnorderedAccountPair> relationships = new HashSet<UnorderedAccountPair>();

		for (int i = 0; i < account_ids.size(); i++) {
			for (int j = i + 1; j < account_ids.size(); j++) {
				relationships.add(new UnorderedAccountPair(account_ids.get(i), account_ids.get(j)));
			}
		}

		return relationships;
	}

	private String normalizeAccountID(Account.Type accountType, String accountUniqueID) {
		String normailzeAccountID = accountUniqueID;

		if (accountType == Account.Type.PHONE) {
			normailzeAccountID = normalizePhoneNum(accountUniqueID);
		}

		return normailzeAccountID;
	}

	private String normalizePhoneNum(String phoneNum) {

		String normailzedPhoneNum = phoneNum.replaceAll("\\D", "");
		if (phoneNum.startsWith("+")) {
			normailzedPhoneNum = "+" + normailzedPhoneNum;
		}

		return normailzedPhoneNum;
	}

	/*
	 * Class representing an unordered pair of account ids. <a,b> is same as
	 * <b,a>
	 */
	public final class UnorderedAccountPair {

		private final long account1_id;
		private final long account2_id;

		public UnorderedAccountPair(long account1_id, long account2_id) {
			this.account1_id = account1_id;
			this.account2_id = account2_id;
		}

		@Override
		public int hashCode() {
			return new Long(account1_id).hashCode() + new Long(account2_id).hashCode();
		}

		@Override
		public boolean equals(Object other) {
			if (other == this) {
				return true;
			}
			if (!(other instanceof UnorderedAccountPair)) {
				return false;
			}

			UnorderedAccountPair otherPair = (UnorderedAccountPair) other;
			return ((account1_id == otherPair.account1_id && account2_id == otherPair.account2_id)
					|| (account1_id == otherPair.account2_id && account2_id == otherPair.account1_id));
		}

		public long getFirst() {
			return account1_id;
		}

		public long getSecond() {
			return account2_id;
		}
	}

}
