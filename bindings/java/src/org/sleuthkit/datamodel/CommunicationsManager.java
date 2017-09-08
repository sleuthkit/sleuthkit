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
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;


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
	 * @param displayName account type display name
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
	 * Get the Account with the given account type and account ID.
	 * Create one if it doesn't exist
	 *
	 * 
	 * @param type account type
	 * @param accountID accountID
	 * 
	 * @return Account, returns NULL is no matching account found
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	public Account getOrCreateAccount(Account.Type accountType, String accountID, String moduleName, Content sourceObj) throws TskCoreException {
		Account account = null;
		BlackboardArtifact accountArtifact = db.getOrCreateAccountArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_ACCOUNT, accountType, normalizeAccountID(accountType, accountID), moduleName, sourceObj);
		if (null != accountArtifact) {
			account = new Account(this.db, accountArtifact.getArtifactID() );
		}
		return account;
	}
	
	/**
	 * Get the Account with the given account type and account ID. 
	 *
	 * 
	 * @param type account type
	 * @param accountID accountID
	 * 
	 * @return Account, returns NULL is no matching account found
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	public Account getAccount(Account.Type accountType, String accountID) throws TskCoreException {
		
		Account account = null;
		
		BlackboardArtifact accountArtifact = db.getAccountArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_ACCOUNT, accountType, normalizeAccountID(accountType, accountID));
		if (null != accountArtifact) {
			account = new Account(this.db, accountArtifact.getArtifactID() );
		}
		
		return account;
	}

	/**
	 * Get all account types in use
	 * 
	 * @return List <Account.Type>, list of account types in use
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	public List <Account.Type> getAccountTypesInUse() throws TskCoreException {
		return db.getAccountTypesInUse();
	}

	/**
	 * Get all accounts of given type
	 * 
	 * @param type account type
	 * 
	 * @return List <Account.Type>, list of accounts
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	public List<Account> getAccounts(Account.Type accountType) throws TskCoreException {
		
		List<Account> accounts =  new ArrayList<Account>();
		
		List<BlackboardArtifact> artifacts = db.getAccountArtifacts(accountType);
		for (BlackboardArtifact accountArtifact: artifacts) {
			accounts.add(new Account(this.db, accountArtifact.getArtifactID() ));
		}
	
		return accounts;
	}

	
/**
 * Reject the given account
 * 
 * @param account account to reject
 * 
 * @throws TskCoreException exception thrown if a critical error occurs
 *                          within TSK core
 */
public void rejectAccount(Account account) throws TskCoreException {
	db.setReviewStatus(db.getBlackboardArtifact(account.getArtifactId()), BlackboardArtifact.ReviewStatus.REJECTED);
}

/**
 * Approve a given account
 * 
 * @param account account to approve
 * 
 * @throws TskCoreException exception thrown if a critical error occurs
 *                          within TSK core
 */
public void approveAccount(Account account) throws TskCoreException {
	db.setReviewStatus(db.getBlackboardArtifact(account.getArtifactId()), BlackboardArtifact.ReviewStatus.APPROVED);
}

/**
 * Set review status for a given account
 * 
 * @param account account to review
 * @param reviewStatus review status
 * @throws TskCoreException exception thrown if a critical error occurs
 *                          within TSK core
 */
public void setReviewStatus(Account account, BlackboardArtifact.ReviewStatus reviewStatus) throws TskCoreException {
	db.setReviewStatus(db.getBlackboardArtifact(account.getArtifactId()), reviewStatus);
}

/**
 * Get all accounts that have any kind of relationship with the given account
 * 
 * @param sender sender account
 * @paraman recipients list of recipients
 * @param communicationArtifact communication item
 * 
 * @throws TskCoreException exception thrown if a critical error occurs
 *                          within TSK core
 */
	public List<Account> getAccountsWithRelationship(Account account) throws TskCoreException {
		
		List<Account> accounts =  new ArrayList<Account>();
		
		List<BlackboardArtifact> artifacts = db.getAccountsWithRelationship(account.getArtifactId());
		for (BlackboardArtifact accountArtifact: artifacts) {
			accounts.add(new Account(this.db, accountArtifact.getArtifactID() ));
		}
	
		return accounts;
	}

/**
 * Add a relationship between the given sender and recipient accounts.
 * 
 * @param sender sender account
 * @paraman recipients list of recipients
 * @param communicationArtifact communication item
 * 
 * @throws TskCoreException exception thrown if a critical error occurs
 *                          within TSK core
 */
public void addRelationships(Account sender, List<Account> recipients, BlackboardArtifact communicationArtifact) {
	
	// Currently we do not save the direction of communication
	List<Long> accountIDs = new ArrayList<Long>();
	if (null != sender) {
		accountIDs.add(sender.getArtifactId());
	}
	
	for (Account recipient: recipients) {
		accountIDs.add(recipient.getArtifactId());
	}
	
	Set<UnorderedPair<Long>> relationships = listToUnorderedPairs(accountIDs);
	
	Iterator<UnorderedPair<Long>> iter = relationships.iterator();
	
	while (iter.hasNext()) {
		
		try {
			UnorderedPair<Long> accountPair = iter.next();
			db.addAccountsRelationship(accountPair.first, accountPair.second, communicationArtifact.getArtifactID());
		}
		catch (TskCoreException ex) {
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
 * @throws TskCoreException exception thrown if a critical error occurs
 *                          within TSK core
 */
public List <BlackboardArtifact.Type> getRelationshipTypes(Account account1, Account account2) throws TskCoreException {
	
	return db.getRelationshipTypes(account1.getArtifactId(), account2.getArtifactId());
}

/**
 * Returns unique relation types between two accounts
 * 
 * @param account1 account 
 * @param account2 account
 * 
 * @throws TskCoreException exception thrown if a critical error occurs
 *                          within TSK core
 */
public List <BlackboardArtifact> getRelationships(Account account1, Account account2) throws TskCoreException {
	
	return db.getRelationships(account1.getArtifactId(), account2.getArtifactId());
}

/**
 * Returns unique relation types between two accounts
 * 
 * @param account1 account 
 * @param account2 account
 * 
 * @throws TskCoreException exception thrown if a critical error occurs
 *                          within TSK core
 */
public List <BlackboardArtifact> getRelationshipsOfType(Account account1, Account account2, BlackboardArtifact.Type artifactType ) throws TskCoreException {
	
	return db.getRelationshipsOfType(account1.getArtifactId(), account2.getArtifactId(), artifactType);
}

/**
 * Return folders found in the email source file
 * 
 * @param srcObjID pbjectID of the email PST/Mbox source file  
 * 
 * @throws TskCoreException exception thrown if a critical error occurs
 *                          within TSK core
 */
public List <MessageFolder> getMessageFolders(long srcObjID ) throws TskCoreException {
	return db.getMessageFolders(srcObjID);
}

/**
 * Return subfolders found in the email source file under the specified folder
 * 
 * @param srcObjID objectID of the email PST/Mbox source file  
 * @param parentfolder parent folder  of messages to return
 * 
 * @throws TskCoreException exception thrown if a critical error occurs
 *                          within TSK core
 */
public List <MessageFolder> getMessageFolders(long srcObjID, MessageFolder  parentfolder ) throws TskCoreException {
	return db.getMessageFolders(srcObjID, parentfolder);
}

/**
 * Return email messages under given folder
 * 
 * @param parentfolder parent folder  of messages to return
 * 
 * @throws TskCoreException exception thrown if a critical error occurs
 *                          within TSK core
 */
public List <BlackboardArtifact> getMessages(MessageFolder  parentfolder ) throws TskCoreException {
	return db.getMessages(parentfolder);
}

/**
 * Converts a list of accountIDs into a set of possible unordered pairs
 * 
 * @param accountIDs - list of accountID
 * 
 * @return Set<UnorderedPair<Long>>
 */
private Set<UnorderedPair<Long>> listToUnorderedPairs(List<Long> accountIDs) {
	Set<UnorderedPair<Long>> relationships = new HashSet<UnorderedPair<Long>> ();
	
	for (int i = 0; i < accountIDs.size(); i++ ) {
		for (int j = i+1; j < accountIDs.size(); j++ ) {
			relationships.add(new UnorderedPair<Long> (accountIDs.get(i), accountIDs.get(j) ));
		}
	}
	
	return relationships;
}

private String normalizeAccountID(Account.Type accountType, String accountID) {
	String normailzeAccountID = accountID;
	
	if (accountType == Account.Type.PHONE) {
		normailzeAccountID = normalizePhoneNum(accountID);
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

public final class UnorderedPair<T> {
    private final T first;
    private final T second;

    public UnorderedPair(T first, T second) {
        this.first = first;
        this.second = second;
    }

    @Override public int hashCode() {
        return first.hashCode() + second.hashCode();
    }

    @Override public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if (!(other instanceof UnorderedPair)) {
            return false;
        }

        UnorderedPair<?> otherPair = (UnorderedPair<?>) other;
        return (first.equals(otherPair.first) && second.equals(otherPair.second))
            || (first.equals(otherPair.second) && second.equals(otherPair.first));
    }

    public T getFirst() {
        return first;
    }

    public T getSecond() {
        return second;
    }
}

}
