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

import java.util.Collection;

/**
 * Instance of an account. A account may be extracted from multiple sources, one
 * per Content, each represents an instance of the account. There is a 1:N
 * relationship between Account & AccountInstance
 *
 * Account instances are stored as Artifacts for type TSK_ACCOUNT
 */
public class AccountInstance {

	private final SleuthkitCase sleuthkitCase;
	private final BlackboardArtifact artifact;  // Underlying TSK_ACCOUNT artifact - that represents an instance 
	private final Account account;				// id of corresponding account.


	AccountInstance(SleuthkitCase sleuthkitCase, BlackboardArtifact artifact, Account account) throws TskCoreException {
		this.sleuthkitCase = sleuthkitCase;
		this.artifact = artifact;
		this.account = account;
	}

	/**
	 * Get an attribute of the account
	 *
	 * @param attrType attribute to get
	 * 
	 * @return BlackboardAttribute 
	 * 
	 * @throws TskCoreException exception thrown if a critical error occurs
	 */
	public BlackboardAttribute getAttribute(BlackboardAttribute.ATTRIBUTE_TYPE attrType) throws TskCoreException {
		return this.artifact.getAttribute(new BlackboardAttribute.Type(attrType));
	}

	/**
	 * An add attribute to the account
	 *
	 * @param bbatr attribute to add
	 * 
	 * @throws TskCoreException exception thrown if a critical error occurs
	 */
	public void addAttribute(BlackboardAttribute bbatr) throws TskCoreException {
		this.artifact.addAttribute(bbatr);
	}

	/**
	 * Adds a collection of attributes to the account
	 *
	 * @param bbatrs collection of attributes to add
	 * 
	 * @throws TskCoreException exception thrown if a critical error occurs
	 */
	public void addAttributes(Collection<BlackboardAttribute> bbatrs) throws TskCoreException {
		this.artifact.addAttributes(bbatrs);
	}
	
	/**
	 * Returns the underlying Account object
	 *
	 * @return account object
	 * 
	 * @throws TskCoreException exception thrown if a critical error occurs
	 */
	public Account getAccount() throws TskCoreException {
		return this.account;
	}


	/**
	 * Reject the account instance
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 */
	public void rejectAccount() throws TskCoreException {
		this.sleuthkitCase.setReviewStatus(this.artifact, BlackboardArtifact.ReviewStatus.REJECTED);
	}

	/**
	 * Reject the account instance
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 */
	public void approveAccount() throws TskCoreException {
		this.sleuthkitCase.setReviewStatus(this.artifact, BlackboardArtifact.ReviewStatus.APPROVED);
	}


}
