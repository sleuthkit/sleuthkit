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
 * An instance of an account. An account may be found in multiple content
 * objects, so there can be up to one account instance per content object, 
 * and there is a 1:N relationship between Account objects and AccountInstance
 * objects. Currently, there is an underlying TSK_ACCOUNT artifact for every 
 * account instance. This may change in the future.
 */
public class AccountInstance {

	private final SleuthkitCase sleuthkitCase;
	private final BlackboardArtifact artifact; 
	private final Account account;

	AccountInstance(SleuthkitCase sleuthkitCase, BlackboardArtifact artifact, Account account) throws TskCoreException {
		this.sleuthkitCase = sleuthkitCase;
		this.artifact = artifact;
		this.account = account;
	}

	/**
	 * Gets the first occurrence of an attribute of the account instance
	 * of a given type. 
	 *
	 * @param attrType The attribute type. 
	 * 
	 * @return The attribute, or null if no attribute of the given type exists.
	 * 
	 * @throws TskCoreException if an there is an error getting the attribute.
	 */
	public BlackboardAttribute getAttribute(BlackboardAttribute.ATTRIBUTE_TYPE attrType) throws TskCoreException {
		return this.artifact.getAttribute(new BlackboardAttribute.Type(attrType));
	}

	/**
	 * Adds an attribute to the account instance.
	 *
	 * @param bbatr The attribute to add.
	 * 
	 * @throws TskCoreException if an there is an error adding the attribute.
	 */
	public void addAttribute(BlackboardAttribute bbatr) throws TskCoreException {
		this.artifact.addAttribute(bbatr);
	}

	/**
	 * Adds a collection of attributes to the account instance
	 *
	 * @param bbatrs The collection of attributes to add.
	 * 
	 * @throws TskCoreException if an there is an error adding the attributes.
	 */
	public void addAttributes(Collection<BlackboardAttribute> bbatrs) throws TskCoreException {
		this.artifact.addAttributes(bbatrs);
	}
	
	/**
	 * Gets the account of which this object is an instance.
	 *
	 * @return The account.
	 * 
	 * @throws TskCoreException if an there is an error getting the account.
	 */
	public Account getAccount() throws TskCoreException {
		return this.account;
	}


	/**
	 * Marks this account instance as invalid.
	 *
	 * @throws TskCoreException if an there is an error marking the account instance.
	 */
	public void rejectAccount() throws TskCoreException {
		this.sleuthkitCase.setReviewStatus(this.artifact, BlackboardArtifact.ReviewStatus.REJECTED);
	}

	/**
	 * Marks this account instance as valid.
	 *
	 * @throws TskCoreException if an there is an error marking the account instance.
	 */
	public void approveAccount() throws TskCoreException {
		this.sleuthkitCase.setReviewStatus(this.artifact, BlackboardArtifact.ReviewStatus.APPROVED);
	}


}
