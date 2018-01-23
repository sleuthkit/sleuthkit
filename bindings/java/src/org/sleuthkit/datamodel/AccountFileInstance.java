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
 * An instance of an Account in a specific file. 
 * An Account may be found in multiple Content
 * objects (such as different databases) on a single device.
 * There is a 1:N relationship between Account objects and AccountFileInstance
 * objects. A TSK_ACCOUNT artifact is created for every account file instance.
 *
 * AccountFileInstances can optionally have BlackboardAttributes to store more details.
 */
public class AccountFileInstance {
	private final BlackboardArtifact artifact; 
	private final Account account;

	AccountFileInstance(BlackboardArtifact artifact, Account account) throws TskCoreException {
		this.artifact = artifact;
		this.account = account;
	}

	/**
	 * Gets the first occurrence of an attribute by type.
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
	 * Adds an attribute.  It is faster to add them as part of a list.
	 *
	 * @param bbatr The attribute to add.
	 * 
	 * @throws TskCoreException if an there is an error adding the attribute.
	 */
	public void addAttribute(BlackboardAttribute bbatr) throws TskCoreException {
		this.artifact.addAttribute(bbatr);
	}

	/**
	 * Adds a collection of attributes
	 *
	 * @param bbatrs The collection of attributes to add.
	 * 
	 * @throws TskCoreException if an there is an error adding the attributes.
	 */
	public void addAttributes(Collection<BlackboardAttribute> bbatrs) throws TskCoreException {
		this.artifact.addAttributes(bbatrs);
	}
	
	/**
	 * Gets the underlying Account for this instance.
	 *
	 * @return The account.
	 * 
	 * @throws TskCoreException if an there is an error getting the account.
	 */
	public Account getAccount() throws TskCoreException {
		return this.account;
	}
	
	long getDataSourceObjectID(){
		return artifact.getDataSourceObjectID();
	}
}
