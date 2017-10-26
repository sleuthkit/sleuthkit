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

import java.util.Set;

/**
 * Filter communications by account type.
 * 
 */
public class AccountTypeFilter implements SubFilter {
	private final Set<Account.Type> accountTypes;
	
	public AccountTypeFilter(Set<Account.Type> accountTypes) {
		this.accountTypes = accountTypes;
	}

	/**
	 * Get the list of account types.
	 * 
	 * @return list of account types
	 */
	public Set<Account.Type> getAccountTypes() {
		return accountTypes;
	}
	
	@Override
	public String getDescription() {
		return "Filters accounts and relationships by account type.";
	}
}
