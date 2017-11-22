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

import java.io.Serializable;
import java.util.Arrays;
import java.util.List;

/**
 * An entity that has a type and a unique identifier. Example types include a
 * Bank Account, Credit Card, Email address, Phone number, phone, Application,
 * Web-site login, etc.  Accounts are unique to the case. 
 */
public class Account {

	private final long account_id;	// primary key in the Accounts table, unique at the case-level 

	private final Account.Type accountType;
	private final String accountUniqueID;

	//JIRA-901 Why does this implement Serializable?
	public static final class Type implements Serializable {

		private static final long serialVersionUID = 1L;
		//JIRA-900:Should the display names of predefined types be internationalized?
		public static final Account.Type CREDIT_CARD = new Type("CREDIT_CARD", "Credit Card");
		public static final Account.Type DEVICE = new Type("DEVICE", "Device");
		public static final Account.Type PHONE = new Type("PHONE", "Phone");
		public static final Account.Type EMAIL = new Type("EMAIL", "Email");
		public static final Account.Type FACEBOOK = new Type("FACEBOOK", "Facebook");
		public static final Account.Type TWITTER = new Type("TWITTER", "Twitter");
		public static final Account.Type INSTAGRAM = new Type("INSTAGRAM", "Instagram");
		public static final Account.Type WHATSAPP = new Type("WHATSAPP", "Facebook");
		public static final Account.Type MESSAGING_APP = new Type("MESSAGING_APP", "MessagingApp");
		public static final Account.Type WEBSITE = new Type("WEBSITE", "Website");

		public static final List<Account.Type> PREDEFINED_ACCOUNT_TYPES = Arrays.asList(
				CREDIT_CARD,
				DEVICE,
				PHONE,
				EMAIL,
				FACEBOOK,
				TWITTER,
				INSTAGRAM,
				WHATSAPP,
				MESSAGING_APP,
				WEBSITE
		);

		private final String typeName;
		private final String displayName;

		/**
		 * Constructs an Account type.
		 *
		 * @param typeName    The type name.
		 * @param displayName The display name for the type.
		 */
		Type(String typeName, String displayName) {
			this.typeName = typeName;
			this.displayName = displayName;
		}

		/**
		 * Gets the type name
		 *
		 * @return The type name.
		 */
		public String getTypeName() {
			return this.typeName;
		}

		public String getDisplayName() {
			return displayName;
		}

		@Override
		public boolean equals(Object that) {
			if (this == that) {
				return true;
			} else if (!(that instanceof Account.Type)) {
				return false;
			} 
			
			Account.Type thatType = (Account.Type) that;
			// DB table enforces uniqueness for type name
			return this.typeName.equals(thatType.getTypeName());
		}

		@Override
		public int hashCode() {
			int hash = 11;

			hash = 83 * hash + (this.typeName != null ? this.typeName.hashCode() : 0);
			hash = 83 * hash + (this.displayName != null ? this.displayName.hashCode() : 0);

			return hash;
		}

		@Override
		public String toString() {
			return " displayName=" + this.displayName
					+ ", typeName=" + this.typeName + ")";
		}
	}

	Account(long account_id, Account.Type accountType, String accountUniqueID) throws TskCoreException {
		this.account_id = account_id;
		this.accountType = accountType;
		this.accountUniqueID = accountUniqueID;
	}

	/**
	 * Gets unique identifier (assigned by a provider) for the account.
	 * Example includes an email address.
	 *
	 * @return unique account id.
	 */
	public String getAccountUniqueID() {
		return this.accountUniqueID;
	}

	/**
	 * Gets the account type
	 *
	 * @return account type
	 */
	public Account.Type getAccountType() {
		return this.accountType;
	}

	/**
	 * Gets a case-specific unique identifier for this account (from the database)
	 *
	 * @return unique row id.
	 */
	public long getAccountId() {
		return this.account_id;
	}
}
