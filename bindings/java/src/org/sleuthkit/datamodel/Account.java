/*
 * Sleuth Kit Data Model
 *
 * Copyright 2011-2016 Basis Technology Corp.
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
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE;

public class Account {

	private long artifactId;	// ArtifactID of the underlying TSK_ACCOUNT artifact
	
	private final Account.Type accountType;
	private final String accountID;
	private final BlackboardArtifact artifact;
	
	public static final class Type implements Serializable {
		
		private static final long serialVersionUID = 1L;
		 
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
		
		public static final List<Account.Type> PREDEFINED_ACCOUNT_TYPES = new ArrayList<Account.Type>();
		
		static {
			PREDEFINED_ACCOUNT_TYPES.add(CREDIT_CARD);
			PREDEFINED_ACCOUNT_TYPES.add(DEVICE);
			PREDEFINED_ACCOUNT_TYPES.add(PHONE);
			PREDEFINED_ACCOUNT_TYPES.add(EMAIL);
			PREDEFINED_ACCOUNT_TYPES.add(FACEBOOK);
			PREDEFINED_ACCOUNT_TYPES.add(TWITTER);
			PREDEFINED_ACCOUNT_TYPES.add(INSTAGRAM);
			PREDEFINED_ACCOUNT_TYPES.add(WHATSAPP);
			PREDEFINED_ACCOUNT_TYPES.add(MESSAGING_APP);
			PREDEFINED_ACCOUNT_TYPES.add(WEBSITE);
		}

		private final int typeID;
		private final String typeName;
		private final String displayName;
		
		
		/**
		 * Constructs an Account type.
		 *
		 * @param typeID      The type id.
		 * @param typeName    The type name.
		 * @param displayName The display name for the type.
		 */
		public Type(int typeID, String typeName, String displayName) {
			this.typeID = typeID;
			this.typeName = typeName;
			this.displayName = displayName;
		}
		
		/**
		 * Constructs an Account type.
		 * @param typeName    The type name.
		 * @param displayName The display name for the type.
		 */
		public Type(String typeName, String displayName) {
			this(0, typeName, displayName );
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
		
		/**
		 * Gets the type id of this account type.
		 *
		 * @return The type id.
		 */
		public int getTypeID() {
			return this.typeID;
		}

		

		@Override
		public boolean equals(Object that) {
			if (this == that) {
				return true;
			} else if (!(that instanceof Account.Type)) {
				return false;
			} else {
				return ((Account.Type) that).sameType(this);
			}
		}
		
		@Override
		public int hashCode() {
        int hash = 11;
		
        hash = 83 * hash + (this.typeName != null ? this.typeName.hashCode() : 0);
		hash = 83 * hash + (this.displayName != null ? this.displayName.hashCode() : 0);
        hash = 83 * hash + Objects.hashCode(this.typeID);
        
        return hash;
    }
	
		@Override
		public String toString() {
			return "(typeID= " + this.typeID
					+ ", displayName=" + this.displayName
					+ ", typeName=" + this.typeName + ")";
					
		}
		
		/**
		 * Determines if this account type object is equivalent to another
		 * account type object.
		 *
		 * @param that the other type
		 *
		 * @return true if it is the same type
		 */
		private boolean sameType(Account.Type that) {
			return this.typeName.equals(that.getTypeName())
					&& this.displayName.equals(that.getDisplayName())
					&& this.typeID == that.getTypeID();
		}
	}

	public Account(SleuthkitCase sleuthkitCase, long artifactId) throws TskCoreException {
	
		this.artifactId = artifactId;
		
		this.artifact = sleuthkitCase.getBlackboardArtifact(artifactId);
		this.accountType =  sleuthkitCase.getAccountType(artifact.getAttribute(new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_ACCOUNT_TYPE)).getValueString());
		this.accountID = artifact.getAttribute(new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_ID)).getValueString();
	
	}
	
	public Account(SleuthkitCase sleuthkitCase, BlackboardArtifact artifact) throws TskCoreException {
		
		this.sleuthkitCase = sleuthkitCase;
		this.artifactId = artifact.getArtifactID();
		
		this.artifact = artifact;
		
		this.accountType =  sleuthkitCase.getAccountType(artifact.getAttribute(new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_ACCOUNT_TYPE)).getValueString());
		this.accountID = artifact.getAttribute(new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_ID)).getValueString();
	
	}
	
	public String getAccountID() {
		return this.accountID;
	}
	
	public Account.Type getAccountType() {
		return this.accountType;
	}
	
	public BlackboardAttribute  getAttribute(BlackboardAttribute.ATTRIBUTE_TYPE attrType) throws TskCoreException {
		return this.artifact.getAttribute(new BlackboardAttribute.Type(attrType));
	}
	
	public void addAttribute(BlackboardAttribute bbatr) throws TskCoreException {
		this.artifact.addAttribute(bbatr);
	}
	
	public long getArtifactId() {
		return this.artifactId;
	}
		
}
