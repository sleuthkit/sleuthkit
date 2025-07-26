/*
 * SleuthKit Java Bindings
 *
 * Copyright 2017-18 Basis Technology Corp.
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

import java.util.Arrays;
import java.util.Collections;
import static java.util.Collections.singleton;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_CALLLOG;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_CONTACT;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_EMAIL_MSG;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_MESSAGE;
import static org.sleuthkit.datamodel.CollectionUtils.hashSetOf;

/**
 * A relationship between Accounts, such as a communication ( email, sms, phone
 * call (call log) ) or presence in a contact book.
 */
public final class Relationship {

	public static final class Type {

		private final String displayName;
		private final String typeName;
		private final int typeID;

		public static final Relationship.Type MESSAGE = new Type("MESSAGE", "Message", 1);
		public static final Relationship.Type CALL_LOG = new Type("CALL_LOG", "Call Log", 2);
		public static final Relationship.Type CONTACT = new Type("CONTACT", "Contact", 3);

		private final static HashMap<Type, Set<Integer>> typesToArtifactTypeIDs = new HashMap<Type, Set<Integer>>();

		static {
			typesToArtifactTypeIDs.put(MESSAGE, hashSetOf(
					TSK_EMAIL_MSG.getTypeID(),
					TSK_MESSAGE.getTypeID()));
			typesToArtifactTypeIDs.put(CALL_LOG, singleton(
					TSK_CALLLOG.getTypeID()));
			typesToArtifactTypeIDs.put(CONTACT, singleton(
					TSK_CONTACT.getTypeID()));
		}

		private static final Set<Type> PREDEFINED_COMMUNICATION_TYPES
				= Collections.unmodifiableSet(new HashSet<Relationship.Type>(Arrays.asList(
						MESSAGE, CALL_LOG)));

		/**
		 * Subset of predefined types that represent communications.
		 *
		 * @return A subset of predefined types that represent communications.
		 *
		 */
		static Set<Relationship.Type> getPredefinedCommunicationTypes() {
			return PREDEFINED_COMMUNICATION_TYPES;
		}

		private Type(String name, String displayName, int id) {
			this.typeName = name;
			this.displayName = displayName;
			this.typeID = id;
		}

		/**
		 * Get the display name.
		 *
		 * @return The display name.
		 */
		public String getDisplayName() {
			return displayName;
		}

		/**
		 * Get the unique type name
		 *
		 * @return The unique type name.
		 */
		public String getTypeName() {
			return typeName;
		}

		/**
		 * Get the id of this type.
		 *
		 * @return The type ID.
		 */
		public int getTypeID() {
			return typeID;
		}

		@Override
		public int hashCode() {
			int hash = 7;
			hash = 37 * hash + (this.typeName != null ? this.typeName.hashCode() : 0);
			hash = 37 * hash + this.typeID;
			return hash;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			final Type other = (Type) obj;
			if (this.typeID != other.typeID) {
				return false;
			}
			if ((this.typeName == null) ? (other.typeName != null) : !this.typeName.equals(other.typeName)) {
				return false;
			}
			return true;
		}

		@Override
		public String toString() {
			return "{" + this.getClass().getName() + ": typeID=" + typeName + ", displayName=" + this.displayName + ", typeName=" + this.typeName + "}";
		}

		/**
		 * Is this type creatable from the given artifact. Specifically do they
		 * have compatible types.
		 *
		 * @param relationshipArtifact the relationshipArtifact to test
		 *                             creatability from
		 *
		 * @return if a relationship of this type can be created from the given
		 *         artifact.
		 */
		boolean isCreatableFrom(BlackboardArtifact relationshipArtifact) {
			Set<Integer> get = typesToArtifactTypeIDs.get(this);
			return get != null && get.contains(relationshipArtifact.getArtifactTypeID());
		}
	}
}
