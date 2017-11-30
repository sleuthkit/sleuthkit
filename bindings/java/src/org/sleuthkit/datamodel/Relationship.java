/*
 * SleuthKit Java Bindings
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

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * A relationship between Accounts, such as a communication ( email, sms, phone
 * call (log) ) or presence in a contact book.
 */
public class Relationship {

	public static final class Type {

		public static final Type MESSAGE = new Type("MESSAGE", "Message");
		public static final Type CALL_LOG = new Type("CALL_LOG", "Call Log");
		public static final Type CONTACT = new Type("CONTACT", "Contact");

		private static final Set<Type> PREDEFINED_RELATIONSHIP_TYPES
				= Collections.unmodifiableSet(new HashSet<Relationship.Type>(Arrays.asList(
						MESSAGE, CALL_LOG, CONTACT)));

		private static final Set<Type> PREDEFINED_COMMUNICATION_TYPES
				= Collections.unmodifiableSet(new HashSet<Relationship.Type>(Arrays.asList(
						MESSAGE, CALL_LOG)));

		static Set<Relationship.Type> getPredefinedRelationshipTypes() {
			return PREDEFINED_RELATIONSHIP_TYPES;
		}

		static Set<Relationship.Type> getPredefinedCommunicationTypes() {
			return PREDEFINED_COMMUNICATION_TYPES;
		}

		private final String displayName;
		private final String typeName;

		private Type(String name, String displayName) {
			this.typeName = name;
			this.displayName = displayName;
		}

		@Override
		public boolean equals(Object that) {
			if (this == that) {
				return true;
			} else if (!(that instanceof Type)) {
				return false;
			}
			Type thatType = (Type) that;
			return this.typeName.equals(thatType.getTypeName());
		}

		public String getDisplayName() {
			return displayName;
		}

		public String getTypeName() {
			return typeName;
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
			return "{" + this.getClass().getName() + ": displayName=" + this.displayName + ", typeName=" + this.typeName + "}";
		}
	}
}
