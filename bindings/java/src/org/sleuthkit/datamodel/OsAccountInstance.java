/*
 * Sleuth Kit Data Model
 *
 * Copyright 2021 Basis Technology Corp.
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

import java.util.Objects;
import java.util.ResourceBundle;

/**
 *
 * 
 */
public class OsAccountInstance implements Comparable<OsAccountInstance>{
	private final Host host;
	private final Content dataSource;
	private final OsAccount account;
	private final OsAccountInstanceType instanceType;
	
	private static final ResourceBundle bundle = ResourceBundle.getBundle("org.sleuthkit.datamodel.Bundle");
	
	/**
	 * Construct a new OsAccount instance object.
	 * 
	 * @param account Account for which an instance needs to be added.
	 * @param host Host on which the instance is found.
	 * @param dataSource Data source where the instance is found.
	 * @param instanceType Instance type.
	 */
	OsAccountInstance(OsAccount account, Host host, Content dataSource, OsAccountInstanceType instanceType) {
		this.account = account;
		this.host = host;
		this.dataSource = dataSource;
		this.instanceType = instanceType;
	}
	
	public OsAccount getOsAccount() {
		return account;
	}
	
	public Content getDataSource() {
		return dataSource;
	}
	
	public Host getHost() {
		return host;
	}
	
	public OsAccountInstanceType getInstanceType() {
		return instanceType;
	}

	@Override
	public int compareTo(OsAccountInstance o) {
		throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
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
			final OsAccountInstance other = (OsAccountInstance) obj;
			if (this.account.getId() != other.getOsAccount().getId()) {
				return false;
			}
			if (this.host.getId() != other.getHost().getId()) {
				return false;
			}
			if (this.dataSource.getId() != other.getDataSource().getId()) {
				return false;
			}
			
			return this.instanceType.equals(other.getInstanceType());
	}

	@Override
	public int hashCode() {
		int hash = 7;
		hash = 67 * hash + Objects.hashCode(this.host.getId());
		hash = 67 * hash + Objects.hashCode(this.dataSource.getId());
		hash = 67 * hash + Objects.hashCode(this.account.getId());
		hash = 67 * hash + Objects.hashCode(this.instanceType);
		return hash;
	}
	
	/**
	 * Describes the relationship between an os account instance and the host
	 * where the instance was found.
	 *
	 * Whether an os account actually performed any action on the host or if
	 * just a reference to it was found on the host (such as in a log file)
	 */
	public enum OsAccountInstanceType {
		PERFORMED_ACTION_ON(0, bundle.getString("OsAccountInstanceType.PerformedActionOn.text")), // the user performed actions on a host
		REFERENCED_ON(1, bundle.getString("OsAccountInstanceType.ReferencedOn.text") );	// user was simply referenced on a host

		private final int id;
		private final String name;

		OsAccountInstanceType(int id, String name) {
			this.id = id;
			this.name = name;
		}

		/**
		 * Get account instance type id.
		 *
		 * @return Account instance type id.
		 */
		public int getId() {
			return id;
		}

		/**
		 * Get account instance type name.
		 *
		 * @return Account instance type name.
		 */
		public String getName() {
			return name;
		}

		/**
		 * Gets account instance type enum from id.
		 *
		 * @param typeId Id to look for.
		 *
		 * @return Account instance type enum.
		 */
		public static OsAccountInstanceType fromID(int typeId) {
			for (OsAccountInstanceType statusType : OsAccountInstanceType.values()) {
				if (statusType.ordinal() == typeId) {
					return statusType;
				}
			}
			return null;
		}
	}
}
