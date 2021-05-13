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
 * An OsAccountInstance represents the appearance of a particular OsAccount on a
 * particular data source.
 */
public class OsAccountInstance implements Comparable<OsAccountInstance> {

	private static final ResourceBundle bundle = ResourceBundle.getBundle("org.sleuthkit.datamodel.Bundle");

	private final SleuthkitCase skCase;
	private final long accountId;
	private final long dataSourceId;
	private final OsAccountInstanceType instanceType;

	private OsAccount account;
	private DataSource dataSource = null;

	/**
	 * Construct with OsAccount and DataSource instances.
	 *
	 * @param skCase       The case instance.
	 * @param account      The instance account.
	 * @param dataSource   The instance data source
	 * @param instanceType The instance type.
	 */
	OsAccountInstance(SleuthkitCase skCase, OsAccount account, DataSource dataSource, OsAccountInstanceType instanceType) {
		this(skCase, account.getId(), dataSource.getId(), instanceType);
		this.dataSource = dataSource;
		this.account = account;
	}

	/**
	 * Construct the OsAccountInstance doing a lazy construction on the data
	 * source object.
	 *
	 * @param skCase       The case instance
	 * @param account      The OsAccount for this instance
	 * @param dataSourceId The id of the data source
	 * @param instanceType The instance type.
	 */
	OsAccountInstance(SleuthkitCase skCase, OsAccount account, long dataSourceId, OsAccountInstanceType instanceType) {
		this(skCase, account.getId(), dataSourceId, instanceType);
		this.account = account;
	}

	/**
	 * Construct with OsAccount and DataSource instances.
	 *
	 * @param skCase          The case instance
	 * @param accountId       The id of the instance account.
	 * @param dataSourceObjId The instance data source object id.
	 * @param instanceType    The instance type.
	 */
	OsAccountInstance(SleuthkitCase skCase, long accountId, long dataSourceObjId, OsAccountInstanceType instanceType) {
		this.skCase = skCase;
		this.accountId = accountId;
		this.dataSourceId = dataSourceObjId;
		this.instanceType = instanceType;
	}

	/**
	 * Returns the OsAccount object for this instance.
	 *
	 * @return The OsAccount object.
	 */
	public OsAccount getOsAccount() throws TskCoreException {
		if (account == null) {
			try {
				account = skCase.getOsAccountManager().getOsAccountByObjectId(accountId);
			} catch (TskCoreException ex) {
				throw new TskCoreException(String.format("Failed to get OsAccount for id %d", accountId), ex);
			}
		}

		return account;
	}

	/**
	 * Returns the data source for this account instance.
	 *
	 * @return Return the data source instance.
	 *
	 * @throws TskCoreException
	 */
	public DataSource getDataSource() throws TskCoreException {
		if (dataSource == null) {
			try {
				dataSource = skCase.getDataSource(dataSourceId);
			} catch (TskDataException ex) {
				throw new TskCoreException(String.format("Failed to get DataSource for id %d", dataSourceId), ex);
			}
		}

		return dataSource;
	}

	/**
	 * Returns the type for this OsAccount instance.
	 *
	 * @return
	 */
	public OsAccountInstanceType getInstanceType() {
		return instanceType;
	}

	/**
	 * Return the dataSourceId value.
	 *
	 * @return Id of the instance data source.
	 */
	private long getDataSourceId() {
		return dataSourceId;
	}

	@Override
	public int compareTo(OsAccountInstance other) {
		if (equals(other)) {
			return 0;
		}

		if (dataSourceId != other.getDataSourceId()) {
			return Long.compare(dataSourceId, other.getDataSourceId());
		}

		return Long.compare(accountId, other.accountId);
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
		if (this.accountId != other.accountId) {
			return false;
		}

		return this.dataSourceId != other.dataSourceId;
	}

	@Override
	public int hashCode() {
		int hash = 7;
		hash = 67 * hash + Objects.hashCode(this.dataSourceId);
		hash = 67 * hash + Objects.hashCode(this.accountId);
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
		LAUNCHED(0, bundle.getString("OsAccountInstanceType.Launched.text"), bundle.getString("OsAccountInstanceType.Launched.descr.text")), // the user launched a program on the host
		ACCESSED(1, bundle.getString("OsAccountInstanceType.Accessed.text"), bundle.getString("OsAccountInstanceType.Accessed.descr.text")), // user accesed a resource for read/write
		REFERENCED(2, bundle.getString("OsAccountInstanceType.Referenced.text"), bundle.getString("OsAccountInstanceType.Referenced.descr.text"));	// user was referenced, e.g. in a event log.

		private final int id;
		private final String name;
		private final String description;

		OsAccountInstanceType(int id, String name, String description) {
			this.id = id;
			this.name = name;
			this.description = description;
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
		 * Get account instance type description.
		 *
		 * @return Account instance type description.
		 */
		public String getDescription() {
			return description;
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
