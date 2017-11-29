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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_CALLLOG;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_CONTACT;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_EMAIL_MSG;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_MESSAGE;
import static org.sleuthkit.datamodel.Relationship.Type.CALL_LOG;
import static org.sleuthkit.datamodel.Relationship.Type.CONTACT;

/**
 * Defines an aggregate of filters to apply to a CommunicationsManager query.
 *
 */
public class CommunicationsFilter {

	private final List<SubFilter> andFilters;
	// RAMAN TBD: figure out OR filters, I don't think we need any
	//private final List<SubFilter> orFilters;

	public CommunicationsFilter() {
		this.andFilters = new ArrayList<SubFilter>();
		//this.orFilters = new ArrayList<SubFilter>;
	}

	/**
	 * Returns the list of filters that will be ANDed together when applied to a
	 * query.
	 *
	 * NOTE: The returned list is unmodifiable, new filters should be added via
	 * addAndFilter.
	 *
	 * @return An unmodifiable list of the filter.
	 */
	List<SubFilter> getAndFilters() {
		return Collections.unmodifiableList(andFilters);
	}

	/**
	 * Adds a filter to list of filters that will be ANDed together when applied
	 * to a query.
	 *
	 * @param subFilter The SubFilter to add.
	 */
	public void addAndFilter(SubFilter subFilter) {
		andFilters.add(subFilter);
	}

	/**
	 * Unit level filter.
	 */
	public static abstract class SubFilter {

		/**
		 * Returns a string description of the filter.
		 *
		 * @return	A string description of the filter.
		 */
		public abstract String getDescription();

		/**
		 * Get the SQL string for the filter.
		 *
		 * @param commsManager Communications manager.
		 *
		 * @return SQL String for the filter.
		 */
		abstract String getSQL(CommunicationsManager commsManager);
	}

	/**
	 * Filters communications by relationship type.
	 *
	 */
	public static class RelationshipTypeFilter extends SubFilter {

		private final Set<Relationship.Type> relationshipTypes;

		/**
		 * Constructs a RelationshipTypeFilter.
		 *
		 * @param relationshipTypes set of relationship types
		 */
		public RelationshipTypeFilter(Set<Relationship.Type> relationshipTypes) {
			this.relationshipTypes = relationshipTypes;
		}

		@Override
		public String getDescription() {
			return "Filters relationships by relationship type.";
		}

		/**
		 * Get the SQL string for the filter.
		 *
		 * @param commsManager Communications manager.
		 *
		 * @return SQL String for the filter.
		 */
		@Override
		public String getSQL(CommunicationsManager commsManager) {
			if (relationshipTypes.isEmpty()) {
				return "";
			}
			String sql = "";
			List<Integer> artifactTypeIds = new ArrayList<Integer>();
			for (Relationship.Type relType : relationshipTypes) {
				if (relType.equals(CALL_LOG)) {
					artifactTypeIds.add(TSK_CALLLOG.getTypeID());
				} else if (relType.equals(CONTACT)) {
					artifactTypeIds.add(TSK_CONTACT.getTypeID());
				} else if (relType.equals(CALL_LOG)) {
					artifactTypeIds.add(TSK_EMAIL_MSG.getTypeID());
					artifactTypeIds.add(TSK_MESSAGE.getTypeID());
				}
			}
			String artifactTypeIdsCSV = StringUtils.buildCSVString(artifactTypeIds);
			if (!artifactTypeIdsCSV.isEmpty()) {
				sql = " relationships.relationship_type IN ( " + artifactTypeIdsCSV + " )";
			}
			return sql;
		}
	}

	public static class DateRangeFilter extends SubFilter {

		private final long startDate;
		private final long endDate;
		private static final long SECS_PER_DAY = 86400;

		/**
		 * Constructs a DateRangeFilter.
		 *
		 * @param startDate start date in epoch. Use 0 to not specify a date
		 * @param endDate   end date in epoch. Use 0 to not specify a date.
		 */
		public DateRangeFilter(long startDate, long endDate) {
			this.startDate = startDate;
			// Add a day to end date to make it inclusive in the range
			if (endDate > 0) {
				this.endDate = endDate + SECS_PER_DAY;
			} else {
				this.endDate = endDate;
			}
		}

		@Override
		public String getDescription() {
			return "Filters communications by date range.";
		}

		/**
		 * Get the SQL string for the filter.
		 *
		 * @param commsManager Communications manager.
		 *
		 * @return SQL String for the filter.
		 */
		@Override
		public String getSQL(CommunicationsManager commsManager) {
			if ((0 == startDate) && (0 == endDate)) {
				return "";
			}
			String sql = "";
			if (startDate > 0) {
				sql = " relationships.date_time >= " + startDate;
			}
			if (endDate > 0) {
				if (!sql.isEmpty()) {
					sql += " AND ";
				}
				sql += " relationships.date_time < " + endDate;
			}
			return sql;
		}
	}

	/**
	 * Filter communications by account type.
	 *
	 */
	public static class AccountTypeFilter extends SubFilter {

		private final Set<Account.Type> accountTypes;

		/**
		 * Constructs a AccountTypeFilter.
		 *
		 * @param accountTypes set of account types to filter on.
		 */
		public AccountTypeFilter(Set<Account.Type> accountTypes) {
			super();
			this.accountTypes = accountTypes;
		}

		@Override
		public String getDescription() {
			return "Filters accounts and relationships by account type.";
		}

		/**
		 * Get the SQL string for the filter.
		 *
		 * @param commsManager Communications manager.
		 *
		 * @return SQL String for the filter.
		 */
		@Override
		public String getSQL(CommunicationsManager commsManager) {
			if (accountTypes.isEmpty()) {
				return "";
			}
			String sql = "";
			List<Integer> type_ids = new ArrayList<Integer>();
			for (Account.Type accountType : accountTypes) {
				type_ids.add(commsManager.getAccountTypeId(accountType));
			}
			String account_type_ids_list = StringUtils.buildCSVString(type_ids);
			if (!account_type_ids_list.isEmpty()) {
				sql = " account_types.account_type_id IN ( " + account_type_ids_list + " )";
			}
			return sql;
		}
	}

	/**
	 * Filter by device ids.
	 *
	 */
	public static class DeviceFilter extends SubFilter {

		private final Set<String> deviceIds;

		/**
		 * Constructs a device filter.
		 *
		 * @param deviceIds set of device Ids to filter on.
		 */
		public DeviceFilter(Set<String> deviceIds) {
			super();
			this.deviceIds = deviceIds;
		}

		@Override
		public String getDescription() {
			return "Filters accounts and relationships by device id.";
		}

		/**
		 * Get the SQL string for the filter.
		 *
		 * @param commsManager Communications manager.
		 *
		 * @return SQL String for the filter.
		 */
		@Override
		public String getSQL(CommunicationsManager commsManager) {
			if (deviceIds.isEmpty()) {
				return "";
			}
			String sql = "";
			List<Long> ds_ids = new ArrayList<Long>();
			for (String deviceId : deviceIds) {
				try {
					ds_ids.addAll(commsManager.getSleuthkitCase().getDataSourceObjIds(deviceId));
				} catch (TskCoreException ex) {
					Logger.getLogger(DeviceFilter.class.getName()).log(Level.WARNING, "failed to get datasource object ids for deviceId", ex);
				}
			}
			String datasource_obj_ids_list = StringUtils.buildCSVString(ds_ids);
			if (!datasource_obj_ids_list.isEmpty()) {
				sql = " relationships.data_source_obj_id IN ( " + datasource_obj_ids_list + " )";
			}
			return sql;
		}
	}
}
