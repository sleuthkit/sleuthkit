/*
 * Sleuth Kit Data Model
 *
 * Copyright 2017-2018 Basis Technology Corp.
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
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Defines an aggregate of filters to apply to a CommunicationsManager query.
 */
final public class CommunicationsFilter {

	/**
	 * For now all filters are anded together
	 */
	private final List<SubFilter> andFilters;

	/**
	 * Create a new empty CommunicationsFilter.
	 */
	public CommunicationsFilter() {
		this(Collections.<SubFilter>emptyList());
	}

	CommunicationsFilter(List<? extends SubFilter> andSubFilters) {
		this.andFilters = new ArrayList<SubFilter>(andSubFilters);
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
	public List<SubFilter> getAndFilters() {
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
	 * Filters relationships by relationship type.
	 *
	 */
	final public static class RelationshipTypeFilter extends SubFilter {

		private final Set<Relationship.Type> relationshipTypes;

		/**
		 * Constructs a RelationshipTypeFilter.
		 *
		 * @param relationshipTypes set of relationship types
		 */
		public RelationshipTypeFilter(Collection<Relationship.Type> relationshipTypes) {
			this.relationshipTypes = new HashSet<Relationship.Type>(relationshipTypes);
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

			List<Integer> relationShipTypeIds = new ArrayList<Integer>();
			for (Relationship.Type relType : relationshipTypes) {
				relationShipTypeIds.add(relType.getTypeID());
			}
			return " relationships.relationship_type IN ( "
					+ StringUtils.buildCSVString(relationShipTypeIds) + " )";
		}
	}

	/**
	 * Filters communications by date range
	 */
	final public static class DateRangeFilter extends SubFilter {

		private final long startDate;
		private final long endDate;
		private static final long SECS_PER_DAY = 86400;
		private final boolean startDateEnabled;
		private final boolean endDateEnabled;

		/**
		 * Constructs a DateRangeFilter.
		 *
		 * @param startDateEnabled boolean
		 * @param startDate start date in epoch
		 * @param endDateEnabled boolean
		 * @param endDate   end date in epoch
		 */
		public DateRangeFilter(boolean startDateEnabled, long startDate, boolean endDateEnabled, long endDate) {
			this.startDate = startDate;
			// Add a day to end date to make it inclusive in the range
			this.endDate = endDate + SECS_PER_DAY;
			
			this.startDateEnabled = startDateEnabled;
			this.endDateEnabled = endDateEnabled;
		}
		
		/**
		 * Get the start date.
		 * 
		 * @return Seconds from java epoch or zero if no value was set
		 */
		public long getStartDate() {
			return startDate;
		}
		
		/**
		 * Get the end date.
		 * 
		 * @return Seconds from java epoch or zero if no value was set
		 */
		public long getEndDate() {
			return endDate;
		}
		
		/**
		 * Returns whether or not the start date should be enabled.
		 * 
		 * @return boolean
		 */
		public boolean isStartDateEnabled(){
			return startDateEnabled;
		}
		
		/**
		 * Returns whether or not the end date should be enabled.
		 * 
		 * @return boolean
		 */
		public boolean isEndDateEnabled(){
			return endDateEnabled;
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
			if (!startDateEnabled && !endDateEnabled) {
				return "";
			}
			String sql = "";
			if (startDateEnabled) {
				sql = "(" + " relationships.date_time IS NULL OR relationships.date_time >= " + startDate + ")";
			}
			if (endDateEnabled) {
				if (!sql.isEmpty()) {
					sql += " AND ";
				}
				sql += "(" + " relationships.date_time IS NULL OR relationships.date_time < " + endDate + ")";
			}
			return sql;
		}
	}

	/**
	 * Filter accounts and relationships by account type.
	 *
	 */
	final public static class AccountTypeFilter extends SubFilter {

		private final Set<Account.Type> accountTypes;

		/**
		 * Constructs a AccountTypeFilter.
		 *
		 * @param accountTypes set of account types to filter on.
		 */
		public AccountTypeFilter(Collection<Account.Type> accountTypes) {
			super();
			this.accountTypes = new HashSet<Account.Type>(accountTypes);
		}
		
		/**
		 * Get the selected Account Types.
		 * 
		 * @return A Set of Type values
		 */
		public Set<Account.Type> getAccountTypes() {
			return accountTypes;
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

			List<Integer> type_ids = new ArrayList<Integer>();
			for (Account.Type accountType : accountTypes) {
				type_ids.add(commsManager.getAccountTypeId(accountType));
			}
			String account_type_ids_list = StringUtils.buildCSVString(type_ids);
			return " account_types.account_type_id IN ( " + account_type_ids_list + " )";
		}
	}

	/**
	 * Filter by device ids.
	 *
	 */
	final public static class DeviceFilter extends SubFilter {

		private final Set<String> deviceIds;

		/**
		 * Constructs a device filter.
		 *
		 * @param deviceIds set of device Ids to filter on.
		 */
		public DeviceFilter(Collection<String> deviceIds) {
			super();
			this.deviceIds = new HashSet<String>(deviceIds);
		}

		@Override
		public String getDescription() {
			return "Filters accounts and relationships by device id.";
		}
		
		/**
		 *  Gets a set of device ids
		 * 
		 * @return Collection of device ids
		 */
		public Collection<String> getDevices() {
			return deviceIds;
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
