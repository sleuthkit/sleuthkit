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

public class DateRangeFilter implements SubFilter {

	private final long startDate;
	private final long endDate;

	private final static long SECS_PER_DAY = 86400;

	/**
	 * Constructs a DateRangeFilter.
	 *
	 * @param startDate start date
	 * @param endDate   end date
	 */
	public DateRangeFilter(long startDate, long endDate) {
		this.startDate = startDate;
		
		// Add a day to end date to make it inclusive in the range
		if (endDate > 0) {
			this.endDate = endDate + SECS_PER_DAY;
		}
		else {
			this.endDate = endDate;
		}	
	}

	/**
	 * Returns a string description of the filter.
	 *
	 * @return	A string description of the filter.
	 */
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
		if ((startDate > 0)) {
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
