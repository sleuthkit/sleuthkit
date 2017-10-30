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
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Filter by device ids.
 *
 */
public class DeviceFilter implements SubFilter {

	private final Set<String> deviceIds;

	public DeviceFilter(Set<String> deviceIds) {
		this.deviceIds = deviceIds;
	}

	/**
	 * Get the list of device id.
	 *
	 * @return list of device Ids.
	 */
	Set<String> getdeviceIds() {
		return new HashSet<String>(deviceIds);
	}

	/**
	 * Returns a string description of the filter.
	 *
	 * @return	A string description of the filter.
	 */
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

		String datasource_obj_ids_list = CommunicationsManager.buildCSVString(ds_ids);
		if (!datasource_obj_ids_list.isEmpty()) {
			sql = " artifacts.data_source_obj_id IN ( " + datasource_obj_ids_list + " )";
		}

		return sql;
	}
}
