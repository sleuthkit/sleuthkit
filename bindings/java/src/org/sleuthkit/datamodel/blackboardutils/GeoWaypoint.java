/*
 * Sleuth Kit Data Model
 *
 * Copyright 2020 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	 http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.datamodel.blackboardutils;

import com.google.gson.annotations.SerializedName;

/**
 * Class that represents a single waypoint made up of longitude, latitude, and
 * altitude.
 */
public class GeoWaypoint {

	@SerializedName("TSK_GEO_LATITUDE")
	private final Double latitude;
	@SerializedName("TSK_GEO_LONGITUDE")
	private final Double longitude;
	@SerializedName("TSK_GEO_ALTITUDE")
	private final Double altitude;

	/**
	 * Creates a GeoWaypoint instance.
	 *
	 * @param latitude  The latitude, required
	 * @param longitude The longitude, required
	 * @param altitude  The altitude, can be null
	 */
	public GeoWaypoint(Double latitude, Double longitude, Double altitude) {
		if(latitude == null || longitude == null) {
			throw new IllegalArgumentException("Null cordinate value passed to waypoint constructor");
		}
		
		this.latitude = latitude;
		this.longitude = longitude;
		this.altitude = altitude;
	}

	/**
	 * Returns latitude of the waypoint.
	 *
	 * @return Double latitude value
	 */
	public Double getLatitude() {
		return latitude;
	}

	/**
	 * Returns longitude of the waypoint.
	 *
	 * @return Double longitude value
	 */
	public Double getLongitude() {
		return longitude;
	}

	/**
	 * Get the altitude if available for this waypoint.
	 *
	 * @return Double altitude value, maybe null if not available or applicable
	 */
	public Double getAltitude() {
		return altitude;
	}

}
