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
package org.sleuthkit.datamodel.blackboardutils.attributes;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Helper class to make it easier to serialize and deserialize the list of
 * waypoints points with json.
 *
 */
public final class GeoWaypointList {

	private final List<GeoWaypoint> points;

	/**
	 * Deserialize the given list of GeoWaypointList.
	 *
	 * @param jsonString JSon string of waypoints.
	 *
	 * @return	Timestamp ordered list of GeoWaypointList, empty list will be
         returned if jsonString is null or empty.
	 */
	public static GeoWaypointList deserialize(String jsonString) {
		if (jsonString == null || jsonString.isEmpty()) {
			return null;
		}

		return (new Gson()).fromJson(jsonString, GeoWaypointList.class);
	}

	
	public GeoWaypointList() {
		points = new ArrayList<>();
	}
	
	/**
	 * Adds a point to the list of waypoints.
	 * 
	 * @param latitude  The latitude, required
	 * @param longitude The longitude, required
	 * @param altitude  The altitude, can be null
	 * @param name		A name for the point, can be null
	 */
	public void addPoint(Double latitude, Double longitude, Double altitude, String name) {
		points.add(new GeoWaypoint(latitude, longitude, altitude, name));
	}
	
	/**
	 * Returns an iterator over the points in the list.
	 * 
	 * @return An iterator over the elements of the list.
	 */
	public Iterator<GeoWaypoint> iterator() {
		return points.iterator();
	}
	
	/**
	 * Returns true if this list contains no points.
	 * 
	 * @return True if this list contains no points.
	 */
	public boolean isEmpty() {
		return points.isEmpty();
	}
	
	/**
	 * Returns serializes this object to JSON. The JSON string can than be
	 * used as the TSK_GEO_TRACKPOINTS attribute of the TSK_GPS_TRACK artifact.
	 * 
	 * @return JSON string
	 */
	public String serialize() {
		Gson gson = new Gson();
		return gson.toJson(this);
	}

	/**
	 * Class that represents a single waypoint made up of longitude, latitude,
	 * and altitude.
	 */
	public static class GeoWaypoint {

		@SerializedName("TSK_GEO_LATITUDE")
		private final Double latitude;
		@SerializedName("TSK_GEO_LONGITUDE")
		private final Double longitude;
		@SerializedName("TSK_GEO_ALTITUDE")
		private final Double altitude;
		@SerializedName("TSK_NAME")
		private final String name;

		/**
		 * Creates a GeoWaypoint instance.
		 *
		 * @param latitude  The latitude, required
		 * @param longitude The longitude, required
		 * @param altitude  The altitude, can be null
		 */
		public GeoWaypoint(Double latitude, Double longitude, Double altitude, String name) {
			if (latitude == null || longitude == null) {
				throw new IllegalArgumentException("Null cordinate value passed to waypoint constructor");
			}

			this.latitude = latitude;
			this.longitude = longitude;
			this.altitude = altitude;
			this.name = name;
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
		 * @return Double altitude value, maybe null if not available or
		 *         applicable
		 */
		public Double getAltitude() {
			return altitude;
		}
	}
}
