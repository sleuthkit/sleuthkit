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

import com.google.gson.annotations.SerializedName;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * A GeoWaypoints object is a collection of Waypoint objects. A Waypoint object
 * represents a waypoint for a GPS-enabled device with a navigation capability.
 * Every waypoint is a location, possibly named, in a geographic coordinate
 * system with latitude, longitude and altitude (elevation) axes.
 *
 * GeoWaypoints objects are designed to be used as the string value of the
 * TSK_GEO_WAYPOINTS attribute of a TSK_GPS_ROUTE artifact. TSK_GPS_ROUTE
 * artifacts are used to record one or more waypoints linked together as a route
 * to be navigated from waypoint to waypoint.
 */
public class GeoWaypoints implements Iterable<GeoWaypoints.Waypoint> {

	private final List<Waypoint> points;

	/**
	 * Constructs an empty GeoWaypoints object.
	 */
	public GeoWaypoints() {
		points = new ArrayList<>();
	}

	/**
	 * Adds a waypoint to this list of waypoints.
	 *
	 * @param wayPoint A waypoint.
	 */
	public void addPoint(Waypoint wayPoint) {
		if (wayPoint == null) {
			throw new IllegalArgumentException("addPoint was passed a null waypoint");
		}

		points.add(wayPoint);
	}

	/**
	 * Returns whether or not this list of waypoints is empty.
	 *
	 * @return True or false.
	 */
	public boolean isEmpty() {
		return points.isEmpty();
	}

	@Override
	public Iterator<Waypoint> iterator() {
		return points.iterator();
	}

	/**
	 * A representation of a waypoint, which is a a location, possibly named, in
	 * a geographic coordinate system with latitude, longitude and altitude
	 * (elevation) axes.
	 */
	public static class Waypoint {

		@SerializedName("TSK_GEO_LATITUDE")
		private final Double latitude;
		@SerializedName("TSK_GEO_LONGITUDE")
		private final Double longitude;
		@SerializedName("TSK_GEO_ALTITUDE")
		private final Double altitude;
		@SerializedName("TSK_NAME")
		private final String name;

		/**
		 * Constructs a representation of a waypoint, which is a a location,
		 * possibly named, in a geographic coordinate system with latitude,
		 * longitude and altitude (elevation) axes.
		 *
		 * @param latitude  The latitude of the waypoint.
		 * @param longitude The longitude of the waypoint.
		 * @param altitude  The altitude of the waypoint, may be null.
		 * @param name      The name of the waypoint, may be null.
		 */
		public Waypoint(Double latitude, Double longitude, Double altitude, String name) {
			if (latitude == null) {
				throw new IllegalArgumentException("Constructor was passed null latitude");
			}

			if (longitude == null) {
				throw new IllegalArgumentException("Constructor was passed null longitude");
			}

			this.latitude = latitude;
			this.longitude = longitude;
			this.altitude = altitude;
			this.name = name;
		}

		/**
		 * Gets the latitude of this waypoint.
		 *
		 * @return The latitude.
		 */
		public Double getLatitude() {
			return latitude;
		}

		/**
		 * Gets the longitude of this waypoint.
		 *
		 * @return The longitude.
		 */
		public Double getLongitude() {
			return longitude;
		}

		/**
		 * Gets the altitude of this waypoint, if available.
		 *
		 * @return The altitude, may be null or zero.
		 */
		public Double getAltitude() {
			return altitude;
		}

		/**
		 * Gets the name of this waypoint, if available.
		 *
		 * @return	The name, may be null or empty.
		 */
		public String getName() {
			return name;
		}
	}

}
