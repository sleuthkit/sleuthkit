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
		if (latitude == null || longitude == null) {
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

	/**
	 * A GeoTrackPoint is a Waypoint with more detailed information about the
	 * point.
	 *
	 */
	public final static class GeoTrackPoint extends GeoWaypoint implements Comparable<GeoTrackPoint> {

		@SerializedName("TSK_GEO_VELOCITY")
		private final Double velocity;
		@SerializedName("TSK_GEO_DISTANCE_FROM_HOME_POINT")
		private final Double distanceFromHP;
		@SerializedName("TSK_GEO_DISTANCE_TRAVELED")
		private final Double distanceTraveled;
		@SerializedName("TSK_DATETIME")
		private final Long timestamp;

		/**
		 * Constructs a GeoTrackPoint with the given attributes.
		 *
		 * @param latitude			      Latitude of the trackpoint, required
		 * @param longitude			     Longitude of the trackpoint, required
		 * @param altitude			      Altitude of the trackpoint, maybe null
		 * @param velocity			      Velocity in meters/sec, maybe null
		 * @param distanceFromHP	  Trackpoint distance from an established "home
		 *                         point", maybe null if not applicable
		 * @param distanceTraveled	Overall distance traveled in meters at the
		 *                         time this trackpoint was created, maybe null
		 *                         if not applicable
		 * @param timestamp			     Trackpoint creation time, maybe null if not
		 *                         applicable
		 */
		public GeoTrackPoint(Double latitude,
				Double longitude,
				Double altitude,
				Double velocity,
				Double distanceFromHP,
				Double distanceTraveled,
				Long timestamp) {
			super(latitude, longitude, altitude);
			this.velocity = velocity;
			this.distanceFromHP = distanceFromHP;
			this.distanceTraveled = distanceTraveled;
			this.timestamp = timestamp;
		}

		/**
		 * Returns velocity of the point.
		 *
		 * @return Double velocity value, maybe null if not available or
		 *         applicable
		 */
		public Double getVelocity() {
			return velocity;
		}

		/**
		 * Returns distance from home point for the point.
		 *
		 * @return Double velocity distance from home point, maybe null if not
		 *         available or applicable
		 */
		public Double getDistanceFromHP() {
			return distanceFromHP;
		}

		/**
		 * Returns distance traveled for the point.
		 *
		 * @return Double distance traveled value, maybe null if not available
		 *         or applicable
		 */
		public Double getDistanceTraveled() {
			return distanceTraveled;
		}

		/**
		 * Returns the time stamp (seconds from java/unix epoch) of the track
		 * point.
		 *
		 * @return time stamp of the track point, or null if not available
		 */
		public Long getTimeStamp() {
			return timestamp;
		}

		@Override
		public int compareTo(GeoTrackPoint otherTP) {
			Long otherTimeStamp = otherTP.getTimeStamp();

			if (timestamp == null && otherTimeStamp != null) {
				return -1;
			} else if (timestamp != null && otherTimeStamp == null) {
				return 1;
			} else {
				return timestamp.compareTo(otherTP.getTimeStamp());
			}
		}
	}

}
