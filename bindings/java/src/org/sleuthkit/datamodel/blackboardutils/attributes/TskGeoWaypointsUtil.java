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
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.blackboardutils.attributes.TskGeoWaypointsUtil.GeoWaypointList;
import org.sleuthkit.datamodel.blackboardutils.attributes.TskGeoWaypointsUtil.GeoWaypointList.GeoWaypoint;

/**
 * A utility class for converting between a TSK_GEO_WAYPOINTS attribute and a
 * GeoWaypointList object. A GeoWaypointList is a collection of GeoWaypoints
 * objects. A GeoWaypoint represents a waypoint for a GPS-enabled device with a
 * navigation capability. Every waypoint is a location, possibly named, in a
 * geographic coordinate system with latitude, longitude and altitude
 * (elevation) axes.
 *
 * TSK_GEO_WAYPOINTS attributes are used by TSK_GPS_ROUTE artifacts to record
 * one or more waypoints linked together as a route to be navigated from
 * waypoint to waypoint.
 */
public final class TskGeoWaypointsUtil implements BlackboardAttributeUtil<GeoWaypointList> {

	@Override
	public BlackboardAttribute toAttribute(String moduleName, GeoWaypointList value) {
		if (value == null) {
			throw new IllegalArgumentException("toAttribute was pass a null list");
		}

		return new BlackboardAttribute(
				BlackboardAttribute.ATTRIBUTE_TYPE.TSK_GEO_WAYPOINTS,
				moduleName,
				toJSON(value));
	}

	@Override
	public GeoWaypointList fromAttribute(BlackboardAttribute attribute) {
		if (attribute == null) {
			throw new IllegalArgumentException("fromAttribute was pass a null list");
		}

		BlackboardAttribute.ATTRIBUTE_TYPE type = BlackboardAttribute.ATTRIBUTE_TYPE.fromID(attribute.getAttributeType().getTypeID());
		if (type != BlackboardAttribute.ATTRIBUTE_TYPE.TSK_GEO_WAYPOINTS) {
			throw new IllegalArgumentException(String.format("Invalid attribute of type %s passed to fromAttribute method. Attribute of type TSK_GEO_WAYPOINTS is required", type.getDisplayName()));
		}

		return fromJSON(attribute.getValueString());
	}

	/**
	 * Constructs a GeoWaypointList object from its JSON representation.
	 *
	 * @param json A JSON representation of a GeoWaypointList.
	 *
	 * @return	The GeoWaypointList object.
	 */
	private static GeoWaypointList fromJSON(String json) {
		if (json == null || json.isEmpty()) {
			return null;
		}

		return (new Gson()).fromJson(json, GeoWaypointList.class);
	}

	/**
	 * Creates a JSON representation of a GeoWaypointList object.
	 *
	 * @param waypoints A GeoWaypointList object.
	 *
	 * @return The JSON representation of the GeoWaypointList object.
	 */
	private static String toJSON(GeoWaypointList waypoints) {
		Gson gson = new Gson();
		return gson.toJson(waypoints);
	}

	/**
	 * A list of GeoWaypoints. A GeoWaypoint represents a waypoint, which is a a
	 * location, possibly named, in a geographic coordinate system with
	 * latitude, longitude and altitude (elevation) axes.
	 */
	public static final class GeoWaypointList implements Iterable<GeoWaypointList.GeoWaypoint> {

		private final List<GeoWaypoint> points;

		/**
		 * Constructs an empty GeoWaypointList.
		 */
		public GeoWaypointList() {
			points = new ArrayList<>();
		}

		/**
		 * Adds a waypoint to this list of waypoints.
		 *
		 * @param wayPoint A waypoint.
		 */
		public void addPoint(GeoWaypoint wayPoint) {
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
		public Iterator<GeoWaypointList.GeoWaypoint> iterator() {
			return points.iterator();
		}

		/**
		 * A representation of a waypoint, which is a a location, possibly
		 * named, in a geographic coordinate system with latitude, longitude and
		 * altitude (elevation) axes.
		 */
		public static class GeoWaypoint {

			private final Double latitude;
			private final Double longitude;
			private final Double altitude;
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
			public GeoWaypoint(Double latitude, Double longitude, Double altitude, String name) {
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
			 * Get the altitude of this waypoint, if available.
			 *
			 * @return The altitude, may be null or zero.
			 */
			public Double getAltitude() {
				return altitude;
			}

			/**
			 * Get the name of this waypoint, if available.
			 *
			 * @return	The name, may be null or empty.
			 */
			public String getName() {
				return name;
			}
		}
	}
}
