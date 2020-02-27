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
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.blackboardutils.attributes.TskGeoWaypointsUtil.GeoWaypointList;
import org.sleuthkit.datamodel.blackboardutils.attributes.TskGeoWaypointsUtil.GeoWaypointList.GeoWaypoint;

/**
 * Utility class for Translating TSK_GEO_WAYPOINTS attribute values to
 * GeoWaypointList objects and GeoWaypointList to BlackboardAttributes.
 */
public final class TskGeoWaypointsUtil implements BlackboardAttributeUtil<GeoWaypointList> {

	private final String moduleName;

	/**
	 * Constructs a new instance of the Translator Utility.
	 *
	 * @param moduleName Name of calling module.
	 */
	public TskGeoWaypointsUtil(String moduleName) {
		this.moduleName = moduleName;
	}

	@Override
	public BlackboardAttribute toAttribute(GeoWaypointList value) {

		if (value == null) {
			throw new IllegalArgumentException("toAttribute was pass a null list.");
		}

		return new BlackboardAttribute(
				BlackboardAttribute.ATTRIBUTE_TYPE.TSK_GEO_WAYPOINTS,
				moduleName,
				toJSON(value));
	}

	@Override
	public GeoWaypointList fromAttribute(BlackboardAttribute attribute) {
		if (attribute == null) {
			throw new IllegalArgumentException("Null value passed to fromAttribute");
		}

		BlackboardAttribute.ATTRIBUTE_TYPE type = BlackboardAttribute.ATTRIBUTE_TYPE.fromID(attribute.getAttributeType().getTypeID());
		if (type != BlackboardAttribute.ATTRIBUTE_TYPE.TSK_GEO_WAYPOINTS) {
			throw new IllegalArgumentException(String.format("Invalid attribute of type %s passed to fromAttribute method. Attribute of type TSK_GEO_WAYPOINTS is required", type.getDisplayName()));
		}

		return fromJSON(attribute.getValueString());
	}

	/**
	 * Deserialize the given list of GeoTrackPoints.
	 *
	 * @param jsonString JSon string of track points.
	 *
	 * @return	Timestamp ordered list of GeoTrackPoints, empty list will be
	 *         returned if jsonString is null or empty.
	 */
	private static GeoWaypointList fromJSON(String jsonString) {
		if (jsonString == null || jsonString.isEmpty()) {
			return null;
		}

		return (new Gson()).fromJson(jsonString, GeoWaypointList.class);
	}

	/**
	 * Returns a JSON string can than be used as the TSK_GEO_TRACKPOINTS 
	 * attribute of the TSK_GPS_TRACK artifact.
	 *
	 * @return JSON string
	 */
	private static String toJSON(GeoWaypointList pointList) {
		Gson gson = new Gson();
		return gson.toJson(pointList);
	}

	/**
	 * Helper class to make it easier to serialize and deserialize the list of
	 * waypoints points with json.
	 *
	 */
	public static final class GeoWaypointList implements Iterable<GeoWaypointList.GeoWaypoint> {

		private final List<GeoWaypoint> points;

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
		 * Returns true if this list contains no points.
		 *
		 * @return True if this list contains no points.
		 */
		public boolean isEmpty() {
			return points.isEmpty();
		}

		@Override
		public Iterator<GeoWaypointList.GeoWaypoint> iterator() {
			return points.iterator();
		}

		/**
		 * Class that represents a single waypoint made up of longitude,
		 * latitude, and altitude.
		 */
		public static class GeoWaypoint {

			private final Double latitude;
			private final Double longitude;
			private final Double altitude;
			private final String name;

			/**
			 * Creates a GeoWaypoint instance.
			 *
			 * @param latitude  The latitude, required
			 * @param longitude The longitude, required
			 * @param altitude  The altitude, can be null
			 * @param name		A name for the waypoint, optional
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
			 * @return Double altitude value, may be null if not available or
			 *         applicable
			 */
			public Double getAltitude() {
				return altitude;
			}
			
			/**
			 * Returns the name for this waypoint.  
			 * @return	Returns waypoint name, may be null if not available or 
			 *			applicable.
			 */
			public String getName() {
				return name;
			}
		}
	}
}
