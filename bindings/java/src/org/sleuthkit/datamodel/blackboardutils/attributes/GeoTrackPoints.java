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
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import org.sleuthkit.datamodel.blackboardutils.attributes.GeoWaypoint.GeoTrackPoint;

/**
 * Helper class to make it easier to serialize and deserialize the list of track
 * points with json.
 *
 */
public final class GeoTrackPoints {

	private final List<GeoTrackPoint> points;

	/**
	 * Deserialize the given list of GeoTrackPoints.
	 *
	 * @param jsonString JSon string of track points.
	 *
	 * @return	Timestamp ordered list of GeoTrackPoints, empty list will be
	 *         returned if jsonString is null or empty.
	 */
	public static List<GeoTrackPoint> deserializePoints(String jsonString) {
		if (jsonString == null || jsonString.isEmpty()) {
			return new ArrayList<>();
		}

		GeoTrackPoints trackPoints = (new Gson()).fromJson(jsonString, GeoTrackPoints.class);
		return trackPoints.getTimeOrderedPoints();
	}

	/**
	 * Serialize the given list of GeoTrackPoints.
	 *
	 * @param points List of GeoTrackPoints
	 *
	 * @return	JSon formatted string is returned or empty string if points was
	 *         null
	 */
	public static String serializePoints(List<GeoTrackPoint> points) {
		if (points == null) {
			return "";
		}

		Gson gson = new Gson();
		return gson.toJson(new GeoTrackPoints(points));
	}

	/**
	 * Constructs a new instance with the give list of GeoTrackPoints.
	 *
	 * @param points
	 */
	private GeoTrackPoints(List<GeoTrackPoint> points) {
		if (points == null) {
			throw new IllegalArgumentException("Invalid list of track points passed to constructor");
		}

		this.points = points;
	}

	/**
	 * Returns a timestamp ordered copy of the points list.
	 *
	 * @return timestamp
	 */
	private List<GeoTrackPoint> getTimeOrderedPoints() {
		return points.stream().sorted().collect(Collectors.toCollection(ArrayList::new));
	}

	/**
	* Helper class to make it easier to serialize and deserialize the list of waypoints
	* points with json.
	*
	*/
	public final static class GeoWaypoints {

		private final List<GeoWaypoint> points;

		/**
		 * Deserialize the given list of GeoWaypoints.
		 *
		 * @param jsonString JSon string of waypoints.
		 *
		 * @return	Timestamp ordered list of GeoWaypoints, empty list will be
		 *         returned if jsonString is null or empty.
		 */
		public static List<GeoWaypoint> deserializePoints(String jsonString) {
			if (jsonString == null || jsonString.isEmpty()) {
				return new ArrayList<>();
			}

			GeoWaypoints wayPoints = (new Gson()).fromJson(jsonString, GeoWaypoints.class);
			return wayPoints.getPoints();
		}

		/**
		 * Serialize the given list of GeoTrackPoints.
		 *
		 * @param points List of GeoWaypoints
		 *
		 * @return	JSon formatted string is returned or empty string if points
		 *         was null
		 */
		public static String serializePoints(List<GeoWaypoint> points) {
			if (points == null) {
				return "";
			}

			Gson gson = new Gson();
			return gson.toJson(new GeoWaypoints(points));
		}

		/**
		 * Constructs a new instance with the give list of GeoWaypoints.
		 *
		 * @param points
		 */
		private GeoWaypoints(List<GeoWaypoint> points) {
			if (points == null) {
				throw new IllegalArgumentException("Invalid list of track points passed to constructor");
			}

			this.points = points;
		}
		
		/**
		 * Returns the list of GeoWaypoint
		 * 
		 * @return Returns unmodifiableListlist of GeoWaypoints, or 
		 */
		private List<GeoWaypoint> getPoints() {
			return Collections.unmodifiableList(points);
		}
	}
}
