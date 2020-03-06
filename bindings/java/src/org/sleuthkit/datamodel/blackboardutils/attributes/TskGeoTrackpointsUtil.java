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
import java.util.stream.Collectors;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.blackboardutils.attributes.TskGeoTrackpointsUtil.GeoTrackPointList;
import org.sleuthkit.datamodel.blackboardutils.attributes.TskGeoTrackpointsUtil.GeoTrackPointList.GeoTrackPoint;

/**
 * A utility class for converting between a JSON-valued TSK_GEO_TRACKPOINTS
 * attribute and a GeoTrackPointList object. A GeoTrackPointList is a collection
 * of GeoTrackPoint objects. A GeoTrackPoint object represents a track point,
 * which is a location in a geographic coordinate system (see
 * https://en.wikipedia.org/wiki/Geographic_coordinate_system) where the
 * coordinates are latitude, longitude and altitude (elevation).
 *
 * A TSK_GEO_TRACKPOINTS atrribute is typically attached to a TSK_GPS_TRACK
 * artifact. A TSK_GPS_TRACK artifact records a track, or path, of a GPS-enabled
 * device as a connected series of track points.
 */
public final class TskGeoTrackpointsUtil implements BlackboardAttributeUtil<TskGeoTrackpointsUtil.GeoTrackPointList> {

	@Override
	public BlackboardAttribute toAttribute(String moduleName, GeoTrackPointList value) {

		if (value == null) {
			throw new IllegalArgumentException("toAttribute was passed a null list");
		}

		return new BlackboardAttribute(
				BlackboardAttribute.ATTRIBUTE_TYPE.TSK_GEO_TRACKPOINTS,
				moduleName,
				toJSON(value));
	}

	@Override
	public GeoTrackPointList fromAttribute(BlackboardAttribute attribute) {
		if (attribute == null) {
			throw new IllegalArgumentException("fromAttribute was passed a null attribute");
		}

		BlackboardAttribute.ATTRIBUTE_TYPE type = BlackboardAttribute.ATTRIBUTE_TYPE.fromID(attribute.getAttributeType().getTypeID());
		if (type != BlackboardAttribute.ATTRIBUTE_TYPE.TSK_GEO_TRACKPOINTS) {
			throw new IllegalArgumentException(String.format("Invalid attribute of type %s passed to fromAttribute method. Attribute of type TSK_GEO_TRACKPOINTS is required", type.getDisplayName()));
		}

		return fromJSON(attribute.getValueString());
	}

	/**
	 * Constructs a GeoTrackPointList object from a GeoTrackPointList serailized
	 * as JSON.
	 *
	 * @param trackPointsJson A JSON representation of a GeoTrackPointList.
	 *
	 * @return	The GeoTrackPointList object.
	 */
	private static GeoTrackPointList fromJSON(String trackPointsJson) {
		if (trackPointsJson == null || trackPointsJson.isEmpty()) {
			throw new IllegalArgumentException("fromJSON was passed a empty or null JSON string");
		}

		return (new Gson()).fromJson(trackPointsJson, GeoTrackPointList.class);
	}

	/**
	 * Serializes a GeoTrackPointList object as JSON.
	 *
	 * @param trackPoints A GeoTrackPointList object.
	 *
	 * @return The JSON serialization of the GeoTrackPointList.
	 */
	private static String toJSON(GeoTrackPointList trackPoints) {
		if (trackPoints == null) {
			throw new IllegalArgumentException("toJSON was passed a null track points list");
		}

		Gson gson = new Gson();
		return gson.toJson(trackPoints);
	}

	/**
	 * A collection of GeoTrackPoint objects. A GeoTrackPoint object represents
	 * a track point, which is a location in a geographic coordinate system (see
	 * https://en.wikipedia.org/wiki/Geographic_coordinate_system) where the
	 * coordinates are latitude, longitude and altitude (elevation).
	 */
	public static class GeoTrackPointList implements Iterable<GeoTrackPointList.GeoTrackPoint> {

		private final List<GeoTrackPoint> pointList;

		/**
		 * Constructs an empty GeoTrackPointList.
		 */
		public GeoTrackPointList() {
			pointList = new ArrayList<>();
		}

		/**
		 * Constructs a GeoTrackPointList from a list of GeoTrackPoint objects.
		 *
		 * @param trackPoints A list of GeoTrackPoint objects.
		 */
		public GeoTrackPointList(List<GeoTrackPoint> trackPoints) {
			if (trackPoints == null) {
				throw new IllegalArgumentException("Constructor was passed a null list");
			}

			pointList = new ArrayList<>();
			for (GeoTrackPoint point : trackPoints) {
				pointList.add(new GeoTrackPoint(point));
			}
		}

		/**
		 * Adds a track point to this list of track points.
		 *
		 * @param trackPoint A track point.
		 */
		public void addPoint(GeoTrackPoint trackPoint) {
			if (trackPoint == null) {
				throw new IllegalArgumentException("addPoint was passed a null track point");
			}

			pointList.add(trackPoint);
		}

//		/**
//		 * Adds a track point to this list of track points.
//		 *
//		 * @param latitude              The latitude of the track point.
//		 * @param longitude             The longitude of the trac kpoint.
//		 * @param altitude              The altitude of the track point, may be
//		 *                              null.
//		 * @param name                  The name of the track point, may be
//		 *                              null.
//		 * @param velocity              The velocity of the device at the track
//		 *                              point in meters/sec, may be null.
//		 * @param distanceFromHomePoint	The distance of the track point from an
//		 *                              established home point, may be null.
//		 * @param distanceTraveled      The distance the device has traveled in
//		 *                              meters at the time this track point was
//		 *                              created, may be null
//		 * @param timestamp             The creation time of the track point as
//		 *                              milliseconds from the Java epoch of
//		 *                              1970-01-01T00:00:00Z, may be null.
//		 */
//		public void addPoint(Double latitude,
//				Double longitude,
//				Double altitude,
//				String name,
//				Double velocity,
//				Double distanceFromHomePoint,
//				Double distanceTraveled,
//				Long timestamp) {
//			pointList.add(new GeoTrackPoint(
//					latitude,
//					longitude,
//					altitude,
//					name,
//					velocity,
//					distanceFromHomePoint,
//					distanceTraveled,
//					timestamp));
//		}

		/**
		 * Gets an iterator for the track points in this list of track points.
		 *
		 * @return The iterator.
		 */
		@Override
		public Iterator<GeoTrackPoint> iterator() {
			return pointList.iterator();
		}

		/**
		 * Returns whether or not this list of track points is empty.
		 *
		 * @return True or false.
		 */
		public boolean isEmpty() {
			return pointList.isEmpty();
		}

		/**
		 * Get the nominal start time for the track represented by this list of
		 * track points, if available.
		 *
		 * @return The earliest timestamp of a track point in this list of track
		 *         points, may be null.
		 */
		public Long getStartTime() {
			List<GeoTrackPoint> orderedPoints = getTimeOrderedPoints();
			if (orderedPoints != null) {
				for (GeoTrackPoint point : orderedPoints) {
					if (point.getTimeStamp() != null) {
						return point.getTimeStamp();
					}
				}
			}
			return null;
		}

		/**
		 * Get the nominal end time for the track represented by this list of
		 * track points, if available.
		 *
		 * @return The latest timestamp of a track point in this list of track
		 *         points, may be null.
		 */
		public Long getEndTime() {
			List<GeoTrackPoint> orderedPoints = getTimeOrderedPoints();
			if (orderedPoints != null) {
				for (int index = orderedPoints.size() - 1; index >= 0; index--) {
					GeoTrackPoint point = orderedPoints.get(index);
					if (point.getTimeStamp() != null) {
						return point.getTimeStamp();
					}
				}
			}
			return null;
		}

		/**
		 * Gets the list of track points in this object as a list ordered by
		 * tarck point timestamp.
		 *
		 * @return The ordered list of track points.
		 */
		private List<GeoTrackPoint> getTimeOrderedPoints() {
			return pointList.stream().sorted().collect(Collectors.toCollection(ArrayList::new));
		}

		/**
		 * A representation of a track point, which is a location in a
		 * geographic coordinate system (see
		 * https://en.wikipedia.org/wiki/Geographic_coordinate_system) where the
		 * coordinates are latitude, longitude and altitude (elevation).
		 */
		public final static class GeoTrackPoint extends TskGeoWaypointsUtil.GeoWaypointList.GeoWaypoint implements Comparable<GeoTrackPoint> {

			private final Double velocity;
			private final Double distanceFromHomePoint;
			private final Double distanceTraveled;
			private final Long timestamp;

			/**
			 * Constructs a representation of a track point, which is a location
			 * in a geographic coordinate system (see
			 * https://en.wikipedia.org/wiki/Geographic_coordinate_system) where
			 * the coordinates are latitude, longitude and altitude (elevation).
			 *
			 * @param latitude              The latitude of the track point.
			 * @param longitude             The longitude of the trac kpoint.
			 * @param altitude              The altitude of the track point, may
			 *                              be null.
			 * @param name                  The name of the track point, may be
			 *                              null.
			 * @param velocity              The velocity of the device at the
			 *                              track point in meters/sec, may be
			 *                              null.
			 * @param distanceFromHomePoint	The distance of the track point in
			 *                              meters from an established home
			 *                              point, may be null.
			 * @param distanceTraveled      The distance the device has traveled
			 *                              in meters at the time this track
			 *                              point was created, may be null.
			 * @param timestamp             The creation time of the track point
			 *                              as milliseconds from the Java epoch
			 *                              of 1970-01-01T00:00:00Z, may be
			 *                              null.
			 */
			public GeoTrackPoint(Double latitude,
					Double longitude,
					Double altitude,
					String name,
					Double velocity,
					Double distanceFromHomePoint,
					Double distanceTraveled,
					Long timestamp) {
				super(latitude, longitude, altitude, name);
				this.velocity = velocity;
				this.distanceFromHomePoint = distanceFromHomePoint;
				this.distanceTraveled = distanceTraveled;
				this.timestamp = timestamp;
			}

			/**
			 * Constructs a copy of a representation of a track point, which is
			 * a location in a geographic coordinate system (see
			 * https://en.wikipedia.org/wiki/Geographic_coordinate_system) where
			 * the coordinates are latitude, longitude and altitude (elevation).
			 *
			 * @param other A GeoTrackPoint to be copied.
			 */
			private GeoTrackPoint(GeoTrackPoint other) {
				super(other.getLatitude(), other.getLongitude(), other.getAltitude(), other.getName());
				this.velocity = other.getVelocity();
				this.distanceFromHomePoint = other.getDistanceFromHomePoint();
				this.distanceTraveled = other.getDistanceTraveled();
				this.timestamp = other.getTimeStamp();
			}

			/**
			 * Gets the velocity of the device at this track point in
			 * meters/sec, if known.
			 *
			 * @return The velocity in meters/sec, may be null.
			 */
			public Double getVelocity() {
				return velocity;
			}

			/**
			 * Gets the distance of this track point from an established home
			 * point, if known.
			 *
			 * @return The distance in meters, may be null.
			 */
			public Double getDistanceFromHomePoint() {
				return distanceFromHomePoint;
			}

			/**
			 * Gets the distance the device has traveled in meters at the time
			 * this track point was created, if known.
			 *
			 *
			 * @return The distance traveled in meters, may be null.
			 */
			public Double getDistanceTraveled() {
				return distanceTraveled;
			}

			/**
			 * Gets the creation time of this track point as milliseconds from
			 * the Java epoch of 1970-01-01T00:00:00Z, if known.
			 *
			 * @return The creation timestamp, may be null.
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

}
