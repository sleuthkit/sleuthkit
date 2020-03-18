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
import java.util.stream.Collectors;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.blackboardutils.attributes.TskGeoTrackpointsUtil.GeoTrackPointList;
import org.sleuthkit.datamodel.blackboardutils.attributes.TskGeoTrackpointsUtil.GeoTrackPointList.GeoTrackPoint;

/**
 * A utility class for converting between a TSK_GEO_TRACKPOINTS attribute and a
 * GeoTrackPointList. A GeoTrackPointList is a collection of GeoTrackPoints. A
 * GeoTrackPoint represents a track point, which is a location in a geographic
 * coordinate system with latitude, longitude and altitude (elevation) axes.
 *
 * TSK_GEO_TRACKPOINTS attributes are used by TSK_GPS_TRACK artifacts to record
 * a track, or path, of a GPS-enabled device as a connected series of track
 * points.
 */
public final class TskGeoTrackpointsUtil implements BlackboardAttributeUtil<GeoTrackPointList> {

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
	 * Constructs a GeoTrackPointList object from its JSON representation.
	 *
	 * @param json A JSON representation of a GeoTrackPointList.
	 *
	 * @return	The GeoTrackPointList object.
	 */
	private static GeoTrackPointList fromJSON(String json) {
		if (json == null || json.isEmpty()) {
			throw new IllegalArgumentException("fromJSON was passed a empty or null JSON string");
		}

		return (new Gson()).fromJson(json, GeoTrackPointList.class);
	}

	/**
	 * Creates a JSON representation of a GeoTrackPointList object.
	 *
	 * @param trackPoints A GeoTrackPointList object.
	 *
	 * @return The JSON representation of the GeoTrackPointList object.
	 */
	private static String toJSON(GeoTrackPointList trackPoints) {
		if (trackPoints == null) {
			throw new IllegalArgumentException("toJSON was passed a null track points list");
		}

		Gson gson = new Gson();
		return gson.toJson(trackPoints);
	}

	/**
	 * A list of GeoTrackPoints. A GeoTrackPoint represents a track point, which
	 * is a location in a geographic coordinate system with latitude, longitude
	 * and altitude (elevation) axes.
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
		 * Gets the earliest track point timestamp in this list of track points,
		 * if timestamps are present.
		 *
		 * @return The timestamp in milliseconds from the Java epoch of
		 *         1970-01-01T00:00:00Z, may be null or zero.
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
		 * Gets the latest track point timestamp in this list of track points,
		 * if timestamps are present.
		 *
		 * @return The timestamp in milliseconds from the Java epoch of
		 *         1970-01-01T00:00:00Z, may be null or zero.
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
		 * Gets this list of track points as a list ordered by track point
		 * timestamp.
		 *
		 * @return The ordered list of track points.
		 */
		private List<GeoTrackPoint> getTimeOrderedPoints() {
			return pointList.stream().sorted().collect(Collectors.toCollection(ArrayList::new));
		}

		/**
		 * A representation of a track point, which is a location in a
		 * geographic coordinate system with latitude, longitude and altitude
		 * (elevation) axes.
		 */
		public final static class GeoTrackPoint extends TskGeoWaypointsUtil.GeoWaypointList.GeoWaypoint implements Comparable<GeoTrackPoint> {

			@SerializedName("TSK_GEO_VELOCITY")
			private final Double velocity;
			@SerializedName("TSK_DISTANCE_FROM_HOMEPOINT")
			private final Double distanceFromHomePoint;
			@SerializedName("TSK_DISTANCE_TRAVELED")
			private final Double distanceTraveled;
			@SerializedName("TSK_DATETIME")
			private final Long timestamp;

			/**
			 * Constructs a representation of a track point, which is a location
			 * in a geographic coordinate system with latitude, longitude and
			 * altitude (elevation) axes.
			 *
			 * @param latitude              The latitude of the track point.
			 * @param longitude             The longitude of the track point.
			 * @param altitude              The altitude of the track point, may
			 *                              be null.
			 * @param name                  The name of the track point, may be
			 *                              null.
			 * @param velocity              The velocity of the device at the
			 *                              track point in meters per second,
			 *                              may be null.
			 * @param distanceFromHomePoint	The distance of the track point in
			 *                              meters from an established home
			 *                              point, may be null.
			 * @param distanceTraveled      The distance the device has traveled
			 *                              in meters at the time this track
			 *                              point was created, may be null.
			 * @param timestamp             The timestamp of the track point as
			 *                              milliseconds from the Java epoch of
			 *                              1970-01-01T00:00:00Z, may be null.
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
			 * Gets the velocity of the device at this track point in meters per
			 * second, if known.
			 *
			 * @return The velocity in meters/sec, may be null or zero.
			 */
			public Double getVelocity() {
				return velocity;
			}

			/**
			 * Gets the distance of this track point from an established home
			 * point, if known.
			 *
			 * @return The distance in meters, may be null or zero.
			 */
			public Double getDistanceFromHomePoint() {
				return distanceFromHomePoint;
			}

			/**
			 * Gets the distance the device has traveled in meters at the time
			 * this track point was created, if known.
			 *
			 * @return The distance traveled in meters, may be null or zero.
			 */
			public Double getDistanceTraveled() {
				return distanceTraveled;
			}

			/**
			 * Gets the timestamp of this track point as milliseconds from the
			 * Java epoch of 1970-01-01T00:00:00Z, if known.
			 *
			 * @return The timestamp, may be null or zero.
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
