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
import org.sleuthkit.datamodel.blackboardutils.attributes.GeoWaypointList.GeoWaypoint;

/**
 * Helper class to make it easier to serialize and deserialize the
 * TSK_GEO_TRACKPOINTS attribute.
 *
 */
public final class GeoTrackPointList {

	private final List<GeoTrackPoint> points;

	/**
	 * Deserialize the given list of GeoTrackPoints.
	 *
	 * @param jsonString JSon string of track points.
	 *
	 * @return	Timestamp ordered list of GeoTrackPoints, empty list will be
	 *         returned if jsonString is null or empty.
	 */
	public static GeoTrackPointList deserialize(String jsonString) {
		if (jsonString == null || jsonString.isEmpty()) {
			return null;
		}

		return (new Gson()).fromJson(jsonString, GeoTrackPointList.class);
	}
	
	/**
	 * Construct an empty GeoTrackPointList.
	 */
	public GeoTrackPointList() {
		points = new ArrayList<>();
	}
	
	/**
	 * Construct a new instance with the given list of GeoTrackPoint objects.
	 * 
	 * @param points List of track points, cannot be null.
	 */
	public GeoTrackPointList(List<GeoTrackPoint> points) {
		if(points == null) {
			throw new IllegalArgumentException("NULL list of trackpoints passed to constructor.");
		}
		
		this.points = points;
	}
	
	/**
	 * Add a point to the list of track points.
	 * 
	 * @param point A point to add to the track point list, cannot be null.
	 */
	public void addPoint(GeoTrackPoint point) {
		if(points == null) {
			throw new IllegalArgumentException("Attempted to add NULL value to track point list.");
		}
		
		points.add(point);
	}
	
	/**
	* Adds a new point with the given attributes.
	*
	* @param latitude			Latitude of the trackpoint, required
	* @param longitude			Longitude of the trackpoint, required
	* @param altitude			Altitude of the trackpoint, maybe null
	* @param name				Name of trackpoint, maybe null
	* @param velocity			Velocity in meters/sec, maybe null
	* @param distanceFromHP		Trackpoint distance from an established "home
	*							point", maybe null if not applicable
	* @param distanceTraveled	Overall distance traveled in meters at the
	*							time this trackpoint was created, maybe null
	*							if not applicable
	* @param timestamp			Trackpoint creation time, maybe null if not
	*							applicable
	*/
	public void addPoint(Double latitude,
				Double longitude,
				Double altitude,
				String name,
				Double velocity,
				Double distanceFromHP,
				Double distanceTraveled,
				Long timestamp) {
		points.add(new GeoTrackPoint(
						latitude, 
						longitude, 
						altitude, 
						name, 
						velocity, 
						distanceFromHP, 
						distanceTraveled, 
						timestamp));
	}
	
	/**
	 * Returns an iterator over the points in this GeoTrackPointList.
	 * 
	 * @return An iterator over the elements of the list.
	 */
	public Iterator<GeoTrackPoint> iterator() {
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
     * Return the start time for the track. 
     *
     * @return First non-null time stamp or null, if one was not found.
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
     * Return the ends time for the track.
     *
     * @return First non-null time stamp or null, if one was not found.
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
	 * Returns a timestamp ordered copy of the points list.
	 *
	 * @return List of points sorted by timestamps.
	 */
	private List<GeoTrackPoint> getTimeOrderedPoints() {
		return points.stream().sorted().collect(Collectors.toCollection(ArrayList::new));
	}

	/**
	 * A GeoTrackPoint is a Waypoint with more detailed information about the
	 * point.
	 *
	 */
	public final static class GeoTrackPoint extends GeoWaypoint implements Comparable<GeoTrackPoint> {

		@SerializedName("TSK_GEO_VELOCITY")
		private final Double velocity;
		private final Double distanceFromHP;
		private final Double distanceTraveled;
		@SerializedName("TSK_DATETIME")
		private final Long timestamp;

		/**
		 * Constructs a GeoTrackPoint with the given attributes.
		 *
		 * @param latitude			Latitude of the trackpoint, required
		 * @param longitude			Longitude of the trackpoint, required
		 * @param altitude			Altitude of the trackpoint, maybe null
		 * @param name				Name of trackpoint, maybe null
		 * @param velocity			Velocity in meters/sec, maybe null
		 * @param distanceFromHP	Trackpoint distance from an established "home
		 *							point", maybe null if not applicable
		 * @param distanceTraveled	Overall distance traveled in meters at the
		 *							time this trackpoint was created, maybe null
		 *							if not applicable
		 * @param timestamp			Trackpoint creation time, maybe null if not
		 *							applicable
		 */
		public GeoTrackPoint(Double latitude,
				Double longitude,
				Double altitude,
				String name,
				Double velocity,
				Double distanceFromHP,
				Double distanceTraveled,
				Long timestamp) {
			super(latitude, longitude, altitude, name);
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
