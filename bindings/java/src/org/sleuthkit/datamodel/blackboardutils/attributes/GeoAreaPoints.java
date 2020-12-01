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
 * A GeoAreaPoints object is a collection of AreaPoint objects.
 * Every AreaPoint is a location in a geographic coordinate
 * system with latitude and longitude axes.
 *
 * GeoWaypoints objects are designed to be used as the string value of the
 * TSK_GEO_AREAPOINTS attribute of a TSK_GPS_AREA artifact. TSK_GPS_AREA
 * artifacts are used to record a series of locations used to outline an
 * area on the map.
 */
public class GeoAreaPoints implements Iterable<GeoAreaPoints.AreaPoint> {

	private final List<AreaPoint> points;

	/**
	 * Constructs an empty GeoAreaPoints object.
	 */
	public GeoAreaPoints() {
		points = new ArrayList<>();
	}

	/**
	 * Adds an area point to this list of points outlining the area.
	 *
	 * @param areaPoint A point.
	 */
	public void addPoint(AreaPoint areaPoint) {
		if (areaPoint == null) {
			throw new IllegalArgumentException("addPoint was passed a null waypoint");
		}

		points.add(areaPoint);
	}

	/**
	 * Returns whether or not this list of area points is empty.
	 *
	 * @return True or false.
	 */
	public boolean isEmpty() {
		return points.isEmpty();
	}

	@Override
	public Iterator<AreaPoint> iterator() {
		return points.iterator();
	}

	/**
	 * A representation of an area point, which is a a location in
	 * a geographic coordinate system with latitude and longitude axes.
	 * Area points are used to mark the outline of an area on the map.
	 */
	public static class AreaPoint {

		@SerializedName("TSK_GEO_LATITUDE")
		private final Double latitude;
		@SerializedName("TSK_GEO_LONGITUDE")
		private final Double longitude;

		/**
		 * Constructs a representation of an area point.
		 *
		 * @param latitude  The latitude of the area point.
		 * @param longitude The longitude of the area point.
		 */
		public AreaPoint(Double latitude, Double longitude) {
			if (latitude == null) {
				throw new IllegalArgumentException("Constructor was passed null latitude");
			}

			if (longitude == null) {
				throw new IllegalArgumentException("Constructor was passed null longitude");
			}

			this.latitude = latitude;
			this.longitude = longitude;
		}

		/**
		 * Gets the latitude of this area point.
		 *
		 * @return The latitude.
		 */
		public Double getLatitude() {
			return latitude;
		}

		/**
		 * Gets the longitude of this area point.
		 *
		 * @return The longitude.
		 */
		public Double getLongitude() {
			return longitude;
		}
	}
}
