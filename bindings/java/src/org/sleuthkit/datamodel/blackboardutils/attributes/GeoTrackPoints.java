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

import java.util.Collection;
import java.util.Collections;
import org.sleuthkit.datamodel.blackboardutils.attributes.GeoWaypoint.GeoTrackPoint;

/**
 * Helper class to make it easier to serialize and deserialize the list of track
 * points with Gson.
 *
 */
public final class GeoTrackPoints {

	private final Collection<GeoTrackPoint> points;

	/**
	 * Constructs a new instance with the give list of GeoTrackPoints.
	 *
	 * @param points
	 */
	public GeoTrackPoints(Collection<GeoTrackPoint> points) {
		if (points == null) {
			throw new IllegalArgumentException("Invalid list of track points passed to constructor");
		}
		this.points = points;
	}

	/**
	 * Return whether or not the points list is empty
	 *
	 * @return True if list is empty.
	 */
	public boolean isEmpty() {
		return points.isEmpty();
	}

	/**
	 * Returns the list of track points.
	 *
	 * @return Unmodifiable collection of trackpoints.
	 */
	public Collection<GeoTrackPoint> getPoints() {
		return Collections.unmodifiableCollection(points);
	}
}
