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
package org.sleuthkit.datamodel.blackboardutils;

import java.util.ArrayList;
import java.util.List;
import org.sleuthkit.datamodel.Blackboard.BlackboardException;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.blackboardutils.attributes.BlackboardJsonAttrUtil;
import org.sleuthkit.datamodel.blackboardutils.attributes.GeoWaypoints;
import org.sleuthkit.datamodel.blackboardutils.attributes.GeoTrackPoints;
import org.sleuthkit.datamodel.blackboardutils.attributes.GeoAreaPoints;

/**
 * An artifact creation helper that adds geolocation artifacts to the case
 * database.
 */
public final class GeoArtifactsHelper extends ArtifactHelperBase {

	private static final BlackboardAttribute.Type WAYPOINTS_ATTR_TYPE = new BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_GEO_WAYPOINTS);
	private static final BlackboardAttribute.Type TRACKPOINTS_ATTR_TYPE = new BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_GEO_TRACKPOINTS);
	private static final BlackboardAttribute.Type AREAPOINTS_ATTR_TYPE = new BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_GEO_AREAPOINTS);
	private final String programName;

	/**
	 * Constructs an artifact creation helper that adds geolocation artifacts to
	 * the case database.
	 *
	 * @param caseDb      The case database.
	 * @param moduleName  The name of the module creating the artifacts.
	 * @param programName The name of the user application associated with the
	 *                    geolocation data to be recorded as artifacts, may be
	 *                    null. If a program name is supplied, it will be added
	 *                    to each artifact that is created as a TSK_PROG_NAME
	 *                    attribute.
	 * @param srcContent  The source content for the artifacts, i.e., either a
	 *                    file within a data source or a data source.
	 */
	public GeoArtifactsHelper(SleuthkitCase caseDb, String moduleName, String programName, Content srcContent) {
		super(caseDb, moduleName, srcContent);
		this.programName = programName;
	}

	/**
	 * Adds a TSK_GPS_TRACK artifact to the case database. A Global Positioning
	 * System (GPS) track artifact records the track, or path, of a GPS-enabled
	 * device as a connected series of track points. A track point is a location
	 * in a geographic coordinate system with latitude, longitude and altitude
	 * (elevation) axes.
	 *
	 * @param trackName      The name of the GPS track, may be null.
	 * @param trackPoints    The track points that make up the track. This list
	 *                       should be non-null and non-empty.
	 * @param moreAttributes Additional attributes for the TSK_GPS_TRACK
	 *                       artifact, may be null.
	 *
	 * @return	The TSK_GPS_TRACK artifact that was added to the case database.
	 *
	 * @throws TskCoreException	        If there is an error creating the
	 *                                  artifact.
	 * @throws BlackboardException      If there is a error posting the artifact
	 *                                  to the blackboard.
	 * @throws IllegalArgumentException If the trackpoints provided are null or
	 *                                  empty.
	 */
	public BlackboardArtifact addTrack(String trackName, GeoTrackPoints trackPoints, List<BlackboardAttribute> moreAttributes) throws TskCoreException, BlackboardException {
		if (trackPoints == null || trackPoints.isEmpty()) {
			throw new IllegalArgumentException(String.format("addTrack was passed a null or empty list of track points"));
		}

		List<BlackboardAttribute> attributes = new ArrayList<>();

		if (trackName != null) {
			attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME, getModuleName(), trackName));
		}

		// acquire necessary attribute.  If 'toAttribute' call throws an exception, an artifact will not be created for this instance.
		attributes.add(BlackboardJsonAttrUtil.toAttribute(TRACKPOINTS_ATTR_TYPE, getModuleName(), trackPoints));

		if (programName != null) {
			attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME, getModuleName(), programName));
		}

		if (moreAttributes != null) {
			attributes.addAll(moreAttributes);
		}

		BlackboardArtifact artifact = getContent().newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_TRACK);
		artifact.addAttributes(attributes);

		getSleuthkitCase().getBlackboard().postArtifact(artifact, getModuleName());

		return artifact;
	}

	/**
	 * Adds a TSK_GPS_ROUTE artifact to the case database. A Global Positioning
	 * System (GPS) route artifact records one or more waypoints entered into a
	 * GPS-enabled device as a route to be navigated from waypoint to waypoint.
	 * A waypoint is a location in a geographic coordinate system with latitude,
	 * longitude and altitude (elevation) axes.
	 *
	 * @param routeName      The name of the GPS route, may be null.
	 * @param creationTime   The time at which the route was created as
	 *                       milliseconds from the Java epoch of
	 *                       1970-01-01T00:00:00Z, may be null.
	 * @param wayPoints      The waypoints that make up the route.  This list
	 *                       should be non-null and non-empty.
	 * @param moreAttributes Additional attributes for the TSK_GPS_ROUTE
	 *                       artifact, may be null.
	 *
	 * @return	The TSK_GPS_ROUTE artifact that was added to the case database.
	 *
	 * @throws TskCoreException	        If there is an error creating the
	 *                                  artifact.
	 * @throws BlackboardException      If there is a error posting the artifact
	 *                                  to the blackboard.
	 * @throws IllegalArgumentException If the waypoints provided are null or
	 *                                  empty.
	 */
	public BlackboardArtifact addRoute(String routeName, Long creationTime, GeoWaypoints wayPoints, List<BlackboardAttribute> moreAttributes) throws TskCoreException, BlackboardException {
		if (wayPoints == null || wayPoints.isEmpty()) {
			throw new IllegalArgumentException(String.format("addRoute was passed a null or empty list of waypoints"));
		}

		BlackboardArtifact artifact = getContent().newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_ROUTE);
		List<BlackboardAttribute> attributes = new ArrayList<>();

		attributes.add(BlackboardJsonAttrUtil.toAttribute(WAYPOINTS_ATTR_TYPE, getModuleName(), wayPoints));

		if (routeName != null) {
			attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME, getModuleName(), routeName));
		}

		if (creationTime != null) {
			attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME, getModuleName(), creationTime));
		}

		if (programName != null) {
			attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME, getModuleName(), programName));
		}

		if (moreAttributes != null) {
			attributes.addAll(moreAttributes);
		}

		artifact.addAttributes(attributes);

		getSleuthkitCase().getBlackboard().postArtifact(artifact, getModuleName());

		return artifact;
	}
	/**
	 * Adds a TSK_GPS_AREA artifact to the case database. A Global Positioning
	 * System (GPS) area artifact records an area on the map outlines by
	 * an ordered set of GPS coordinates.
	 *
	 * @param areaName       The name of the GPS area, may be null.
	 * @param areaPoints     The points that make up the outline of the area.  This list
	 *                       should be non-null and non-empty.
	 * @param moreAttributes Additional attributes for the TSK_GPS_AREA
	 *                       artifact, may be null.
	 *
	 * @return	The TSK_GPS_AREA artifact that was added to the case database.
	 *
	 * @throws TskCoreException	        If there is an error creating the
	 *                                  artifact.
	 * @throws BlackboardException      If there is a error posting the artifact
	 *                                  to the blackboard.
	 * @throws IllegalArgumentException If the area points provided are null or
	 *                                  empty.
	 */
	public BlackboardArtifact addArea(String areaName, GeoAreaPoints areaPoints, List<BlackboardAttribute> moreAttributes) throws TskCoreException, BlackboardException {
		if (areaPoints == null || areaPoints.isEmpty()) {
			throw new IllegalArgumentException(String.format("addArea was passed a null or empty list of points"));
		}
		
		BlackboardArtifact artifact = getContent().newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_AREA);
		List<BlackboardAttribute> attributes = new ArrayList<>();
		attributes.add(BlackboardJsonAttrUtil.toAttribute(AREAPOINTS_ATTR_TYPE, getModuleName(), areaPoints));

		if (areaName != null) {
			attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME, getModuleName(), areaName));
		}

		if (programName != null) {
			attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME, getModuleName(), programName));
		}

		if (moreAttributes != null) {
			attributes.addAll(moreAttributes);
		}

		artifact.addAttributes(attributes);

		getSleuthkitCase().getBlackboard().postArtifact(artifact, getModuleName());

		return artifact;
	}

}
