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
import org.sleuthkit.datamodel.blackboardutils.attributes.TskGeoTrackpointsUtil.GeoTrackPointList;
import java.util.List;
import org.sleuthkit.datamodel.Blackboard.BlackboardException;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.blackboardutils.attributes.TskGeoWaypointsUtil.GeoWaypointList;
import org.sleuthkit.datamodel.blackboardutils.attributes.TskGeoTrackpointsUtil;
import org.sleuthkit.datamodel.blackboardutils.attributes.TskGeoWaypointsUtil;

/**
 * An artifact creation helper that adds geolocation artifacts to the case
 * database.
 */
public final class GeoArtifactsHelper extends ArtifactHelperBase {

	private final String programName;
	private final TskGeoTrackpointsUtil trackPointAttributeUtil;
	private final TskGeoWaypointsUtil waypointsAttributeUtil;

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
		trackPointAttributeUtil = new TskGeoTrackpointsUtil();
		waypointsAttributeUtil = new TskGeoWaypointsUtil();
	}

	/**
	 * Adds a TSK_GPS_TRACK artifact to the case database. A Global Positioning
	 * System (GPS) track artifact records the track, or path, of a GPS-enabled
	 * device as a connected series of track points. A track point is a location
	 * in a geographic coordinate system with latitude, longitude and altitude
	 * (elevation) axes.
	 *
	 * @param trackName      The name of the GPS track, may be null.
	 * @param trackPoints    The track points that make up the track.
	 * @param moreAttributes Additional attributes for the TSK_GPS_TRACK
	 *                       artifact, may be null.
	 *
	 * @return	The TSK_GPS_TRACK artifact that was added to the case database.
	 *
	 * @throws TskCoreException	   If there is an error creating the artifact.
	 * @throws BlackboardException If there is a error posting the artifact to
	 *                             the blackboard.
	 */
	public BlackboardArtifact addTrack(String trackName, GeoTrackPointList trackPoints, List<BlackboardAttribute> moreAttributes) throws TskCoreException, BlackboardException {
		if (trackPoints == null) {
			throw new IllegalArgumentException(String.format("addTrack was passed a null list of track points"));
		}

		BlackboardArtifact artifact = getContent().newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_TRACK);
		List<BlackboardAttribute> attributes = new ArrayList<>();

		if (trackName != null) {
			attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME, getModuleName(), trackName));
		}

		attributes.add(trackPointAttributeUtil.toAttribute(getModuleName(), trackPoints));

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
	 * @param wayPoints      The waypoints that make up the route.
	 * @param moreAttributes Additional attributes for the TSK_GPS_ROUTE
	 *                       artifact, may be null.
	 *
	 * @return	The TSK_GPS_ROUTE artifact that was added to the case database.
	 *
	 * @throws TskCoreException	   If there is an error creating the artifact.
	 * @throws BlackboardException If there is a error posting the artifact to
	 *                             the blackboard.
	 */
	public BlackboardArtifact addRoute(String routeName, Long creationTime, GeoWaypointList wayPoints, List<BlackboardAttribute> moreAttributes) throws TskCoreException, BlackboardException {
		if (wayPoints == null) {
			throw new IllegalArgumentException(String.format("addRoute was passed a null list of waypoints"));
		}

		BlackboardArtifact artifact = getContent().newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_ROUTE);
		List<BlackboardAttribute> attributes = new ArrayList<>();

		attributes.add(waypointsAttributeUtil.toAttribute(getModuleName(), wayPoints));

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
}
