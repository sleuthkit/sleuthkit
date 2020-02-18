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
import org.sleuthkit.datamodel.blackboardutils.attributes.GeoTrackPointList;
import java.util.List;
import org.sleuthkit.datamodel.Blackboard.BlackboardException;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.blackboardutils.attributes.GeoWaypointList;

/**
 * Class to help ingest modules create Geolocation artifacts.
 *
 */
public final class GeoArtifactsHelper extends ArtifactHelperBase {

	private final String programName;

	/**
	 * Constructs a geolocation artifact helper for the given source file.
	 *
	 * @param caseDb		Sleuthkit case db.
	 * @param moduleName	Name of module using the helper.
	 * @param programName
	 * @param srcFile		Source file being processed by the module.
	 */
	public GeoArtifactsHelper(SleuthkitCase caseDb, String moduleName, String programName, Content srcFile) {
		super(caseDb, moduleName, srcFile);
		this.programName = programName;
	}

	/**
	 * Add a Track from a GPS device to the database. A Track represents a
	 * series of points that the device has traveled on. This will create a
	 * TSK_GPS_TRACK artifact and add it to the case.
	 *
	 * @param trackName			Name of GPS track, not required. Pass in null if
	 *							unknown.
	 * @param points			List of GeoTrackPoints that the track traversed.
	 *							Required.
	 * @param moreAttributes	Optional list of other artifact attributes
	 *
	 * @return	TSK_GPS_TRACK artifact
	 *
	 * @throws TskCoreException		If there is an error creating the artifact.
	 * @throws BlackboardException	If there is a problem posting the artifact
	 */
	public BlackboardArtifact addTrack(String trackName, GeoTrackPointList points, List<BlackboardAttribute> moreAttributes) throws TskCoreException, BlackboardException {
		if (points == null) {
			throw new IllegalArgumentException(String.format("List of GeoTrackPoints instance must be valid for track %s", trackName != null ? trackName : ""));
		}

		BlackboardArtifact artifact = getContent().newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_TRACK);
		List<BlackboardAttribute> attributes = new ArrayList<>();
		if (trackName != null) {
			attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME, getModuleName(), trackName));
		}

		attributes.add(
				new BlackboardAttribute(
						BlackboardAttribute.ATTRIBUTE_TYPE.TSK_GEO_TRACKPOINTS,
						getModuleName(),
						points.serialize()));

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
	 * Add a Route from a GPS device to the database.
	 *
	 * @param routeName
	 * @param creationTime		Time the route was created
	 * @param points			List of GeoWaypointList belonging to the route
	 * @param moreAttributes	Optional list of other artifact attributes
	 *
	 * @return TSK_GPS_ROUTE artifact
	 *
	 * @throws TskCoreException		If there is an error creating the artifact.
	 * @throws BlackboardException	If there is a problem posting the artifact.
	 */
	public BlackboardArtifact addRoute(String routeName, Long creationTime, GeoWaypointList points, List<BlackboardAttribute> moreAttributes) throws TskCoreException, BlackboardException {

		if (points == null) {
			throw new IllegalArgumentException(String.format("List of GeoWaypoints must be valid for route"));
		}

		BlackboardArtifact artifact = getContent().newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_ROUTE);
		List<BlackboardAttribute> attributes = new ArrayList<>();

		attributes.add(new BlackboardAttribute(
				BlackboardAttribute.ATTRIBUTE_TYPE.TSK_GEO_WAYPOINTS,
				getModuleName(),
				points.serialize()));
		
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
