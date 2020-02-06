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

import org.sleuthkit.datamodel.blackboardutils.attributes.GeoTrackPoints;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import org.sleuthkit.datamodel.Blackboard.BlackboardException;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.blackboardutils.attributes.GeoTrackPoints.GeoWaypoints;
import org.sleuthkit.datamodel.blackboardutils.attributes.GeoWaypoint;
import org.sleuthkit.datamodel.blackboardutils.attributes.GeoWaypoint.GeoTrackPoint;

/**
 * Class to help ingest modules create Geolocation artifacts.
 *
 */
public final class GeoArtifactsHelper extends ArtifactHelperBase {

	/**
	 * Constructs a geolocation artifact helper for the given source file.
	 *
	 * @param caseDb			  Sleuthkit case db.
	 * @param moduleName	Name of module using the helper.
	 * @param srcFile			 Source file being processed by the module.
	 */
	public GeoArtifactsHelper(SleuthkitCase caseDb, String moduleName, Content srcFile) {
		super(caseDb, moduleName, srcFile);
	}

	/**
	 * Add a Track from a GPS device to the database. A Track represents a
	 * series of points that the device has traveled on. This will create a
	 * TSK_GPS_TRACK artifact and add it to the case.
	 *
	 * @param trackName	Name of GPS track, not required. Pass in null if
	 *                  unknown.
	 * @param points	   List of GeoTrackPoints that the track traversed.
	 *                  Required.
	 *
	 * @return	TSK_GPS_TRACK artifact
	 *
	 * @throws TskCoreException		  If there is an error creating the artifact.
	 * @throws BlackboardException	If there is a problem posting the artifact
	 */
	public BlackboardArtifact addTrack(String trackName, List<GeoTrackPoint> points) throws TskCoreException, BlackboardException {
		if (points == null) {
			throw new IllegalArgumentException(String.format("List of GeoTrackPoints instance must be valid for track %s", trackName != null ? trackName : ""));
		}

		BlackboardArtifact artifact = getContent().newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_TRACK);
		if (trackName != null) {
			artifact.addAttribute(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME, getModuleName(), trackName));
		}

		artifact.addAttribute(
				new BlackboardAttribute(
						BlackboardAttribute.ATTRIBUTE_TYPE.TSK_GEO_TRACKPOINTS,
						getModuleName(),
						GeoTrackPoints.serializePoints(points)));

		getSleuthkitCase().getBlackboard().postArtifact(artifact, getModuleName());

		return artifact;
	}

	/**
	 * Add a Route from a GPS device to the database.
	 *
	 * @param name			      Name of the route, not required
	 * @param creationTime	Time the route was created
	 * @param location		   The final destination of the route, not required
	 * @param programName	 The name of the program creating this route, not
	 *                     required
	 * @param category		   String category of the route, not required
	 * @param points		     List of GeoWaypoints belonging to the route
	 *
	 * @return TSK_GPS_ROUTE artifact
	 *
	 * @throws TskCoreException		  If there is an error creating the artifact.
	 * @throws BlackboardException	If there is a problem posting the artifact.
	 */
	public BlackboardArtifact addRoute(String name, Long creationTime, String location, String programName, String category, List<GeoWaypoint> points) throws TskCoreException, BlackboardException {

		if (points == null) {
			throw new IllegalArgumentException(String.format("List of GeoWaypoints must be valid for route %s", name != null ? name : ""));
		}

		BlackboardArtifact artifact = getContent().newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_ROUTE);
		List<BlackboardAttribute> attributes = new ArrayList<>();

		attributes.add(new BlackboardAttribute(
				BlackboardAttribute.ATTRIBUTE_TYPE.TSK_GEO_WAYPOINTS,
				getModuleName(),
				GeoWaypoints.serializePoints(points)));

		if (name != null) {
			attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME, getModuleName(), name));
		}

		if (creationTime != null) {
			attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME, getModuleName(), creationTime));
		}

		if (location != null) {
			attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_LOCATION, getModuleName(), location));
		}

		if (programName != null) {
			attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME, getModuleName(), programName));
		}

		if (category != null) {
			attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_CATEGORY, getModuleName(), category));
		}

		artifact.addAttributes(attributes);

		getSleuthkitCase().getBlackboard().postArtifact(artifact, getModuleName());

		return artifact;
	}

	/**
	 * Add a Route with a start and end point from a GPS device to the database.
	 *
	 * @param name			        Name of the route, not required
	 * @param creationTime	  Time the route was created
	 * @param location		     The final destination of the route, not required
	 * @param programName	   The name of the program creating this route, not
	 *                       required
	 * @param category		     String category of the route, not required
	 * @param startLatitude	 Starting point latitude
	 * @param startLongitude Starting point longitude
	 * @param endLatitude	   End point latitude
	 * @param endLongitude	  End point longitude
	 *
	 * @return TSK_GPS_ROUTE
	 *
	 * @throws TskCoreException		  If there is an error creating the artifact.
	 * @throws BlackboardException	If there is a problem posting the artifact.
	 */
	public BlackboardArtifact addRoute(String name, Long creationTime, String location, String programName, String category, Double startLatitude, Double startLongitude, Double endLatitude, Double endLongitude) throws TskCoreException, BlackboardException {
		if (startLatitude == null || startLongitude == null) {
			throw new IllegalArgumentException(String.format("Start latitude & longitude must be valid for route %s", name != null ? name : ""));
		}

		if (endLatitude == null || endLongitude == null) {
			throw new IllegalArgumentException(String.format("End latitude & longitude must be valid for route %s", name != null ? name : ""));
		}

		List<GeoWaypoint> waypointList = new ArrayList<>();
		waypointList.add(new GeoWaypoint(startLatitude, startLongitude, null));
		waypointList.add(new GeoWaypoint(endLatitude, endLongitude, null));

		return addRoute(name, creationTime, location, programName, category, waypointList);
	}

	/**
	 * Adds a Track with a single point. A GPS track generally refers to several
	 * points that a device has traversed and addTrack() is more appropriate.
	 *
	 * @param latitude    Location latitude, required.
	 * @param longitude   Location longitude, required.
	 * @param timeStamp   Date/time trackpoint was recorded, can be 0 if not
	 *                    available.
	 * @param name        Trackpoint name, can be empty/null if not available.
	 * @param programName Name of program that recorded the trackpoint, can be
	 *                    empty or null if not available.
	 *
	 * @return GPS trackpoint artifact added
	 *
	 * @throws TskCoreException		  If there is an error creating the artifact.
	 * @throws BlackboardException	If there is a problem posting the artifact.
	 */
	public BlackboardArtifact addGPSTrackpoint(double latitude, double longitude,
			long timeStamp, String name, String programName) throws TskCoreException, BlackboardException {

		return addGPSTrackpoint(latitude, longitude, timeStamp, name, programName,
				Collections.emptyList());
	}

	/**
	 * Adds a TSK_GPS_TRACKPOINT artifact.
	 *
	 * @param latitude            Location latitude, required.
	 * @param longitude           Location longitude, required.
	 * @param timeStamp           Date/time the trackpoint was recorded, can be
	 *                            0 if not available.
	 * @param name                Trackpoint name, can be empty/null if not
	 *                            available.
	 * @param programName         Name of program that recorded the trackpoint,
	 *                            can be empty or null if not available.
	 * @param otherAttributesList Other attributes, can be an empty list of no
	 *                            additional attributes.
	 *
	 * @return GPS trackpoint artifact added
	 *
	 * @throws TskCoreException		  If there is an error creating the artifact.
	 * @throws BlackboardException	If there is a problem posting the artifact.
	 */
	public BlackboardArtifact addGPSTrackpoint(double latitude, double longitude, long timeStamp, String name, String programName,
			Collection<BlackboardAttribute> otherAttributesList) throws TskCoreException, BlackboardException {

		BlackboardArtifact gpsTrackpointArtifact;
		Collection<BlackboardAttribute> attributes = new ArrayList<>();

		// create artifact
		gpsTrackpointArtifact = getContent().newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_TRACKPOINT);

		// construct attributes 
		attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_GEO_LATITUDE, getModuleName(), latitude));
		attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_GEO_LONGITUDE, getModuleName(), longitude));

		addAttributeIfNotZero(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME, timeStamp, attributes);

		addAttributeIfNotNull(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME, name, attributes);
		addAttributeIfNotNull(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME, programName, attributes);

		// add the attributes 
		attributes.addAll(otherAttributesList);
		gpsTrackpointArtifact.addAttributes(attributes);

		// post artifact 
		getSleuthkitCase().getBlackboard().postArtifact(gpsTrackpointArtifact, getModuleName());

		// return the artifact
		return gpsTrackpointArtifact;
	}

}
