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
 * Class to help ingest modules create Geolocation artifacts.
 *
 */
public final class GeoArtifactsHelper extends ArtifactHelperBase {

	private final String programName;
	private final TskGeoTrackpointsUtil trackPointAttributeUtil;
	private final TskGeoWaypointsUtil waypointsAttributeUtil;

	/**
	 * Constructs a geolocation artifact helper for the given source file.
	 *
	 * @param caseDb		Sleuthkit case db.
	 * @param moduleName	Name of module using the helper.
	 * @param programName	Optional program name for TSK_PROG_NAME attribute, 
	 *						nulls and empty string will be ignored.
	 * @param srcFile		Source file being processed by the module.
	 */
	public GeoArtifactsHelper(SleuthkitCase caseDb, String moduleName, String programName, Content srcFile) {
		super(caseDb, moduleName, srcFile);
		this.programName = programName;
		trackPointAttributeUtil = new TskGeoTrackpointsUtil();
		waypointsAttributeUtil = new TskGeoWaypointsUtil();
	}

	/**
	 * Add a Track from a GPS device to the database. A Track represents a 
	 * series of points that the device has traveled on. This will create a 
	 * TSK_GPS_TRACK artifact and add it to the case.
	 *
	 * @param trackName			Name of GPS track, not required.
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
		
		if(points == null) {
			throw new IllegalArgumentException(String.format("GeoTrackPointList is required to be non-null"));
		}
		
		BlackboardArtifact artifact = getContent().newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_TRACK);
		List<BlackboardAttribute> attributes = new ArrayList<>();
		if (trackName != null) {
			attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME, getModuleName(), trackName));
		}

		attributes.add(trackPointAttributeUtil.toAttribute(getModuleName(), points));

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
	 * Add a Route from a GPS device to the database. This will create a 
	 * TSK_GPS_ROUTE artifact and add it to the case.
	 *
	 * @param routeName			Optional route name
	 * @param creationTime		Time the route was created, optional.
	 * @param points			List of GeoWaypointList belonging to the route, required
	 * @param moreAttributes	Optional list of other artifact attributes.
	 *
	 * @return TSK_GPS_ROUTE artifact
	 *
	 * @throws TskCoreException		If there is an error creating the artifact.
	 * @throws BlackboardException	If there is a problem posting the artifact.
	 */
	public BlackboardArtifact addRoute(String routeName, Long creationTime, GeoWaypointList points, List<BlackboardAttribute> moreAttributes) throws TskCoreException, BlackboardException {

		if (points == null) {
			throw new IllegalArgumentException(String.format("GeoWaypointList object be valid"));
		}

		BlackboardArtifact artifact = getContent().newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_ROUTE);
		List<BlackboardAttribute> attributes = new ArrayList<>();

		attributes.add(waypointsAttributeUtil.toAttribute(getModuleName(), points));
		
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
