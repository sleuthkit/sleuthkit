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

import com.google.gson.Gson;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.Blackboard.BlackboardException;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.sleuthkit.datamodel.TskCoreException;

/**
 * Class to help ingest modules create Geolocation artifacts. Helper supported
 * artifacts include: TSK_GPS_TRACK.
 *
 */
public final class GeoArtifactHelper extends ArtifactHelperBase {

	/**
	 * Constructs a geolocation artifact helper for the given source file.
	 *
	 * @param caseDb			  Sleuthkit case db.
	 * @param moduleName	Name of module using the helper.
	 * @param srcFile			 Source file being processed by the module.
	 */
	public GeoArtifactHelper(SleuthkitCase caseDb, String moduleName, AbstractFile srcFile) {
		super(caseDb, moduleName, srcFile);
	}

	/**
	 * Creates and adds a TSK_GPS_TRACK artifact to the case with specified
	 * attributes and posts the artifact to the Blackboard.
	 *
	 * @param trackName	Name of GPS track, not required
	 * @param points		  GeoTrackPoints, required.
	 *
	 * @return	TSK_GPS_TRACK artifact
	 *
	 * @throws TskCoreException		  If there is an error creating the artifact.
	 * @throws BlackboardException	If there is a problem posting the artifact
	 */
	public BlackboardArtifact addTrack(String trackName, GeoTrackPoints points) throws TskCoreException, BlackboardException {
		if (points == null) {
			throw new IllegalArgumentException("GeoTrackPoint instance must be valid");
		}

		BlackboardArtifact artifact = getAbstractFile().newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_TRACK);
		if (trackName != null) {
			artifact.addAttribute(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME, getModuleName(), trackName));
		}

		addPathToArtifact(artifact, points);

		getSleuthkitCase().getBlackboard().postArtifact(artifact, getModuleName());

		return artifact;
	}

	/**
	 * Creates the json for GeoTrackPoints and adds as attribute to the given
	 * artifact.
	 *
	 * @param artifact
	 * @param points
	 *
	 * @throws TskCoreException
	 */
	private void addPathToArtifact(BlackboardArtifact artifact, GeoTrackPoints points) throws TskCoreException {
		Gson gson = new Gson();
		String jsonString = gson.toJson(points);

		artifact.addAttribute(
				new BlackboardAttribute(
						BlackboardAttribute.ATTRIBUTE_TYPE.TSK_GEO_TRACKPOINTS,
						getModuleName(),
						jsonString));
	}
}
