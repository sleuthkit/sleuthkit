/*
 * Sleuth Kit Data Model
 *
 * Copyright 2019 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.datamodel.blackboardutils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import org.sleuthkit.datamodel.Blackboard.BlackboardException;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.sleuthkit.datamodel.TskCoreException;

/**
 * This class helps ingest modules create miscellaneous artifacts.
 *
 */
public final class ArtifactsHelper extends ArtifactHelperBase {

	/**
	 * Creates an artifact helper for modules to create artifacts.
	 *
	 * @param caseDb     Sleuthkit case database.
	 * @param moduleName Name of module using the helper.
	 * @param srcContent Source content for the artifacts.
	 *
	 */
	public ArtifactsHelper(SleuthkitCase caseDb, String moduleName, Content srcContent) {
		super(caseDb, moduleName, srcContent);
	}

	/**
	 * Adds a TSK_INSTALLED_PROGRAM artifact.
	 *
	 * @param programName   Name of program, required.
	 * @param dateInstalled Date/time of install, can be 0 if not available.
	 *
	 * @return Installed program artifact added.
	 *
	 * @throws TskCoreException		If there is an error creating the artifact.
	 * @throws BlackboardException	If there is a problem posting the artifact.
	 */
	public BlackboardArtifact addInstalledProgram(String programName, long dateInstalled) throws TskCoreException, BlackboardException {
		return addInstalledProgram(programName, dateInstalled,
				Collections.emptyList());
	}

	/**
	 * Adds a TSK_INSTALLED_PROGRAM artifact.
	 *
	 * @param programName         Name of program, required.
	 * @param dateInstalled       Date/time of install, can be 0 if not
	 *                            available.
	 * @param otherAttributesList Additional attributes, can be an empty list if
	 *                            no additional attributes.
	 *
	 * @return Installed program artifact added.
	 *
	 * @throws TskCoreException		If there is an error creating the artifact.
	 * @throws BlackboardException	If there is a problem posting the artifact.
	 */
	public BlackboardArtifact addInstalledProgram(String programName, long dateInstalled,
			Collection<BlackboardAttribute> otherAttributesList) throws TskCoreException, BlackboardException {

		BlackboardArtifact installedProgramArtifact;
		Collection<BlackboardAttribute> attributes = new ArrayList<>();

		// create artifact
		installedProgramArtifact = getContent().newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INSTALLED_PROG);

		// construct attributes 
		attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME, getModuleName(), programName));
		addAttributeIfNotZero(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME, dateInstalled, attributes);

		// add the attributes 
		attributes.addAll(otherAttributesList);
		installedProgramArtifact.addAttributes(attributes);

		// post artifact 
		getSleuthkitCase().getBlackboard().postArtifact(installedProgramArtifact, getModuleName());

		// return the artifact
		return installedProgramArtifact;
	}

}
