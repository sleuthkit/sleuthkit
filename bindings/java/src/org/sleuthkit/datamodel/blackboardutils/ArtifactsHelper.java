/*
 * Sleuth Kit Data Model
 *
 * Copyright 2019-2021 Basis Technology Corp.
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
import java.util.Optional;
import org.sleuthkit.datamodel.Blackboard.BlackboardException;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.sleuthkit.datamodel.TskCoreException;

/**
 * A class that helps modules to create various types of artifacts.
 */
public final class ArtifactsHelper extends ArtifactHelperBase {

	private static final BlackboardArtifact.Type INSTALLED_PROG_TYPE = new BlackboardArtifact.Type(ARTIFACT_TYPE.TSK_INSTALLED_PROG);

	/**
	 * Constructs an instance of a class that helps modules to create various
	 * types of artifacts.
	 *
	 * @param caseDb      The case database.
	 * @param moduleName  The name of the module creating the artifacts.
	 * @param srcContent  The source/parent content of the artifacts.
	 * @param ingestJobId The numeric identifier of the ingest job within which
	 *                    the artifacts are being created, may be null.
	 */
	public ArtifactsHelper(SleuthkitCase caseDb, String moduleName, Content srcContent, Long ingestJobId) {
		super(caseDb, moduleName, srcContent, ingestJobId);
	}

	/**
	 * Constructs an instance of a class that helps modules to create various
	 * types of artifacts.
	 *
	 * @param caseDb     The case database.
	 * @param moduleName The name of the module creating the artifacts.
	 * @param srcContent The source/parent content of the artifacts.
	 *
	 * @deprecated Use ArtifactsHelper(SleuthkitCase caseDb, String moduleName,
	 * Content srcContent, Long ingestJobId) instead.
	 */
	@Deprecated
	public ArtifactsHelper(SleuthkitCase caseDb, String moduleName, Content srcContent) {
		this(caseDb, moduleName, srcContent, null);
	}

	/**
	 * Adds a TSK_INSTALLED_PROGRAM artifact.
	 *
	 * @param programName   Name of program, required.
	 * @param dateInstalled Date/time of install, can be 0 if not available.
	 *
	 * @return Installed program artifact added.
	 *
	 * @throws TskCoreException		  If there is an error creating the artifact.
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
	 * @throws TskCoreException		  If there is an error creating the artifact.
	 * @throws BlackboardException	If there is a problem posting the artifact.
	 */
	public BlackboardArtifact addInstalledProgram(String programName, long dateInstalled,
			Collection<BlackboardAttribute> otherAttributesList) throws TskCoreException, BlackboardException {

		Collection<BlackboardAttribute> attributes = new ArrayList<>();

		// construct attributes 
		attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME, getModuleName(), programName));
		addAttributeIfNotZero(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME, dateInstalled, attributes);

		// add the attributes 
		attributes.addAll(otherAttributesList);

		// create artifact
		Content content = getContent();
		BlackboardArtifact installedProgramArtifact = content.newDataArtifact(INSTALLED_PROG_TYPE, attributes);

		// post artifact 
		Optional<Long> ingestJobId = getIngestJobId();
		getSleuthkitCase().getBlackboard().postArtifact(installedProgramArtifact, getModuleName(), ingestJobId.orElse(null));

		// return the artifact
		return installedProgramArtifact;
	}

}
