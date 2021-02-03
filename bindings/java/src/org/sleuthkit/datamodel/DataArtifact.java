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
package org.sleuthkit.datamodel;

import java.util.Optional;


/**
 * DataArtifact is a category of artifact types that are simply data directly
 * extracted from a data source.
 *
 */
public final class DataArtifact extends BlackboardArtifact {
	
	// data artifacts may have a OS Account associated with them.
	private final OsAccount osAccount;
	
	
	/**
	 *  Constructs a DataArtifact.
	 * 
	 * @param sleuthkitCase    The SleuthKit case (case database) that contains
	 *                         the artifact data.
	 * @param artifactID       The unique id for this artifact.
	 * @param sourceObjId      The unique id of the content with which this
	 *                         artifact is associated.
	 * @param artifactObjId    The object id of artifact, in tsk_objects.
	 * @param dataSourceObjId  Object ID of the datasource where the artifact
	 *                         was found.
	 * @param artifactTypeID   The type id of this artifact.
	 * @param artifactTypeName The type name of this artifact.
	 * @param displayName      The display name of this artifact.
	 * @param reviewStatus     The review status of this artifact.
	 * @param osAccount        OsAccount associated with this artifact, may be
	 *                         null.
	 */
	DataArtifact(SleuthkitCase sleuthkitCase, long artifactID, long sourceObjId, long artifactObjId, long dataSourceObjId, int artifactTypeID, String artifactTypeName, String displayName, ReviewStatus reviewStatus, OsAccount osAccount) {
		super(sleuthkitCase, artifactID, sourceObjId, artifactObjId, dataSourceObjId, artifactTypeID, artifactTypeName, displayName, reviewStatus);
		this.osAccount = osAccount;
	}
	
	
	/**
	 * Gets the OS Account for this artifact.
	 *
	 * @return Optional with OsAccount, Optional.empty if there is no account.
	 *
	 * @throws TskCoreException If there is an error getting the account.
	 */
	public Optional<OsAccount> getOsAccount() throws TskCoreException {
		return Optional.ofNullable(osAccount);
	}
	
	
}
