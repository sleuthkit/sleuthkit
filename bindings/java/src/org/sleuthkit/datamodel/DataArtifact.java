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


/**
 * DataArtifact is a category of artifact types that are simply data directly
 * extracted from a data source.
 *
 */
public final class DataArtifact extends BlackboardArtifact {
	
	private final OsAccount osAccount;
	
	
	DataArtifact(SleuthkitCase sleuthkitCase, long artifactID, long sourceObjId, long artifactObjId, long dataSourceObjId, int artifactTypeID, String artifactTypeName, String displayName, ReviewStatus reviewStatus, OsAccount osAccount) {
		super(sleuthkitCase, artifactID, sourceObjId, artifactObjId, dataSourceObjId, artifactTypeID, artifactTypeName, displayName, reviewStatus);
		this.osAccount = osAccount;
	}
	
	
	/**
	 * Gets the user for this artifact.
	 *
	 * @return OsAccount
	 *
	 * @throws TskCoreException If there is an error getting the user
	 */
	public OsAccount getOsAccount() throws TskCoreException {
		return osAccount;
	}
	
	
}
