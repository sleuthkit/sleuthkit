/*
 * Sleuth Kit Data Model
 *
 * Copyright 2011-2020 Basis Technology Corp.
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
 * Analysis result is a category of artifact types that represent the outcome of
 * some analysis technique applied to extracted data.
 *
 *
 */
public class AnalysisResult extends BlackboardArtifact {

	private final String conclusion;	// conclusion of analysis - may be empty
	private final Score score;			// score from the analysis
	private final String configuration; // name of a configuration file/element that guides this analysis, may be empty.
	private final String justificaion;  // justification/explanation from the analysis, may be empty.

	private boolean ignore_result = false;

	public AnalysisResult(Score score, String conclusion, String configuration, String justificaion, SleuthkitCase sleuthkitCase, long artifactID, long sourceObjId, long artifactObjId, long dataSourceObjId, int artifactTypeID, String artifactTypeName, String displayName, ReviewStatus reviewStatus) {
		super(sleuthkitCase, artifactID, sourceObjId, artifactObjId, dataSourceObjId, artifactTypeID, artifactTypeName, displayName, reviewStatus);
		this.score = score;
		this.conclusion = conclusion;
		this.configuration = configuration;
		this.justificaion = justificaion;
	}

	public AnalysisResult(Score score, String conclusion, String configuration, String justificaion, SleuthkitCase sleuthkitCase, long artifactID, long sourceObjId, long artifactObjID, long dataSourceObjID, int artifactTypeID, String artifactTypeName, String displayName, ReviewStatus reviewStatus, boolean isNew) {
		super(sleuthkitCase, artifactID, sourceObjId, artifactObjID, dataSourceObjID, artifactTypeID, artifactTypeName, displayName, reviewStatus, isNew);
		this.score = score;
		this.conclusion = conclusion;
		this.configuration = configuration;
		this.justificaion = justificaion;
	}

	public String getConclusion() {
		return conclusion;
	}

	public Score getScore() {
		return score;
	}

	public String getConfiguration() {
		return configuration;
	}

	public String getJustificaion() {
		return justificaion;
	}

	public void ignoreResult(boolean ignore) {
		ignore_result = ignore;
	}

	public boolean isIgnored() {
		return ignore_result;
	}

}
