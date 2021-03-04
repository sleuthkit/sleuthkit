/*
 * Sleuth Kit Data Model
 *
 * Copyright 2020-2021 Basis Technology Corp.
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
 */
public class AnalysisResult extends BlackboardArtifact {

	private final String conclusion;	// conclusion of analysis - may be an empty string
	private final Score score;			// score from the analysis
	private final String configuration; // name of a configuration file/element that guides this analysis, may be an empty string.
	private final String justification;  // justification/explanation from the analysis, may be an empty string.

	private boolean ignoreResult = false; // ignore this analysis result when computing score of the parent object.

	/**
	 * Constructs an analysis result. 
	 *
	 * @param sleuthkitCase    The SleuthKit case (case database) that contains
	 *                         the artifact data.
	 * @param artifactID       The unique id for this artifact.
	 * @param sourceObjId      The unique id of the content with which this
	 *                         artifact is associated.
	 * @param artifactObjId    The unique id this artifact, in tsk_objects.
	 * @param dataSourceObjId  Object ID of the datasource where the artifact
	 *                         was found. May be null.
	 * @param artifactTypeID   The type id of this artifact.
	 * @param artifactTypeName The type name of this artifact.
	 * @param displayName      The display name of this artifact.
	 * @param reviewStatus     The review status of this artifact.
	 * @param score            The score assigned by the analysis.
	 * @param conclusion       Conclusion arrived at by the analysis. May be
	 *                         null.
	 * @param configuration    Configuration used for analysis. May be null.
	 * @param justification	   Justification for the analysis. May be null.
	 */
	AnalysisResult( SleuthkitCase sleuthkitCase, long artifactID, long sourceObjId, long artifactObjId, Long dataSourceObjId, int artifactTypeID, String artifactTypeName, String displayName, ReviewStatus reviewStatus, Score score, String conclusion, String configuration, String justification) {
		super(sleuthkitCase, artifactID, sourceObjId, artifactObjId, dataSourceObjId, artifactTypeID, artifactTypeName, displayName, reviewStatus);
		this.score = score;
		this.conclusion = (conclusion != null) ? conclusion : "";
		this.configuration = (configuration != null) ? configuration : "";
		this.justification = (justification != null) ? justification : "";
	}

	
	/**
	 * Constructs an analysis result. 
	 *
	 * @param sleuthkitCase    The SleuthKit case (case database) that contains
	 *                         the artifact data.
	 * @param artifactID       The unique id for this artifact.
	 * @param sourceObjId      The unique id of the content with which this
	 *                         artifact is associated.
	 * @param artifactObjId    The unique id this artifact, in tsk_objects.
	 * @param dataSourceObjId  Object ID of the datasource where the artifact
	 *                         was found. May be null.
	 * @param artifactTypeID   The type id of this artifact.
	 * @param artifactTypeName The type name of this artifact.
	 * @param displayName      The display name of this artifact.
	 * @param reviewStatus     The review status of this artifact.
	 * @param isNew            If this analysis result is newly created.
	 * @param score            The score assigned by the analysis.
	 * @param conclusion       Conclusion arrived at by the analysis. May be
	 *                         null.
	 * @param configuration    Configuration used for analysis. May be null.
	 * @param justification	   Justification for the analysis. May be null.
	 */
	
	AnalysisResult(SleuthkitCase sleuthkitCase, long artifactID, long sourceObjId, long artifactObjID, Long dataSourceObjID, int artifactTypeID, String artifactTypeName, String displayName, ReviewStatus reviewStatus, boolean isNew, Score score, String conclusion, String configuration, String justification) {
		super(sleuthkitCase, artifactID, sourceObjId, artifactObjID, dataSourceObjID, artifactTypeID, artifactTypeName, displayName, reviewStatus, isNew);
		this.score = score;
		this.conclusion = (conclusion != null) ? conclusion : "";
		this.configuration = (configuration != null) ? configuration : "";
		this.justification = (justification != null) ? justification : "";
	}

	/**
	 * Returns analysis result conclusion.
	 *
	 * @return Conclusion, returns an empty string if not set.
	 */
	public String getConclusion() {
		return conclusion;
	}

	/**
	 * Returns analysis result score.
	 *
	 * @return Score.
	 */
	public Score getScore() {
		return score;
	}

	/**
	 * Returns configuration used in analysis.
	 *
	 * @return Configuration, returns an empty string if not set.
	 */
	public String getConfiguration() {
		return configuration;
	}

	/**
	 * Returns analysis justification.
	 *
	 * @return justification, returns an empty string if not set.
	 */
	public String getJustification() {
		return justification;
	}

	/**
	 * Sets if this result is to be ignored.
	 *
	 * @param ignore if the result should be ignored or not.
	 */
	public void setIgnoreResult(boolean ignore) {
		ignoreResult = ignore;
	}

	/**
	 * Checks if this result is to be ignored.
	 *
	 * @return true is the result should should be ignored, false otherwise.
	 */
	public boolean ignoreResult() {
		return ignoreResult;
	}

}
