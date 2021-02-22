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
 * An AnalysisResult represents the outcome of some analysis technique
 * that was applied to some data (i.e. Content) to determine the data's
 * relevance.  The result should have a conclusion and a relevance 
 * score. The score of the AnalysisResult will be used to calculate
 * the final score of the parent data.  Additional metadata can be
 * stored as BlackboardAttributes.
 *
 */
public class AnalysisResult extends BlackboardArtifact {

	private final String conclusion;	// conclusion of analysis - may be an empty string
	private final Score score;			// relevance score based on the conclusion 
	private final String configuration; // Optional descriptor of configuration of analysis technique (such as a set name). Maybe empty string
	private final String justification;  // justification/explanation of the conclusion.  Maybe empty string.

	private boolean ignoreResult = false; // ignore this analysis result when computing score of the parent object.

	AnalysisResult( SleuthkitCase sleuthkitCase, long artifactID, long sourceObjId, long artifactObjId, long dataSourceObjId, int artifactTypeID, String artifactTypeName, String displayName, ReviewStatus reviewStatus, Score score, String conclusion, String configuration, String justification) {
		super(sleuthkitCase, artifactID, sourceObjId, artifactObjId, dataSourceObjId, artifactTypeID, artifactTypeName, displayName, reviewStatus);
		this.score = score;
		this.conclusion = (conclusion != null) ? conclusion : "";
		this.configuration = (configuration != null) ? configuration : "";
		this.justification = (justification != null) ? justification : "";
	}

	AnalysisResult(SleuthkitCase sleuthkitCase, long artifactID, long sourceObjId, long artifactObjID, long dataSourceObjID, int artifactTypeID, String artifactTypeName, String displayName, ReviewStatus reviewStatus, boolean isNew, Score score, String conclusion, String configuration, String justification) {
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
	 * Returns relevance score based on conclusion
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
	 * Returns justification for conclusion
	 *
	 * @return justification, returns an empty string if not set.
	 */
	public String getJustification() {
		return justification;
	}

	/**
	 * Sets if this result is to be ignored when calculating
     * the final score of the parent object. 
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
