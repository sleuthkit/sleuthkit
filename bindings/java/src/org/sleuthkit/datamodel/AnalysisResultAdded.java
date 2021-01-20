/**
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
 * This class encapsulates an analysis result added to Content, and the content's 
 * aggregate score upon adding the analysis result. 
 */
public class AnalysisResultAdded {
	
	private final AnalysisResult analysisResult;
	private final Score score;
	
	AnalysisResultAdded(AnalysisResult analysisResult, Score score) {
		this.analysisResult = analysisResult;
		this.score = score;
	}
	
	public AnalysisResult getAnalysisResult() {
		return analysisResult;
	}

	public Score getAggregateScore() {
		return score;
	}
	
}
