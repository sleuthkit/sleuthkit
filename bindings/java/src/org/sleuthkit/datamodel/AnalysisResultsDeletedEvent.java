/*
 * Sleuth Kit Data Model
 *
 * Copyright 2021 Basis Technology Corp.
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
package org.sleuthkit.datamodel;

import java.util.Collections;
import java.util.List;

/**
 * Event to indicate that analysis results were deleted.
 */
public class AnalysisResultsDeletedEvent implements TskEvent {

	private final List<AnalysisResult> deletedResults;

	/**
	 * Constructs a new AnalysisResultsDeletedEvent.
	 *
	 * @param deletedResults List of deleted results.
	 */
	AnalysisResultsDeletedEvent(List<AnalysisResult> deletedResults) {
		this.deletedResults = deletedResults;
	}

	/**
	 * Returns a list of deleted results.
	 *
	 * @return List of AnalysisResult.
	 */
	public List<AnalysisResult> getDeletedAnalysisResult() {
		return Collections.unmodifiableList(deletedResults);
	}

}
