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
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.sleuthkit.datamodel;

import com.google.common.collect.ImmutableSet;

/**
 * Event to indicate that aggregate score of objects has changed.
 */
final public class AggregateScoresChangedEvent implements TskDataSourceEvent, TskEvent {

	AggregateScoresChangedEvent(long dataSourceId, ImmutableSet<ScoreChange> scoreChanges) {
		this.dataSourceId = dataSourceId;
		this.scoreChanges = scoreChanges;
		
		// ensure that all score changes have the same data source as the one in the event.
		scoreChanges.stream()
				.forEach(chg -> {
					if (chg.getDataSourceObjectId() != dataSourceId) {
						throw new IllegalArgumentException("ScoreChange datasource id does not match the datasource id of the event.");
					}
				});
	}

	private final long dataSourceId;
	private final ImmutableSet<ScoreChange> scoreChanges;

	@Override
	public long getDataSourceId() {
		return dataSourceId;
	}

	public ImmutableSet<ScoreChange> getScoreChanges() {
		return scoreChanges;
	}

}
