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

/**
 * This class encapsulates a score change.
 */
final public class ScoreChange {

	private final long objId;
	private final long dataSourceObjectId;
	private final Score oldScore;
	private final Score newScore;

	ScoreChange(long objId, long dataSourceObjectId, Score oldScore, Score newScore) {
		this.objId = objId;
		this.dataSourceObjectId = dataSourceObjectId;
		this.oldScore = oldScore;
		this.newScore = newScore;
	}

	public long getDataSourceObjectId() {
		return dataSourceObjectId;
	}

	public long getObjId() {
		return objId;
	}

	public Score getOldScore() {
		return oldScore;
	}

	public Score getNewScore() {
		return newScore;
	}
}
