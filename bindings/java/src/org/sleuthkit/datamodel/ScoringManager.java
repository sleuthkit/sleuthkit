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

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.sleuthkit.datamodel.Score.Confidence;
import org.sleuthkit.datamodel.Score.Significance;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbConnection;

/**
 * The scoring manager is responsible for maintaining the score of the objects.
 *
 */
public class ScoringManager {

	private static final Logger LOGGER = Logger.getLogger(ScoringManager.class.getName());

	private final SleuthkitCase db;

	/**
	 * Construct a ScoringManager for the given SleuthkitCase.
	 *
	 * @param skCase The SleuthkitCase
	 *
	 */
	ScoringManager(SleuthkitCase skCase) {
		this.db = skCase;
	}

	/**
	 * Get the final score for the given object.
	 *
	 * @param obj_id Object id.
	 *
	 * @return Score, if it is found, unknown otherwise.
	 *
	 * @throws TskCoreException
	 */
	public Score getScore(long obj_id) throws TskCoreException {
		String queryString = "SELECT significance, confidence FROM tsk_final_score WHERE obj_id = " + obj_id;

		try (CaseDbConnection connection = db.getConnection()) {
			db.acquireSingleUserCaseReadLock();

			try (Statement s = connection.createStatement(); ResultSet rs = connection.executeQuery(s, queryString)) {
				if (rs.next()) {
					return new Score(Significance.fromID(rs.getInt("significance")), Confidence.fromID(rs.getInt("confidence")));
				} else {
					return new Score(Significance.UNKNOWN, Confidence.NONE);
				}
			} catch (SQLException ex) {
				throw new TskCoreException("SQLException thrown while running query: " + queryString, ex);
			}
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}


	
	/**
	 * Inserts pr updates the final score for the given object.
	 *
	 * @param obj_id Object id of the object.
	 * @param score  Final score to be inserted/updated.
	 *
	 * @throws TskCoreException
	 */
	void setScore(long obj_id, Score score) throws TskCoreException {

		String query = String.format(" INTO tsk_final_score (obj_id, significance , confidence) VALUES (%d, %d, %d)",
				obj_id, score.getSignificance().getId(), score.getConfidence().getId());

		switch (db.getDatabaseType()) {
			case POSTGRESQL:
				query = "INSERT " + query + " ON CONFLICT DO NOTHING"; //NON-NLS
				break;
			case SQLITE:
				query = "INSERT OR IGNORE " + query;
				break;
			default:
				throw new TskCoreException("Unknown DB Type: " + db.getDatabaseType().name());
		}

		try (CaseDbConnection connection = db.getConnection()) {
			db.acquireSingleUserCaseReadLock();

			try (Statement updateStatement = connection.createStatement()) {
				updateStatement.executeUpdate(query);
			} catch (SQLException ex) {
				throw new TskCoreException("Error updating  final score, query: " + query, ex);//NON-NLS
			}

		} finally {
			db.releaseSingleUserCaseReadLock();
		}

	}

	/**
	 * Recalculate and update the final score of the specified object.
	 *
	 * @param obj_id Object id.
	 *
	 * @return Final score of the object.
	 */
	Score recalculateScore(long obj_id) throws TskCoreException {

		// Get the current score 
		Score currentScore = getScore(obj_id);

		// Get all the analysis_results for this object, 
		List<AnalysisResult> analysisResults = db.getBlackboard().getAnalysisResultsWhere(" arts.obj_id = " + obj_id);

		// RAMAN TBD: what if there is no analysis result??
		if ( analysisResults.isEmpty() ) {
			LOGGER.log(Level.WARNING, String.format("No analysis results found for obj id = %d", obj_id)  );
			return new Score(Significance.UNKNOWN, Confidence.NONE);
		}
		
		// find the highest score
		Score newScore = analysisResults.stream()
				.map(result -> result.getScore())
				.max(Score.getScoreComparator())
				.get();

		// If the new score is diff from current score
		if (currentScore.getSignificance() == Significance.UNKNOWN
				|| Score.getScoreComparator().compare(newScore, currentScore) > 0) {

			setScore(obj_id, newScore);

			// fire an event
			db.fireTSKEvent(new ScoreChangedEvent(obj_id, newScore));

			return newScore;
		} else {
			// return te current score
			return currentScore;
		}
	}
	
	final public class ScoreChangedEvent {

		private final long obj_id;
		private final Score score;

		public ScoreChangedEvent(long obj_id, Score score) {
			this.obj_id = obj_id;
			this.score = score;
		}

		public long getObjId() {
			return obj_id;
		}

		public Score getScore() {
			return score;
		}
	}
}
