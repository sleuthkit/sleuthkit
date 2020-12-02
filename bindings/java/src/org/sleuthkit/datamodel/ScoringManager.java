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
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbTransaction;

/**
 * The scoring manager is responsible for updating and querying the score of
 * objects.
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
	public Score getFinalScore(long obj_id) throws TskCoreException {
		try (CaseDbConnection connection = db.getConnection()) {
			return getFinalScore(obj_id, connection);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get the final score for the given object. Uses the connection from the
	 * given transaction.
	 *
	 * @param obj_id      Object id.
	 * @param transaction Transaction that provides the connection to use.
	 *
	 * @return Score, if it is found, unknown otherwise.
	 *
	 * @throws TskCoreException
	 */
	Score getFinalScore(long obj_id, CaseDbTransaction transaction) throws TskCoreException {
		CaseDbConnection connection = transaction.getConnection();
		return getFinalScore(obj_id, connection);
	}

	/**
	 * Get the final score for the given object.
	 *
	 * @param obj_id Object id.
	 * @param connection Connection to use for the query.
	 *
	 * @return Score, if it is found, Score(UNKNOWN,NONE) otherwise.
	 *
	 * @throws TskCoreException
	 */
	private Score getFinalScore(long obj_id, CaseDbConnection connection) throws TskCoreException {
		String queryString = "SELECT significance, confidence FROM tsk_final_score WHERE obj_id = " + obj_id;

		try {
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
	void setFinalScore(long obj_id, Score score) throws TskCoreException {

		try (CaseDbConnection connection = db.getConnection()) {
			setFinalScore(obj_id, score, connection);
		} finally {
			// do nothing
		}
	}

	/**
	 * Inserts or updates the score for the given object.
	 *
	 * @param obj_id Object id of the object.
	 * @param score  Score to be inserted/updated.
	 * @param transaction Transaction to use for the update.
	 *
	 * @throws TskCoreException
	 */
	void setFinalScore(long obj_id, Score score, CaseDbTransaction transaction) throws TskCoreException {
		CaseDbConnection connection = transaction.getConnection();
		setFinalScore(obj_id, score, connection);
	}

	/**
	 * Inserts or updates the score for the given object.
	 *
	 * @param obj_id Object id of the object.
	 * @param score  Score to be inserted/updated.
	 * @param connection Connection to use for the update.
	 *
	 * @throws TskCoreException
	 */
	private void setFinalScore(long obj_id, Score score, CaseDbConnection connection) throws TskCoreException {

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

		try {
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
	public Score recalculateFinalScore(long obj_id) throws TskCoreException {

		CaseDbTransaction transaction = db.beginTransaction();
		try {
			Score score = recalculateFinalScore(obj_id, transaction);

			transaction.commit();
			return score;
		} catch (TskCoreException ex) {
			try {
				transaction.rollback();
			} catch (TskCoreException ex2) {
				LOGGER.log(Level.SEVERE, "Failed to rollback transaction after exception. "
						+ "Error invoking recalculateScore with obj_id: " + obj_id, ex2);
			}
			throw ex;
		}
	}

	/**
	 * Recalculates and update the final score of the specified object, based on
	 * the analysis results. The update is done as part of the given
	 * transaction.
	 *
	 * @param obj_id      Object id.
	 * @param transaction Transaction to use to update the score.
	 *
	 * @return Final score of the object.
	 */
	public Score recalculateFinalScore(long obj_id, CaseDbTransaction transaction) throws TskCoreException {

		// Get the current score 
		Score currentScore = getFinalScore(obj_id, transaction);

		// Get all the analysis_results for this object, 
		List<AnalysisResult> analysisResults = db.getBlackboard().getAnalysisResultsWhere(" arts.obj_id = " + obj_id, transaction.getConnection());
		if (analysisResults.isEmpty()) {
			LOGGER.log(Level.WARNING, String.format("No analysis results found for obj id = %d", obj_id));
			return new Score(Significance.UNKNOWN, Confidence.NONE);
		}

		// find the highest score
		Score newScore = analysisResults.stream()
				.map(result -> result.getScore())
				.max(Score.getScoreComparator())
				.get();

		// If the new score is diff from current score
		if ((currentScore.compareTo(new Score(Significance.UNKNOWN, Confidence.NONE)) == 0)
				|| (Score.getScoreComparator().compare(newScore, currentScore) != 0)) {

			setFinalScore(obj_id, newScore, transaction);

			// fire an event
			db.fireTSKEvent(new FinalScoreChangedEvent(obj_id, newScore));

			return newScore;
		} else {
			// return te current score
			return currentScore;
		}
	}

	/**
	 * Updates the score for the specified object, if the given analysis result
	 * score is higher than the score the object already has.
	 *
	 * @param obj_id      Object id.
	 * @param resultScore Score for newly added analysis result.
	 *
	 * @return Final score for the object.
	 *
	 * @throws TskCoreException
	 */
	Score updateFinalScore(long obj_id, Score resultScore) throws TskCoreException {
		CaseDbTransaction transaction = db.beginTransaction();
		try {
			Score score = updateFinalScore(obj_id, resultScore, transaction);

			transaction.commit();
			return score;
		} catch (TskCoreException ex) {
			try {
				transaction.rollback();
			} catch (TskCoreException ex2) {
				LOGGER.log(Level.SEVERE, "Failed to rollback transaction after exception. "
						+ "Error invoking updateScore with obj_id: " + obj_id, ex2);
			}
			throw ex;
		}
	}

	/**
	 * /**
	 * Updates the score for the specified object, if the given analysis result
	 * score is higher than the score the object already has.
	 *
	 * @param obj_id      Object id.
	 * @param resultScore Score for a newly added analysis result.
	 * @param transaction Transaction to use for the update.
	 *
	 * @return Final score for the object.
	 *
	 * @throws TskCoreException
	 */
	Score updateFinalScore(long obj_id, Score resultScore, CaseDbTransaction transaction) throws TskCoreException {

		// Get the current score 
		Score currentScore = getFinalScore(obj_id, transaction);

		// If the current score is Unknown or the new score is higher than the current score
		if ((currentScore.compareTo(new Score(Significance.UNKNOWN, Confidence.NONE)) == 0)
				|| (Score.getScoreComparator().compare(resultScore, currentScore) > 0)) {

			setFinalScore(obj_id, resultScore, transaction);

			// fire an event
			db.fireTSKEvent(new FinalScoreChangedEvent(obj_id, resultScore));
			return resultScore;
		} else {
			// return te current score
			return currentScore;
		}
	}

	/**
	 * Event fired to indicate that the score of an object has changed. 
	 */
	final public class FinalScoreChangedEvent {

		private final long obj_id;
		private final Score score;

		public FinalScoreChangedEvent(long obj_id, Score score) {
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
