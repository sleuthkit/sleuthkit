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
	 * Get the aggregate score for the given object.
	 *
	 * @param objId Object id.
	 *
	 * @return Score, if it is found, unknown otherwise.
	 *
	 * @throws TskCoreException
	 */
	public Score getAggregateScore(long objId) throws TskCoreException {
		try (CaseDbConnection connection = db.getConnection()) {
			return getAggregateScore(objId, connection);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get the aggregate score for the given object. Uses the connection from the
	 * given transaction.
	 *
	 * @param objId      Object id.
	 * @param transaction Transaction that provides the connection to use.
	 *
	 * @return Score, if it is found, unknown otherwise.
	 *
	 * @throws TskCoreException
	 */
	private Score getAggregateScore(long objId, CaseDbTransaction transaction) throws TskCoreException {
		CaseDbConnection connection = transaction.getConnection();
		return getAggregateScore(objId, connection);
	}

	/**
	 * Get the aggregate score for the given object.
	 *
	 * @param objId Object id.
	 * @param connection Connection to use for the query.
	 *
	 * @return Score, if it is found, Score(UNKNOWN,NONE) otherwise.
	 *
	 * @throws TskCoreException
	 */
	private Score getAggregateScore(long objId, CaseDbConnection connection) throws TskCoreException {
		String queryString = "SELECT significance, confidence FROM tsk_aggregate_score WHERE obj_id = " + objId;

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
	 * Inserts or updates the score for the given object.
	 *
	 * @param objId Object id of the object.
	 * @param score  Score to be inserted/updated.
	 * @param transaction Transaction to use for the update.
	 *
	 * @throws TskCoreException
	 */
	private void setAggregateScore(long objId, Score score, CaseDbTransaction transaction) throws TskCoreException {
		CaseDbConnection connection = transaction.getConnection();
		setAggregateScore(objId, score, connection);
	}

	/**
	 * Inserts or updates the score for the given object.
	 *
	 * @param objId Object id of the object.
	 * @param score  Score to be inserted/updated.
	 * @param connection Connection to use for the update.
	 *
	 * @throws TskCoreException
	 */
	private void setAggregateScore(long objId, Score score, CaseDbConnection connection) throws TskCoreException {

		String query = String.format(" INTO tsk_aggregate_score (obj_id, significance , confidence) VALUES (%d, %d, %d)",
				objId, score.getSignificance().getId(), score.getConfidence().getId());

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
	 * @param objId Object id.
	 *
	 * @return Final score of the object.
	 */
	public Score recalculateAggregateScore(long objId) throws TskCoreException {

		CaseDbTransaction transaction = db.beginTransaction();
		try {
			// Get the current score 
			Score currentScore = ScoringManager.this.getAggregateScore(objId, transaction);

			// Get all the analysis_results for this object, 
			List<AnalysisResult> analysisResults = db.getBlackboard().getAnalysisResultsWhere(" arts.obj_id = " + objId, transaction.getConnection());
			if (analysisResults.isEmpty()) {
				LOGGER.log(Level.WARNING, String.format("No analysis results found for obj id = %d", objId));
				return new Score(Significance.UNKNOWN, Confidence.NONE);
			}

			// find the highest score
			Score newScore = analysisResults.stream()
					.map(result -> result.getScore())
					.max(Score.getScoreComparator())
					.get();

			// If the new score is diff from current score
			if  (Score.getScoreComparator().compare(newScore, currentScore) != 0) {
				ScoringManager.this.setAggregateScore(objId, newScore, transaction);

				// register score change in the transaction.
				long dataSourceObjectId = analysisResults.get(0).getDataSourceObjectID();
				transaction.registerScoreChange(new ScoreChange(objId, dataSourceObjectId, currentScore, newScore));

				return newScore;
			} else {
				// return the current score
				return currentScore;
			}

		} catch (TskCoreException ex) {
			try {
				transaction.rollback();
			} catch (TskCoreException ex2) {
				LOGGER.log(Level.SEVERE, "Failed to rollback transaction after exception. "
						+ "Error invoking recalculateScore with objId: " + objId, ex2);
			}
			throw ex;
		}
	}

	/**
	 * /**
	 * Updates the score for the specified object, if the given analysis result
	 * score is higher than the score the object already has.
	 *
	 * @param objId      Object id.
	 * @param dataSourceObjectId Object id of the data source.
	 * @param resultScore Score for a newly added analysis result.
	 * @param transaction Transaction to use for the update.
	 *
	 * @return Final score for the object.
	 *
	 * @throws TskCoreException
	 */
	Score updateFinalScore(long objId, long dataSourceObjectId, Score resultScore, CaseDbTransaction transaction) throws TskCoreException {

		// Get the current score 
		Score currentScore = ScoringManager.this.getAggregateScore(objId, transaction);

		// If current score is Unknown And newscore is not Unknown - allow None (good) to be recorded
		// or if the new score is higher than the current score
		if  ( (currentScore.compareTo(Score.SCORE_UNKNOWN) == 0 && resultScore.compareTo(Score.SCORE_UNKNOWN) != 0)
			  || (Score.getScoreComparator().compare(resultScore, currentScore) > 0)) {
			ScoringManager.this.setAggregateScore(objId, resultScore, transaction);
			
			// register score change in the transaction.
			transaction.registerScoreChange(new ScoreChange(objId, dataSourceObjectId, currentScore, resultScore));
			return resultScore;
		} else {
			// return the current score
			return currentScore;
		}
	}

	
	
	
}
