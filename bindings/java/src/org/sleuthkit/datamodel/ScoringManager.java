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
import java.util.ArrayList;
import java.util.List;
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
	 * @param dataSourceObjectId Data source object id.
	 * @param score  Score to be inserted/updated.
	 * @param transaction Transaction to use for the update.
	 *
	 * @throws TskCoreException
	 */
	private void setAggregateScore(long objId, long dataSourceObjectId, Score score, CaseDbTransaction transaction) throws TskCoreException {
		CaseDbConnection connection = transaction.getConnection();
		setAggregateScore(objId, dataSourceObjectId, score, connection);
	}

	/**
	 * Inserts or updates the score for the given object.
	 *
	 * @param objId Object id of the object.
	 * @param dataSourceObjectId Data source object id.
	 * @param score  Score to be inserted/updated.
	 * @param connection Connection to use for the update.
	 *
	 * @throws TskCoreException
	 */
	private void setAggregateScore(long objId, long dataSourceObjectId, Score score, CaseDbConnection connection) throws TskCoreException {

		String query = String.format("INSERT INTO tsk_aggregate_score (obj_id, data_source_obj_id, significance , confidence) VALUES (%d, %d, %d, %d)"
				+ " ON CONFLICT (obj_id) DO UPDATE SET significance = %d, confidence = %d",
				objId, dataSourceObjectId, score.getSignificance().getId(), score.getConfidence().getId(), score.getSignificance().getId(), score.getConfidence().getId() );

		try {
			db.acquireSingleUserCaseWriteLock();

			try (Statement updateStatement = connection.createStatement()) {
				updateStatement.executeUpdate(query);
			} catch (SQLException ex) {
				throw new TskCoreException("Error updating  aggregate score, query: " + query, ex);//NON-NLS
			}

		} finally {
			db.releaseSingleUserCaseWriteLock();
		}

	}



	/**
	 * Updates the score for the specified object, if the given analysis result
	 * score is higher than the score the object already has.
	 *
	 * @param objId      Object id.
	 * @param dataSourceObjectId Object id of the data source.
	 * @param resultScore Score for a newly added analysis result.
	 * @param transaction Transaction to use for the update.
	 *
	 * @return Aggregate score for the object.
	 *
	 * @throws TskCoreException
	 */
	Score updateAggregateScore(long objId, long dataSourceObjectId, Score resultScore, CaseDbTransaction transaction) throws TskCoreException {

		// Get the current score 
		Score currentScore = ScoringManager.this.getAggregateScore(objId, transaction);

		// If current score is Unknown And newscore is not Unknown - allow None (good) to be recorded
		// or if the new score is higher than the current score
		if  ( (currentScore.compareTo(Score.SCORE_UNKNOWN) == 0 && resultScore.compareTo(Score.SCORE_UNKNOWN) != 0)
			  || (Score.getScoreComparator().compare(resultScore, currentScore) > 0)) {
			ScoringManager.this.setAggregateScore(objId, dataSourceObjectId, resultScore, transaction);
			
			// register score change in the transaction.
			transaction.registerScoreChange(new ScoreChange(objId, dataSourceObjectId, currentScore, resultScore));
			return resultScore;
		} else {
			// return the current score
			return currentScore;
		}
	}

	/**
	 * Get the count of contents within the specified data source
	 * with the specified aggregate score.
	 *
	 * @param dataSourceObjectId Data source object id.
	 * @param aggregateScore Score to look for.
	 *
	 * @return Number of contents with given score.
	 * @throws TskCoreException if there is an error getting the count. 
	 */
	public long getContentCount(long dataSourceObjectId, Score aggregateScore) throws TskCoreException {
		try (CaseDbConnection connection = db.getConnection()) {
			return getContentCount(dataSourceObjectId, aggregateScore, connection);
		} 
	}


	/**
	 * Get the count of contents with the specified score. Uses the specified
	 * transaction to obtain the database connection.
	 *
	 * @param dataSourceObjectId Data source object id.
	 * @param aggregateScore       Score to look for.
	 * @param transaction Transaction from which to get the connection.
	 *
	 * @return Number of contents with given score.
	 *
	 * @throws TskCoreException if there is an error getting the count. 
	 */
	private long getContentCount(long dataSourceObjectId, Score aggregateScore, CaseDbConnection connection) throws TskCoreException {
		String queryString = "SELECT COUNT(obj_id) AS count FROM tsk_aggregate_score"
				+ " WHERE data_source_obj_id = " + dataSourceObjectId 
				+ " AND significance = " + aggregateScore.getSignificance().getId()
				+ " AND confidence = " + aggregateScore.getConfidence().getId();

		db.acquireSingleUserCaseReadLock();
		try (Statement statement = connection.createStatement();
				ResultSet resultSet = connection.executeQuery(statement, queryString);) {

			long count = 0;
			if (resultSet.next()) {
				count = resultSet.getLong("count");
			}
			return count;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting count of items with score = " + aggregateScore.toString(), ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}
	
	/**
	 * Get the contents with the specified score.
	 * 
	 * @param dataSourceObjectId Data source object id.
	 * @param aggregateScore Score to look for.
	 *
	 * @return Collection of contents with given score.
	 */
	public List<Content> getContent(long dataSourceObjectId, Score aggregateScore) throws TskCoreException {
		try (CaseDbConnection connection = db.getConnection()) {
			return getContent(dataSourceObjectId, aggregateScore, connection);
		} 
	}

	/**
	 * Gets the contents with the specified score. Uses the specified transaction
	 * to obtain the database connection.
	 *
	 * @param dataSourceObjectId Data source object id.
	 * @param aggregateScore       Score to look for.
	 * @param connection Connection to use for the query.
	 *
	 * @return List of contents with given score.
	 *
	 * @throws TskCoreException
	 */
	private List<Content> getContent(long dataSourceObjectId, Score aggregateScore, CaseDbConnection connection) throws TskCoreException {
		String queryString = "SELECT obj_id FROM tsk_aggregate_score"
				+ " WHERE data_source_obj_id = " + dataSourceObjectId 
				+ " AND significance = " + aggregateScore.getSignificance().getId()
				+ " AND confidence = " + aggregateScore.getConfidence().getId();

		db.acquireSingleUserCaseReadLock();
		try (Statement statement = connection.createStatement();
				ResultSet resultSet = connection.executeQuery(statement, queryString);) {

			List<Content> items = new ArrayList<>();
			while (resultSet.next()) {
				long objId = resultSet.getLong("obj_id");
				items.add(db.getContentById(objId));
			}
			return items;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting list of items with score = " + aggregateScore.toString(), ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}
}
