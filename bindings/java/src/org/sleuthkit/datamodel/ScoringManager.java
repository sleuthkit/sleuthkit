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

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import org.sleuthkit.datamodel.Score.Priority;
import org.sleuthkit.datamodel.Score.Significance;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbConnection;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbTransaction;
import org.sleuthkit.datamodel.TskData.DbType;

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
		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = db.getConnection()) {
			return getAggregateScore(objId, false, connection).orElse(Score.SCORE_UNKNOWN);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get the aggregate scores for the given list of object ids.
	 *
	 * @param objIds Object id list.
	 *
	 * @return Map<Long, Score> Each input object id will be mapped. If a score 
	 * is not found for an object Unknown score will be mapped.
	 *
	 * @throws TskCoreException
	 */
	public Map<Long, Score> getAggregateScores(List<Long> objIds) throws TskCoreException {

		if (objIds.isEmpty()) {
			return Collections.emptyMap();
		}
		
		// We need to deduplicate the list of object IDs. Otherwise the map  
		// below breaks and throws an exception.
		Set<Long> set = new HashSet<>(objIds);

		String queryString = "SELECT obj_id, significance, priority FROM tsk_aggregate_score WHERE obj_id in "
				+ set.stream().map(l -> l.toString()).collect(Collectors.joining(",", "(", ")"));

		Map<Long, Score> results = set.stream().collect(Collectors.toMap( key -> key, key -> Score.SCORE_UNKNOWN));
		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = db.getConnection()) {
			try (Statement s = connection.createStatement(); ResultSet rs = connection.executeQuery(s, queryString)) {
				while (rs.next()) {
					Long objId = rs.getLong("obj_id");
					Score score = new Score(Significance.fromID(rs.getInt("significance")), Priority.fromID(rs.getInt("priority")));
					results.put(objId, score);
				}
			} catch (SQLException ex) {
				throw new TskCoreException("SQLException thrown while running query: " + queryString, ex);
			}
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
		return results;
	}


	/**
	 * Get the aggregate score for the given object. Uses the connection from the
	 * given transaction.
	 *
	 * @param objId      Object id.
	 * @param forUpdate   set to true if a FOR UPDATE lock is required. This is a pgsql only option. 
	 * @param transaction Transaction that provides the connection to use.
	 *
	 * @return Score, if it is found, unknown otherwise.
	 *
	 * @throws TskCoreException
	 */
	private Optional<Score> getAggregateScore(long objId, boolean forUpdate, CaseDbTransaction transaction) throws TskCoreException {
		CaseDbConnection connection = transaction.getConnection();
		return getAggregateScore(objId, forUpdate, connection);
	}

	/**
	 * Get the aggregate score for the given object.
	 *
	 * @param objId Object id.
	 * @param forUpdate   set to true if a FOR UPDATE lock is required. This is a pgsql only option. 
	 * @param connection Connection to use for the query.
	 *
	 * @return Score, if it is found, SCORE_UNKNOWN otherwise.
	 *
	 * @throws TskCoreException
	 */
	private Optional<Score> getAggregateScore(long objId, boolean forUpdate, CaseDbConnection connection) throws TskCoreException {
		String queryString = "SELECT significance, priority FROM tsk_aggregate_score WHERE obj_id = " + objId + (forUpdate? " FOR UPDATE " : "");
		try (Statement s = connection.createStatement(); ResultSet rs = connection.executeQuery(s, queryString)) {
			if (rs.next()) {
				return Optional.of(new Score(Significance.fromID(rs.getInt("significance")), Priority.fromID(rs.getInt("priority"))));
			} else {
				return Optional.empty();
			}
		} catch (SQLException ex) {
			throw new TskCoreException("SQLException thrown while running query: " + queryString, ex);
		} 
	}

 
	/**
	 * Inserts or updates the score for the given object.
	 *
	 * @param objId              Object id of the object.
	 * @param dataSourceObjectId Data source object id, may be null.
	 * @param score              Score to be inserted/updated.
	 * @param updateOnly		 If score was previously recorded and need to be
	 *							 an updated - send true. 
	 * @param transaction        Transaction to use for the update.
	 *
	 * @throws TskCoreException
	 */
	private void setAggregateScore(long objId, Long dataSourceObjectId, Score score, boolean updateOnly, CaseDbTransaction transaction) throws TskCoreException {

		if (updateOnly) {
			String updateSQLString = " UPDATE tsk_aggregate_score SET significance = ?, priority = ? where obj_id = ?" ;

			CaseDbConnection connection = transaction.getConnection();
			try {
				PreparedStatement preparedStatement = connection.getPreparedStatement(updateSQLString, Statement.NO_GENERATED_KEYS);
				preparedStatement.clearParameters();

				preparedStatement.setInt(1, score.getSignificance().getId());
				preparedStatement.setInt(2, score.getPriority().getId());
				
				preparedStatement.setLong(3, objId);
				 
				connection.executeUpdate(preparedStatement);
			} catch (SQLException ex) {
				throw new TskCoreException(String.format("Error updating aggregate score, query: %s for objId = %d", updateSQLString, objId), ex);//NON-NLS 
			}
		} else {

			String insertSQLString = "INSERT INTO tsk_aggregate_score (obj_id, data_source_obj_id, significance , priority) VALUES (?, ?, ?, ?)"
					+ " ON CONFLICT (obj_id) DO UPDATE SET significance = ?, priority = ?";

			CaseDbConnection connection = transaction.getConnection();
			try {
				PreparedStatement preparedStatement = connection.getPreparedStatement(insertSQLString, Statement.NO_GENERATED_KEYS);
				preparedStatement.clearParameters();

				preparedStatement.setLong(1, objId);
				if (dataSourceObjectId != null) {
					preparedStatement.setLong(2, dataSourceObjectId);
				} else {
					preparedStatement.setNull(2, java.sql.Types.NULL);
				}
				preparedStatement.setInt(3, score.getSignificance().getId());
				preparedStatement.setInt(4, score.getPriority().getId());

				preparedStatement.setInt(5, score.getSignificance().getId());
				preparedStatement.setInt(6, score.getPriority().getId());

				connection.executeUpdate(preparedStatement);
			} catch (SQLException ex) {
				throw new TskCoreException(String.format("Error updating aggregate score, query: %s for objId = %d", insertSQLString, objId), ex);//NON-NLS
			}
		}
	}



	/**
	 * Updates the score for the specified object after a result has been
	 * added. Is optimized to do nothing if the new score is less than the
	 * current aggregate score. 
	 *
	 * @param objId              Object id.
	 * @param dataSourceObjectId Object id of the data source, may be null.
	 * @param newResultScore        Score for a newly added analysis result.
	 * @param transaction        Transaction to use for the update.
	 *
	 * @return Aggregate score for the object.
	 *
	 * @throws TskCoreException
	 */
	Score updateAggregateScoreAfterAddition(long objId, Long dataSourceObjectId, Score newResultScore, CaseDbTransaction transaction) throws TskCoreException {

		/* get an exclusive write lock on the DB before we read anything so that we know we are
		 * the only one reading existing scores and updating.  The risk is that two computers
		 * could update the score and the aggregate score ends up being incorrect. 
		 * 
		 * NOTE: The alternative design is to add a 'version' column for opportunistic locking
		 * and calculate these outside of a transaction.  We opted for table locking for performance
		 * reasons so that we can still add the analysis results in a batch.  That remains an option
		 * if we get into deadlocks with the current design. 
		 */  
		
		// Get the current score 
		// Will get a "FOR UPDATE" lock in postgresql 
		Optional<Score> oCurrentAggregateScore = ScoringManager.this.getAggregateScore(objId, db.getDatabaseType().equals(DbType.POSTGRESQL), transaction);

		Score currentAggregateScore = oCurrentAggregateScore.orElse(Score.SCORE_UNKNOWN);

		// If current score is Unknown And newscore is not Unknown - allow None (good) to be recorded
		// or if the new score is higher than the current score
		if  ( (currentAggregateScore.compareTo(Score.SCORE_UNKNOWN) == 0 && newResultScore.compareTo(Score.SCORE_UNKNOWN) != 0)
				|| (Score.getScoreComparator().compare(newResultScore, currentAggregateScore) > 0)) {
			setAggregateScore(objId, dataSourceObjectId, newResultScore, oCurrentAggregateScore.isPresent(), transaction);  // If score is present, do an update. 
			// register score change in the transaction.
			transaction.registerScoreChange(new ScoreChange(objId, dataSourceObjectId, currentAggregateScore, newResultScore));
			return newResultScore;
		} else {
			// return the current score
			return currentAggregateScore;
		}
	}
	
	/**
	 * Recalculate the aggregate score after an analysis result was 
	 * deleted.
	 * 
	 * @param objId Content that had result deleted from
	 * @param dataSourceObjectId Data source content is in
	 * @param transaction 
	 * @return New Score
	 * @throws TskCoreException 
	 */
	Score updateAggregateScoreAfterDeletion(long objId, Long dataSourceObjectId, CaseDbTransaction transaction) throws TskCoreException {

		CaseDbConnection connection = transaction.getConnection();
		
		/* get an exclusive write lock on the DB before we read anything so that we know we are
		 * the only one reading existing scores and updating.  The risk is that two computers
		 * could update the score and the aggregate score ends up being incorrect. 
		 * 
		 * NOTE: The alternative design is to add a 'version' column for opportunistic locking
		 * and calculate these outside of a transaction.  We opted for table locking for performance
		 * reasons so that we can still add the analysis results in a batch.  That remains an option
		 * if we get into deadlocks with the current design. 
		 */
  
		// Get the current score 
		Optional<Score> oCurrentAggregateScore = ScoringManager.this.getAggregateScore(objId, db.getDatabaseType().equals(DbType.POSTGRESQL), transaction);

		Score currentScore = oCurrentAggregateScore.orElse(Score.SCORE_UNKNOWN);		

		// Calculate the score from scratch by getting all of them and getting the highest
		List<AnalysisResult> analysisResults = db.getBlackboard().getAnalysisResults(objId, connection);
		Score newScore = Score.SCORE_UNKNOWN;
		for (AnalysisResult iter : analysisResults) {
			Score iterScore = iter.getScore();
			if (Score.getScoreComparator().compare(iterScore, newScore) > 0) {
				newScore = iterScore;
			}
		}

		// get the maximum score of the calculated aggregate score of analysis results
		// or the score derived from the maximum known status of a content tag on this content.
		Optional<Score> tagScore = db.getTaggingManager().getMaxTagType(objId, transaction)
				.map(knownStatus -> TaggingManager.getTagScore(knownStatus));
		
		if (tagScore.isPresent() && Score.getScoreComparator().compare(tagScore.get(), newScore) > 0) {
			newScore = tagScore.get();
		}
		
		// only change the DB if we got a new score. 
		if (newScore.compareTo(currentScore) != 0) {
			setAggregateScore(objId, dataSourceObjectId, newScore, oCurrentAggregateScore.isPresent(), transaction);

			// register the score change with the transaction so an event can be fired for it. 
			transaction.registerScoreChange(new ScoreChange(objId, dataSourceObjectId, currentScore, newScore));
		}
		return newScore;
	}
	
	/**
	 * Get the count of contents within the specified data source
	 * with the specified significance.
	 *
	 * @param dataSourceObjectId Data source object id.
	 * @param significance Significance to look for.
	 *
	 * @return Number of contents with given score.
	 * @throws TskCoreException if there is an error getting the count. 
	 */
	public long getContentCount(long dataSourceObjectId, Score.Significance significance) throws TskCoreException {
		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = db.getConnection()) {
			return getContentCount(dataSourceObjectId, significance, connection);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}


	/**
	 * Get the count of contents with the specified significance. Uses the
	 * specified database connection.
	 *
	 * @param dataSourceObjectId Data source object id.
	 * @param significance       Significance to look for.
	 * @param connection         Database connection to use..
	 *
	 * @return Number of contents with given score.
	 *
	 * @throws TskCoreException if there is an error getting the count.
	 */
	private long getContentCount(long dataSourceObjectId, Score.Significance significance, CaseDbConnection connection) throws TskCoreException {
		String queryString = "SELECT COUNT(obj_id) AS count FROM tsk_aggregate_score"
				+ " WHERE data_source_obj_id = " + dataSourceObjectId
				+ " AND significance = " + significance.getId();

		try (Statement statement = connection.createStatement();
				ResultSet resultSet = connection.executeQuery(statement, queryString);) {

			long count = 0;
			if (resultSet.next()) {
				count = resultSet.getLong("count");
			}
			return count;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting count of items with significance = " + significance.toString(), ex);
		}
	}
	
	/**
	 * Get the contents with the specified score.
	 *
	 * @param dataSourceObjectId Data source object id.
	 * @param significance       Significance to look for.
	 *
	 * @return Collection of contents with given score.
	 * 
	 * @throws TskCoreException if there is an error getting the contents.
	 */
	public List<Content> getContent(long dataSourceObjectId, Score.Significance significance) throws TskCoreException {
		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = db.getConnection()) {
			return getContent(dataSourceObjectId, significance, connection);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Gets the contents with the specified score. Uses the specified
	 * database connection.
	 *
	 * @param dataSourceObjectId Data source object id.
	 * @param significance       Significance to look for.
	 * @param connection         Connection to use for the query.
	 *
	 * @return List of contents with given score.
	 *
	 * @throws TskCoreException
	 */
	private List<Content> getContent(long dataSourceObjectId, Score.Significance significance, CaseDbConnection connection) throws TskCoreException {
		String queryString = "SELECT obj_id FROM tsk_aggregate_score"
				+ " WHERE data_source_obj_id = " + dataSourceObjectId 
				+ " AND significance = " + significance.getId();
			
		try (Statement statement = connection.createStatement();
				ResultSet resultSet = connection.executeQuery(statement, queryString);) {

			List<Content> items = new ArrayList<>();
			while (resultSet.next()) {
				long objId = resultSet.getLong("obj_id");
				items.add(db.getContentById(objId));
			}
			return items;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting list of items with significance = " + significance.toString(), ex);
		} 
	}
}
