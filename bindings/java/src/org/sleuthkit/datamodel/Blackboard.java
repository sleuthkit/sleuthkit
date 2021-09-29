/*
 * Sleuth Kit Data Model
 *
 * Copyright 2018-2021 Basis Technology Corp.
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

import com.google.common.collect.ImmutableSet;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbConnection;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbTransaction;

/**
 * A representation of the blackboard, a place where artifacts and their
 * attributes are posted.
 */
public final class Blackboard {

	private static final Logger LOGGER = Logger.getLogger(Blackboard.class.getName());

	private final SleuthkitCase caseDb;

	/**
	 * Constructs a representation of the blackboard, a place where artifacts
	 * and their attributes are posted.
	 *
	 * @param casedb The case database.
	 */
	Blackboard(SleuthkitCase casedb) {
		this.caseDb = Objects.requireNonNull(casedb, "Cannot create Blackboard for null SleuthkitCase");
	}

	/**
	 * Posts the artifact. The artifact should be complete (all attributes have
	 * been added) before being posted. Posting the artifact includes making any
	 * timeline events that may be derived from it, and broadcasting a
	 * notification that the artifact is ready for further analysis.
	 *
	 * @param artifact   The artifact to be posted.
	 * @param moduleName The name of the module that is posting the artifacts.
	 *
	 * @throws BlackboardException If there is a problem posting the artifact.
	 */
	public void postArtifact(BlackboardArtifact artifact, String moduleName) throws BlackboardException {
		postArtifacts(Collections.singleton(artifact), moduleName);
	}

	/**
	 * Posts a Collection of artifacts. The artifacts should be complete (all
	 * attributes have been added) before being posted. Posting the artifacts
	 * includes making any events that may be derived from them, and
	 * broadcasting notifications that the artifacts are ready for further
	 * analysis.
	 *
	 *
	 * @param artifacts  The artifacts to be posted .
	 * @param moduleName The name of the module that is posting the artifacts.
	 *
	 *
	 * @throws BlackboardException If there is a problem posting the artifacts.
	 *
	 */
	public void postArtifacts(Collection<BlackboardArtifact> artifacts, String moduleName) throws BlackboardException {
		/*
		 * For now this just processes them one by one, but in the future it
		 * could be smarter and use transactions, etc.
		 */
		for (BlackboardArtifact artifact : artifacts) {
			try {
				caseDb.getTimelineManager().addArtifactEvents(artifact);
			} catch (TskCoreException ex) {
				throw new BlackboardException("Failed to add events for artifact: " + artifact, ex);
			}
		}

		caseDb.fireTSKEvent(new ArtifactsPostedEvent(artifacts, moduleName));
	}

	/**
	 * Gets an artifact type, creating it if it does not already exist. Use this
	 * method to define custom artifact types.
	 *
	 * This assumes that the artifact type is of category DATA_ARTIFACT.
	 *
	 * @param typeName    The type name of the artifact type.
	 * @param displayName The display name of the artifact type.
	 *
	 * @return A type object representing the artifact type.
	 *
	 * @throws BlackboardException If there is a problem getting or adding the
	 *                             artifact type.
	 */
	public BlackboardArtifact.Type getOrAddArtifactType(String typeName, String displayName) throws BlackboardException {

		return getOrAddArtifactType(typeName, displayName, BlackboardArtifact.Category.DATA_ARTIFACT);
	}

	/**
	 * Gets an artifact type, creating it if it does not already exist. Use this
	 * method to define custom artifact types.
	 *
	 * @param typeName    The type name of the artifact type.
	 * @param displayName The display name of the artifact type.
	 * @param category    The artifact type category.
	 *
	 * @return A type object representing the artifact type.
	 *
	 * @throws BlackboardException If there is a problem getting or adding the
	 *                             artifact type.
	 */
	public BlackboardArtifact.Type getOrAddArtifactType(String typeName, String displayName, BlackboardArtifact.Category category) throws BlackboardException {
		if (category == null) {
			throw new BlackboardException("Category provided must be non-null");
		}

		try {
			return caseDb.addBlackboardArtifactType(typeName, displayName, category);
		} catch (TskDataException typeExistsEx) {
			try {
				return caseDb.getArtifactType(typeName);
			} catch (TskCoreException ex) {
				throw new BlackboardException("Failed to get or add artifact type", ex);
			}
		} catch (TskCoreException ex) {
			throw new BlackboardException("Failed to get or add artifact type", ex);
		}
	}

	/**
	 * Adds new analysis result artifact.
	 *
	 * @param artifactType    Type of analysis result artifact to create.
	 * @param objId           Object id of parent.
	 * @param dataSourceObjId Data source object id, may be null.
	 * @param score	          Score associated with this analysis result.
	 * @param conclusion      Conclusion of the analysis, may be null or an
	 *                        empty string.
	 * @param configuration   Configuration associated with this analysis, may
	 *                        be null or an empty string.
	 * @param justification   Justification, may be null or an empty string.
	 * @param attributesList  Attributes to be attached to this analysis result
	 *                        artifact.
	 *
	 * @return AnalysisResultAdded The analysis return added and the current
	 *         aggregate score of content.
	 *
	 * @throws TskCoreException
	 * @throws BlackboardException exception thrown if a critical error occurs
	 *                             within TSK core
	 */
	public AnalysisResultAdded newAnalysisResult(BlackboardArtifact.Type artifactType, long objId, Long dataSourceObjId, Score score,
			String conclusion, String configuration, String justification, Collection<BlackboardAttribute> attributesList)
			throws BlackboardException, TskCoreException {

		if (artifactType.getCategory() != BlackboardArtifact.Category.ANALYSIS_RESULT) {
			throw new BlackboardException(String.format("Artifact type (name = %s) is not of Analysis Result category. ", artifactType.getTypeName()));
		}

		CaseDbTransaction transaction = caseDb.beginTransaction();
		try {
			AnalysisResultAdded analysisResult = newAnalysisResult(artifactType, objId, dataSourceObjId, score,
					conclusion, configuration, justification, attributesList, transaction);
			transaction.commit();
			return analysisResult;
		} catch (TskCoreException | BlackboardException ex) {
			try {
				transaction.rollback();
			} catch (TskCoreException ex2) {
				LOGGER.log(Level.SEVERE, "Failed to rollback transaction after exception. "
						+ "Error invoking newAnalysisResult with dataSourceObjId: "
						+ (dataSourceObjId == null ? "<null>" : dataSourceObjId)
						+ ",  sourceObjId: " + objId, ex2);
			}
			throw ex;
		}
	}

	/**
	 * Adds new analysis result artifact.
	 *
	 * @param artifactType    Type of analysis result artifact to create.
	 * @param objId           Object id of parent.
	 * @param dataSourceObjId Data source object id, may be null.
	 * @param score	          Score associated with this analysis result.
	 * @param conclusion      Conclusion of the analysis, may be null or an
	 *                        empty string.
	 * @param configuration   Configuration associated with this analysis, may
	 *                        be null or an empty string.
	 * @param justification   Justification, may be null or an empty string.
	 * @param attributesList  Attributes to be attached to this analysis result
	 *                        artifact.
	 * @param transaction     DB transaction to use.
	 *
	 * @return AnalysisResultAdded The analysis return added and the current
	 *         aggregate score of content.
	 *
	 * @throws BlackboardException exception thrown if a critical error occurs
	 *                             within TSK core
	 */
	public AnalysisResultAdded newAnalysisResult(BlackboardArtifact.Type artifactType, long objId, Long dataSourceObjId, Score score,
			String conclusion, String configuration, String justification, Collection<BlackboardAttribute> attributesList, CaseDbTransaction transaction) throws BlackboardException {

		if (artifactType.getCategory() != BlackboardArtifact.Category.ANALYSIS_RESULT) {
			throw new BlackboardException(String.format("Artifact type (name = %s) is not of Analysis Result category. ", artifactType.getTypeName()));
		}

		try {
			// add analysis result
			AnalysisResult analysisResult = caseDb.newAnalysisResult(artifactType, objId, dataSourceObjId, score, conclusion, configuration, justification, transaction.getConnection());

			// add the given attributes
			if (attributesList != null && !attributesList.isEmpty()) {
				analysisResult.addAttributes(attributesList, transaction);
			}

			// update the final score for the object 
			Score aggregateScore = caseDb.getScoringManager().updateAggregateScoreAfterAddition(objId, dataSourceObjId, analysisResult.getScore(), transaction);

			// return the analysis result and the current aggregate score.
			return new AnalysisResultAdded(analysisResult, aggregateScore);

		} catch (TskCoreException ex) {
			throw new BlackboardException("Failed to add analysis result.", ex);
		}
	}

	/**
	 * Delete the specified analysis result.
	 *
	 * Deletes the result from blackboard_artifacts and tsk_analysis_results,
	 * and recalculates and updates the aggregate score of the content. Fires an
	 * event to indicate that the analysis result has been deleted and that the
	 * score of the item has changed.
	 *
	 * @param analysisResult AnalysisResult to delete.
	 *
	 * @return New score of the content.
	 *
	 * @throws TskCoreException
	 */
	public Score deleteAnalysisResult(AnalysisResult analysisResult) throws TskCoreException {

		CaseDbTransaction transaction = this.caseDb.beginTransaction();
		try {
			Score score = deleteAnalysisResult(analysisResult, transaction);
			transaction.commit();
			transaction = null;

			return score;
		} finally {
			if (transaction != null) {
				transaction.rollback();
			}
		}
	}

	/**
	 * Delete the specified analysis result.
	 *
	 * Deletes the result from blackboard_artifacts and tsk_analysis_results,
	 * and recalculates and updates the aggregate score of the content.
	 *
	 * @param artifactObjId Artifact Obj Id to be deleted
	 * @param transaction
	 *
	 * @return
	 *
	 * @throws TskCoreException
	 */
	public Score deleteAnalysisResult(long artifactObjId, CaseDbTransaction transaction) throws TskCoreException {

		List<AnalysisResult> analysisResults = getAnalysisResultsWhere(" artifacts.artifact_obj_id = " + artifactObjId, transaction.getConnection());

		if (analysisResults.isEmpty()) {
			throw new TskCoreException(String.format("Analysis Result not found for artifact obj id %d", artifactObjId));
		}

		return deleteAnalysisResult(analysisResults.get(0), transaction);
	}

	/**
	 * Delete the specified analysis result.
	 *
	 * Deletes the result from blackboard_artifacts and tsk_analysis_results,
	 * and recalculates and updates the aggregate score of the content.
	 *
	 * @param analysisResult AnalysisResult to delete.
	 * @param transaction    Transaction to use for database operations.
	 *
	 * @return New score of the content.
	 *
	 * @throws TskCoreException
	 */
	private Score deleteAnalysisResult(AnalysisResult analysisResult, CaseDbTransaction transaction) throws TskCoreException {

		try {
			CaseDbConnection connection = transaction.getConnection();

			// delete the blackboard artifacts row. This will also delete the tsk_analysis_result row
			String deleteSQL = "DELETE FROM blackboard_artifacts WHERE artifact_obj_id = ?";

			PreparedStatement deleteStatement = connection.getPreparedStatement(deleteSQL, Statement.RETURN_GENERATED_KEYS);
			deleteStatement.clearParameters();
			deleteStatement.setLong(1, analysisResult.getId());

			deleteStatement.executeUpdate();

			// register the deleted result with the transaction so an event can be fired for it. 
			transaction.registerDeletedAnalysisResult(analysisResult.getObjectID());

			return caseDb.getScoringManager().updateAggregateScoreAfterDeletion(analysisResult.getObjectID(), analysisResult.getDataSourceObjectID(), transaction);

		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error deleting analysis result with artifact obj id %d", analysisResult.getId()), ex);
		}
	}

	private final static String ANALYSIS_RESULT_QUERY_STRING = "SELECT DISTINCT artifacts.artifact_id AS artifact_id, " //NON-NLS
			+ " artifacts.obj_id AS obj_id, artifacts.artifact_obj_id AS artifact_obj_id, artifacts.data_source_obj_id AS data_source_obj_id, artifacts.artifact_type_id AS artifact_type_id, "
			+ " types.type_name AS type_name, types.display_name AS display_name, types.category_type as category_type,"//NON-NLS
			+ " artifacts.review_status_id AS review_status_id, " //NON-NLS
			+ " results.conclusion AS conclusion,  results.significance AS significance,  results.priority AS priority,  "
			+ " results.configuration AS configuration,  results.justification AS justification "
			+ " FROM blackboard_artifacts AS artifacts "
			+ " JOIN blackboard_artifact_types AS types " //NON-NLS
			+ "		ON artifacts.artifact_type_id = types.artifact_type_id" //NON-NLS
			+ " LEFT JOIN tsk_analysis_results AS results "
			+ "		ON artifacts.artifact_obj_id = results.artifact_obj_id " //NON-NLS
			+ " WHERE artifacts.review_status_id != " + BlackboardArtifact.ReviewStatus.REJECTED.getID() //NON-NLS
			+ "     AND types.category_type = " + BlackboardArtifact.Category.ANALYSIS_RESULT.getID(); // NON-NLS

	/**
	 * Get all analysis results of given artifact type.
	 *
	 * @param artifactTypeId The artifact type id for which to search.
	 *
	 * @return The list of analysis results.
	 *
	 * @throws TskCoreException Exception thrown if a critical error occurs
	 *                          within TSK core.
	 */
	public List<AnalysisResult> getAnalysisResultsByType(int artifactTypeId) throws TskCoreException {
		return getAnalysisResultsWhere(" artifacts.artifact_type_id = " + artifactTypeId);
	}

	/**
	 * Get all analysis results of given artifact type.
	 *
	 * @param artifactTypeId  The artifact type id for which to search.
	 * @param dataSourceObjId Object Id of the data source to look under.
	 *
	 * @return The list of analysis results.
	 *
	 * @throws TskCoreException Exception thrown if a critical error occurs
	 *                          within TSK core.
	 */
	public List<AnalysisResult> getAnalysisResultsByType(int artifactTypeId, long dataSourceObjId) throws TskCoreException {
		return getAnalysisResultsWhere(" artifacts.artifact_type_id = " + artifactTypeId + " AND artifacts.data_source_obj_id = " + dataSourceObjId);
	}

	/**
	 * Get all analysis results for a given object.
	 *
	 * @param sourceObjId Object id.
	 *
	 * @return list of analysis results.
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core.
	 */
	public List<AnalysisResult> getAnalysisResults(long sourceObjId) throws TskCoreException {
		return getAnalysisResultsWhere(" artifacts.obj_id = " + sourceObjId);
	}

	/**
	 * Get all data artifacts for a given object.
	 *
	 * @param sourceObjId Object id.
	 *
	 * @return List of data artifacts.
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core.
	 */
	List<DataArtifact> getDataArtifactsBySource(long sourceObjId) throws TskCoreException {
		caseDb.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = caseDb.getConnection()) {
			return getDataArtifactsWhere(String.format(" artifacts.obj_id = %d", sourceObjId), connection);
		} finally {
			caseDb.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Returns true if there are data artifacts belonging to the sourceObjId.
	 *
	 * @param sourceObjId The source content object id.
	 *
	 * @return True if there are data artifacts belonging to this source obj id.
	 *
	 * @throws TskCoreException
	 */
	public boolean hasDataArtifacts(long sourceObjId) throws TskCoreException {
		return hasArtifactsOfCategory(BlackboardArtifact.Category.DATA_ARTIFACT, sourceObjId);
	}

	/**
	 * Returns true if there are analysis results belonging to the sourceObjId.
	 *
	 * @param sourceObjId The source content object id.
	 *
	 * @return True if there are analysis results belonging to this source obj
	 *         id.
	 *
	 * @throws TskCoreException
	 */
	public boolean hasAnalysisResults(long sourceObjId) throws TskCoreException {
		return hasArtifactsOfCategory(BlackboardArtifact.Category.ANALYSIS_RESULT, sourceObjId);
	}

	/**
	 * Returns true if there are artifacts of the given category belonging to
	 * the sourceObjId.
	 *
	 * @param category    The category of the artifacts.
	 * @param sourceObjId The source content object id.
	 *
	 * @return True if there are artifacts of the given category belonging to
	 *         this source obj id.
	 *
	 * @throws TskCoreException
	 */
	private boolean hasArtifactsOfCategory(BlackboardArtifact.Category category, long sourceObjId) throws TskCoreException {
		String queryString = "SELECT COUNT(*) AS count " //NON-NLS
				+ " FROM blackboard_artifacts AS arts "
				+ " JOIN blackboard_artifact_types AS types " //NON-NLS
				+ "		ON arts.artifact_type_id = types.artifact_type_id" //NON-NLS
				+ " WHERE types.category_type = " + category.getID()
				+ " AND arts.obj_id = " + sourceObjId;

		caseDb.acquireSingleUserCaseReadLock();
		try (SleuthkitCase.CaseDbConnection connection = caseDb.getConnection();
				Statement statement = connection.createStatement();
				ResultSet resultSet = connection.executeQuery(statement, queryString);) {
			if (resultSet.next()) {
				return resultSet.getLong("count") > 0;
			}
			return false;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting artifact types is use for data source." + ex.getMessage(), ex);
		} finally {
			caseDb.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get all analysis results for a given object.
	 *
	 * @param sourceObjId Object id.
	 * @param connection  Database connection to use.
	 *
	 *
	 * @return list of analysis results.
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core.
	 */
	List<AnalysisResult> getAnalysisResults(long sourceObjId, CaseDbConnection connection) throws TskCoreException {
		return getAnalysisResultsWhere(" artifacts.obj_id = " + sourceObjId, connection);
	}

	/**
	 * Get analysis results of the given type, for the given object.
	 *
	 * @param sourceObjId    Object id.
	 * @param artifactTypeId Result type to get.
	 *
	 * @return list of analysis results.
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core.
	 */
	public List<AnalysisResult> getAnalysisResults(long sourceObjId, int artifactTypeId) throws TskCoreException {
		// Get the artifact type to check that it in the analysis result category.
		BlackboardArtifact.Type artifactType = caseDb.getArtifactType(artifactTypeId);
		if (artifactType.getCategory() != BlackboardArtifact.Category.ANALYSIS_RESULT) {
			throw new TskCoreException(String.format("Artifact type id %d is not in analysis result catgeory.", artifactTypeId));
		}

		String whereClause = " types.artifact_type_id = " + artifactTypeId
				+ " AND artifacts.obj_id = " + sourceObjId;
		return getAnalysisResultsWhere(whereClause);
	}

	/**
	 * Get all analysis results matching the given where sub-clause.
	 *
	 *
	 * @param whereClause Where sub clause, specifies conditions to match.
	 *
	 * @return list of analysis results.
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core.
	 */
	public List<AnalysisResult> getAnalysisResultsWhere(String whereClause) throws TskCoreException {
		caseDb.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = caseDb.getConnection()) {
			return getAnalysisResultsWhere(whereClause, connection);
		} finally {
			caseDb.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get all analysis results matching the given where sub-clause. Uses the
	 * given database connection to execute the query.
	 *
	 * @param whereClause Where sub clause, specifies conditions to match.
	 * @param connection  Database connection to use.
	 *
	 * @return list of analysis results.
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	List<AnalysisResult> getAnalysisResultsWhere(String whereClause, CaseDbConnection connection) throws TskCoreException {

		final String queryString = ANALYSIS_RESULT_QUERY_STRING
				+ " AND " + whereClause;

		try (Statement statement = connection.createStatement();
				ResultSet resultSet = connection.executeQuery(statement, queryString);) {

			List<AnalysisResult> analysisResults = resultSetToAnalysisResults(resultSet);
			return analysisResults;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting analysis results for WHERE clause = '%s'", whereClause), ex);
		}
	}

	/**
	 * Get the analysis results by its artifact_obj_id.
	 *
	 * @param artifactObjId Artifact object id of the analysis result.
	 *
	 * @return AnalysisResult.
	 *
	 * @throws TskCoreException If a critical error occurred within TSK core.
	 */
	public AnalysisResult getAnalysisResultById(long artifactObjId) throws TskCoreException {

		String whereClause = " artifacts.artifact_obj_id = " + artifactObjId;
		List<AnalysisResult> results = getAnalysisResultsWhere(whereClause);

		if (results.isEmpty()) { // throw an error if no analysis result found by id.
			throw new TskCoreException(String.format("Error getting analysis result with id = '%d'", artifactObjId));
		}
		if (results.size() > 1) { // should not happen - throw an error
			throw new TskCoreException(String.format("Multiple analysis results found with id = '%d'", artifactObjId));
		}

		return results.get(0);
	}

	/**
	 * Creates AnalysisResult objects for the result set of a table query of the
	 * form "SELECT * FROM blackboard_artifacts JOIN WHERE XYZ".
	 *
	 * @param rs A result set from a query of the blackboard_artifacts table of
	 *           the form "SELECT * FROM blackboard_artifacts,
	 *           tsk_analysis_results WHERE ...".
	 *
	 * @return A list of BlackboardArtifact objects.
	 *
	 * @throws SQLException     Thrown if there is a problem iterating through
	 *                          the result set.
	 * @throws TskCoreException Thrown if there is an error looking up the
	 *                          artifact type id.
	 */
	private List<AnalysisResult> resultSetToAnalysisResults(ResultSet resultSet) throws SQLException, TskCoreException {
		ArrayList<AnalysisResult> analysisResults = new ArrayList<>();

		while (resultSet.next()) {
			analysisResults.add(new AnalysisResult(caseDb, resultSet.getLong("artifact_id"), resultSet.getLong("obj_id"),
					resultSet.getLong("artifact_obj_id"),
					resultSet.getObject("data_source_obj_id") != null ? resultSet.getLong("data_source_obj_id") : null,
					resultSet.getInt("artifact_type_id"), resultSet.getString("type_name"), resultSet.getString("display_name"),
					BlackboardArtifact.ReviewStatus.withID(resultSet.getInt("review_status_id")),
					new Score(Score.Significance.fromID(resultSet.getInt("significance")), Score.Priority.fromID(resultSet.getInt("priority"))),
					resultSet.getString("conclusion"), resultSet.getString("configuration"), resultSet.getString("justification")));
		} //end for each resultSet

		return analysisResults;
	}

	private final static String DATA_ARTIFACT_QUERY_STRING = "SELECT DISTINCT artifacts.artifact_id AS artifact_id, " //NON-NLS
			+ "artifacts.obj_id AS obj_id, artifacts.artifact_obj_id AS artifact_obj_id, artifacts.data_source_obj_id AS data_source_obj_id, artifacts.artifact_type_id AS artifact_type_id, " //NON-NLS
			+ " types.type_name AS type_name, types.display_name AS display_name, types.category_type as category_type,"//NON-NLS
			+ " artifacts.review_status_id AS review_status_id, " //NON-NLS
			+ " data_artifacts.os_account_obj_id as os_account_obj_id " //NON-NLS
			+ " FROM blackboard_artifacts AS artifacts "
			+ " JOIN blackboard_artifact_types AS types " //NON-NLS
			+ "		ON artifacts.artifact_type_id = types.artifact_type_id" //NON-NLS
			+ " LEFT JOIN tsk_data_artifacts AS data_artifacts "
			+ "		ON artifacts.artifact_obj_id = data_artifacts.artifact_obj_id " //NON-NLS
			+ " WHERE artifacts.review_status_id != " + BlackboardArtifact.ReviewStatus.REJECTED.getID() //NON-NLS
			+ "     AND types.category_type = " + BlackboardArtifact.Category.DATA_ARTIFACT.getID(); // NON-NLS

	/**
	 * Gets all data artifacts of a given type for a given data source. To get
	 * all the data artifacts for the data source, pass null for the type ID.
	 *
	 * @param dataSourceObjId The object ID of the data source.
	 * @param artifactTypeID  The type ID of the desired artifacts or null.
	 *
	 * @return A list of the data artifacts, possibly empty.
	 *
	 * @throws TskCoreException This exception is thrown if there is an error
	 *                          querying the case database.
	 */
	public List<DataArtifact> getDataArtifacts(long dataSourceObjId, Integer artifactTypeID) throws TskCoreException {
		caseDb.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = caseDb.getConnection()) {
			String whereClause = " artifacts.data_source_obj_id = " + dataSourceObjId;
			if (artifactTypeID != null) {
				whereClause += " AND artifacts.artifact_type_id = " + artifactTypeID;
			}
			return getDataArtifactsWhere(whereClause, connection);
		} finally {
			caseDb.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get all data artifacts of a given type for a given data source.
	 *
	 * @param artifactTypeID  Artifact type to get.
	 * @param dataSourceObjId Data source to look under.
	 *
	 * @return List of data artifacts. May be an empty list.
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core.
	 */
	public List<DataArtifact> getDataArtifacts(int artifactTypeID, long dataSourceObjId) throws TskCoreException {

		// Get the artifact type to check that it in the data artifact category.
		BlackboardArtifact.Type artifactType = caseDb.getArtifactType(artifactTypeID);
		if (artifactType.getCategory() != BlackboardArtifact.Category.DATA_ARTIFACT) {
			throw new TskCoreException(String.format("Artifact type id %d is not in data artifact catgeory.", artifactTypeID));
		}

		caseDb.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = caseDb.getConnection()) {
			String whereClause = "artifacts.data_source_obj_id = " + dataSourceObjId
					+ " AND artifacts.artifact_type_id = " + artifactTypeID;

			return getDataArtifactsWhere(whereClause, connection);
		} finally {
			caseDb.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get all data artifacts of a given type.
	 *
	 * @param artifactTypeID Artifact type to get.
	 *
	 * @return List of data artifacts. May be an empty list.
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core.
	 */
	public List<DataArtifact> getDataArtifacts(int artifactTypeID) throws TskCoreException {
		// Get the artifact type to check that it in the data artifact category.
		BlackboardArtifact.Type artifactType = caseDb.getArtifactType(artifactTypeID);
		if (artifactType.getCategory() != BlackboardArtifact.Category.DATA_ARTIFACT) {
			throw new TskCoreException(String.format("Artifact type id %d is not in data artifact catgeory.", artifactTypeID));
		}

		caseDb.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = caseDb.getConnection()) {
			String whereClause = " artifacts.artifact_type_id = " + artifactTypeID;

			return getDataArtifactsWhere(whereClause, connection);
		} finally {
			caseDb.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get the data artifact with the given artifact obj id.
	 *
	 * @param artifactObjId Object id of the data artifact to get.
	 *
	 * @return Data artifact with given artifact object id.
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core.
	 */
	public DataArtifact getDataArtifactById(long artifactObjId) throws TskCoreException {
		caseDb.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = caseDb.getConnection()) {
			String whereClause = " artifacts.artifact_obj_id = " + artifactObjId;

			List<DataArtifact> artifacts = getDataArtifactsWhere(whereClause, connection);
			if (artifacts.isEmpty()) { // throw an error if no analysis result found by id.
				throw new TskCoreException(String.format("Error getting data artifact with id = '%d'", artifactObjId));
			}
			if (artifacts.size() > 1) { // should not happen - throw an error
				throw new TskCoreException(String.format("Multiple data artifacts found with id = '%d'", artifactObjId));
			}

			return artifacts.get(0);
		} finally {
			caseDb.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get all data artifacts matching the given where sub-clause.
	 *
	 * @param whereClause SQL Where sub-clause, specifies conditions to match.
	 *
	 * @return List of data artifacts. May be an empty list.
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core.
	 */
	List<DataArtifact> getDataArtifactsWhere(String whereClause) throws TskCoreException {
		caseDb.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = caseDb.getConnection()) {
			return getDataArtifactsWhere(whereClause, connection);
		} finally {
			caseDb.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get all data artifacts matching the given where sub-clause. Uses the
	 * given database connection to execute the query.
	 *
	 * @param whereClause SQL Where sub-clause, specifies conditions to match.
	 * @param connection  Database connection to use.
	 *
	 * @return List of data artifacts. May be an empty list.
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core.
	 */
	List<DataArtifact> getDataArtifactsWhere(String whereClause, CaseDbConnection connection) throws TskCoreException {

		final String queryString = DATA_ARTIFACT_QUERY_STRING
				+ " AND ( " + whereClause + " )";

		try (Statement statement = connection.createStatement();
				ResultSet resultSet = connection.executeQuery(statement, queryString);) {

			List<DataArtifact> dataArtifacts = resultSetToDataArtifacts(resultSet, connection);
			return dataArtifacts;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting data artifacts with queryString = %s", queryString), ex);
		}
	}

	/**
	 * Creates DataArtifacts objects for the resultset of a table query of the
	 * form "SELECT * FROM blackboard_artifacts JOIN data_artifacts WHERE ...".
	 *
	 * @param resultSet  A result set from a query of the blackboard_artifacts
	 *                   table of the form "SELECT * FROM blackboard_artifacts,
	 *                   tsk_data_artifacts WHERE ...".
	 * @param connection Database connection.
	 *
	 * @return A list of DataArtifact objects.
	 *
	 * @throws SQLException     Thrown if there is a problem iterating through
	 *                          the result set.
	 * @throws TskCoreException Thrown if there is an error looking up the
	 *                          artifact type id.
	 */
	private List<DataArtifact> resultSetToDataArtifacts(ResultSet resultSet, CaseDbConnection connection) throws SQLException, TskCoreException {
		ArrayList<DataArtifact> dataArtifacts = new ArrayList<>();

		while (resultSet.next()) {

			Long osAccountObjId = resultSet.getLong("os_account_obj_id");
			if (resultSet.wasNull()) {
				osAccountObjId = null;
			}

			dataArtifacts.add(new DataArtifact(caseDb, resultSet.getLong("artifact_id"), resultSet.getLong("obj_id"),
					resultSet.getLong("artifact_obj_id"),
					resultSet.getObject("data_source_obj_id") != null ? resultSet.getLong("data_source_obj_id") : null,
					resultSet.getInt("artifact_type_id"), resultSet.getString("type_name"), resultSet.getString("display_name"),
					BlackboardArtifact.ReviewStatus.withID(resultSet.getInt("review_status_id")), osAccountObjId, false));
		} //end for each resultSet

		return dataArtifacts;
	}

	/**
	 * Get the artifact type associated with an artifact type id.
	 *
	 * @param artTypeId An artifact type id.
	 *
	 * @return The artifact type.
	 *
	 * @throws TskCoreException If an error occurs accessing the case database
	 *                          or no value is found.
	 *
	 */
	public BlackboardArtifact.Type getArtifactType(int artTypeId) throws TskCoreException {
		return caseDb.getArtifactType(artTypeId);
	}

	/**
	 * Gets an attribute type, creating it if it does not already exist. Use
	 * this method to define custom attribute types.
	 *
	 * @param typeName    The type name of the attribute type.
	 * @param valueType   The value type of the attribute type.
	 * @param displayName The display name of the attribute type.
	 *
	 * @return A type object representing the attribute type.
	 *
	 * @throws BlackboardException If there is a problem getting or adding the
	 *                             attribute type.
	 */
	public BlackboardAttribute.Type getOrAddAttributeType(String typeName, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE valueType, String displayName) throws BlackboardException {

		try {
			return caseDb.addArtifactAttributeType(typeName, valueType, displayName);
		} catch (TskDataException typeExistsEx) {
			try {
				return caseDb.getAttributeType(typeName);
			} catch (TskCoreException ex) {
				throw new BlackboardException("Failed to get or add attribute type", ex);
			}
		} catch (TskCoreException ex) {
			throw new BlackboardException("Failed to get or add attribute type", ex);
		}
	}

	/**
	 * Gets the list of all artifact types in use for the given data source.
	 * Gets both standard and custom types.
	 *
	 * @param dataSourceObjId data source object id
	 *
	 * @return The list of artifact types
	 *
	 * @throws TskCoreException exception thrown if a critical error occurred
	 *                          within tsk core
	 */
	public List<BlackboardArtifact.Type> getArtifactTypesInUse(long dataSourceObjId) throws TskCoreException {

		final String queryString = "SELECT DISTINCT arts.artifact_type_id AS artifact_type_id, "
				+ "types.type_name AS type_name, "
				+ "types.display_name AS display_name, "
				+ "types.category_type AS category_type "
				+ "FROM blackboard_artifact_types AS types "
				+ "INNER JOIN blackboard_artifacts AS arts "
				+ "ON arts.artifact_type_id = types.artifact_type_id "
				+ "WHERE arts.data_source_obj_id = " + dataSourceObjId;

		caseDb.acquireSingleUserCaseReadLock();
		try (SleuthkitCase.CaseDbConnection connection = caseDb.getConnection();
				Statement statement = connection.createStatement();
				ResultSet resultSet = connection.executeQuery(statement, queryString);) {

			List<BlackboardArtifact.Type> uniqueArtifactTypes = new ArrayList<>();
			while (resultSet.next()) {
				uniqueArtifactTypes.add(new BlackboardArtifact.Type(resultSet.getInt("artifact_type_id"),
						resultSet.getString("type_name"), resultSet.getString("display_name"),
						BlackboardArtifact.Category.fromID(resultSet.getInt("category_type"))));
			}
			return uniqueArtifactTypes;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting artifact types is use for data source." + ex.getMessage(), ex);
		} finally {
			caseDb.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get count of all blackboard artifacts of a given type for the given data
	 * source. Does not include rejected artifacts.
	 *
	 * @param artifactTypeID  artifact type id (must exist in database)
	 * @param dataSourceObjId data source object id
	 *
	 * @return count of blackboard artifacts
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	public long getArtifactsCount(int artifactTypeID, long dataSourceObjId) throws TskCoreException {
		return getArtifactsCountHelper(artifactTypeID,
				"blackboard_artifacts.data_source_obj_id = '" + dataSourceObjId + "';");
	}

	/**
	 * Get all blackboard artifacts of a given type. Does not included rejected
	 * artifacts.
	 *
	 * @param artifactTypeID  artifact type to get
	 * @param dataSourceObjId data source to look under
	 *
	 * @return list of blackboard artifacts
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	public List<BlackboardArtifact> getArtifacts(int artifactTypeID, long dataSourceObjId) throws TskCoreException {
		String whereClause = String.format("artifacts.data_source_obj_id = %d", dataSourceObjId);
		return getArtifactsWhere(caseDb.getArtifactType(artifactTypeID), whereClause);
	}

	/**
	 * Get all blackboard artifacts of the given type(s) for the given data
	 * source(s). Does not included rejected artifacts.
	 *
	 * @param artifactTypes    list of artifact types to get
	 * @param dataSourceObjIds data sources to look under
	 *
	 * @return list of blackboard artifacts
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	public List<BlackboardArtifact> getArtifacts(Collection<BlackboardArtifact.Type> artifactTypes,
			Collection<Long> dataSourceObjIds) throws TskCoreException {

		if (artifactTypes.isEmpty() || dataSourceObjIds.isEmpty()) {
			return new ArrayList<>();
		}

		String analysisResultQuery = "";
		String dataArtifactQuery = "";

		for (BlackboardArtifact.Type type : artifactTypes) {
			if (type.getCategory() == BlackboardArtifact.Category.ANALYSIS_RESULT) {
				if (!analysisResultQuery.isEmpty()) {
					analysisResultQuery += " OR ";
				}
				analysisResultQuery += "types.artifact_type_id = " + type.getTypeID();
			} else {
				if (!dataArtifactQuery.isEmpty()) {
					dataArtifactQuery += " OR ";
				}
				dataArtifactQuery += "types.artifact_type_id = " + type.getTypeID();
			}
		}

		String dsQuery = "";
		for (long dsId : dataSourceObjIds) {
			if (!dsQuery.isEmpty()) {
				dsQuery += " OR ";
			}
			dsQuery += "artifacts.data_source_obj_id = " + dsId;
		}

		List<BlackboardArtifact> artifacts = new ArrayList<>();

		if (!analysisResultQuery.isEmpty()) {
			String fullQuery = "( " + analysisResultQuery + " ) AND (" + dsQuery + ") ";
			artifacts.addAll(this.getAnalysisResultsWhere(fullQuery));
		}

		if (!dataArtifactQuery.isEmpty()) {
			String fullQuery = "( " + dataArtifactQuery + " ) AND (" + dsQuery + ") ";
			artifacts.addAll(this.getDataArtifactsWhere(fullQuery));
		}

		return artifacts;
	}

	/**
	 * Gets count of blackboard artifacts of given type that match a given WHERE
	 * clause. Uses a SELECT COUNT(*) FROM blackboard_artifacts statement
	 *
	 * @param artifactTypeID artifact type to count
	 * @param whereClause    The WHERE clause to append to the SELECT statement.
	 *
	 * @return A count of matching BlackboardArtifact .
	 *
	 * @throws TskCoreException If there is a problem querying the case
	 *                          database.
	 */
	private long getArtifactsCountHelper(int artifactTypeID, String whereClause) throws TskCoreException {
		String queryString = "SELECT COUNT(*) AS count FROM blackboard_artifacts "
				+ "WHERE blackboard_artifacts.artifact_type_id = " + artifactTypeID
				+ " AND blackboard_artifacts.review_status_id !=" + BlackboardArtifact.ReviewStatus.REJECTED.getID()
				+ " AND " + whereClause;

		caseDb.acquireSingleUserCaseReadLock();
		try (SleuthkitCase.CaseDbConnection connection = caseDb.getConnection();
				Statement statement = connection.createStatement();
				ResultSet resultSet = connection.executeQuery(statement, queryString);) {
			//NON-NLS	
			long count = 0;
			if (resultSet.next()) {
				count = resultSet.getLong("count");
			}
			return count;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting artifact types is use for data source." + ex.getMessage(), ex);
		} finally {
			caseDb.releaseSingleUserCaseReadLock();
		}
	}

	/*
	 * Determine if an artifact of a given type exists for given content with a
	 * specific list of attributes.
	 *
	 * @param content The content whose artifacts need to be looked at. @param
	 * artifactType The type of artifact to look for. @param attributesList The
	 * list of attributes to look for.
	 *
	 * @return True if the specific artifact exists; otherwise false.
	 *
	 * @throws TskCoreException If there is a problem getting artifacts or
	 * attributes.
	 */
	public boolean artifactExists(Content content, BlackboardArtifact.ARTIFACT_TYPE artifactType,
			Collection<BlackboardAttribute> attributesList) throws TskCoreException {

		ArrayList<BlackboardArtifact> artifactsList;

		/*
		 * Get the content's artifacts.
		 */
		artifactsList = content.getArtifacts(artifactType);
		if (artifactsList.isEmpty()) {
			return false;
		}

		/*
		 * Get each artifact's attributes and analyze them for matches.
		 */
		for (BlackboardArtifact artifact : artifactsList) {
			if (attributesMatch(artifact.getAttributes(), attributesList)) {
				/*
				 * The exact artifact exists, so we don't need to look any
				 * further.
				 */
				return true;
			}
		}

		/*
		 * None of the artifacts have the exact set of attribute type/value
		 * combinations. The provided content does not have the artifact being
		 * sought.
		 */
		return false;
	}

	/**
	 * Determine if the expected attributes can all be found in the supplied
	 * file attributes list.
	 *
	 * @param fileAttributesList     The list of attributes to analyze.
	 * @param expectedAttributesList The list of attribute to check for.
	 *
	 * @return True if all attributes are found; otherwise false.
	 */
	private boolean attributesMatch(Collection<BlackboardAttribute> fileAttributesList, Collection<BlackboardAttribute> expectedAttributesList) {
		for (BlackboardAttribute expectedAttribute : expectedAttributesList) {
			boolean match = false;
			for (BlackboardAttribute fileAttribute : fileAttributesList) {
				BlackboardAttribute.Type attributeType = fileAttribute.getAttributeType();
				if (attributeType.getTypeID() != expectedAttribute.getAttributeType().getTypeID()) {
					continue;
				}

				Object fileAttributeValue;
				Object expectedAttributeValue;
				switch (attributeType.getValueType()) {
					case BYTE:
						fileAttributeValue = fileAttribute.getValueBytes();
						expectedAttributeValue = expectedAttribute.getValueBytes();
						break;
					case DOUBLE:
						fileAttributeValue = fileAttribute.getValueDouble();
						expectedAttributeValue = expectedAttribute.getValueDouble();
						break;
					case INTEGER:
						fileAttributeValue = fileAttribute.getValueInt();
						expectedAttributeValue = expectedAttribute.getValueInt();
						break;
					case LONG: // Fall-thru
					case DATETIME:
						fileAttributeValue = fileAttribute.getValueLong();
						expectedAttributeValue = expectedAttribute.getValueLong();
						break;
					case STRING: // Fall-thru
					case JSON:
						fileAttributeValue = fileAttribute.getValueString();
						expectedAttributeValue = expectedAttribute.getValueString();
						break;
					default:
						fileAttributeValue = fileAttribute.getDisplayString();
						expectedAttributeValue = expectedAttribute.getDisplayString();
						break;
				}

				/*
				 * If the exact attribute was found, mark it as a match to
				 * continue looping through the expected attributes list.
				 */
				if (fileAttributeValue instanceof byte[]) {
					if (Arrays.equals((byte[]) fileAttributeValue, (byte[]) expectedAttributeValue)) {
						match = true;
						break;
					}
				} else if (fileAttributeValue.equals(expectedAttributeValue)) {
					match = true;
					break;
				}
			}
			if (!match) {
				/*
				 * The exact attribute type/value combination was not found.
				 */
				return false;
			}
		}

		/*
		 * All attribute type/value combinations were found in the provided
		 * attributes list.
		 */
		return true;

	}

	/**
	 * A Blackboard exception.
	 */
	public static final class BlackboardException extends Exception {

		private static final long serialVersionUID = 1L;

		/**
		 * Constructs a blackboard exception with the specified message.
		 *
		 * @param message The message.
		 */
		BlackboardException(String message) {
			super(message);
		}

		/**
		 * Constructs a blackboard exception with the specified message and
		 * cause.
		 *
		 * @param message The message.
		 * @param cause   The cause.
		 */
		BlackboardException(String message, Throwable cause) {
			super(message, cause);
		}
	}

	/**
	 * Add a new data artifact with the given type.
	 *
	 * @param artifactType    The type of the data artifact.
	 * @param sourceObjId     The content that is the source of this artifact.
	 * @param dataSourceObjId The data source the artifact source content
	 *                        belongs to, may be the same as the sourceObjId.
	 *                        May be null.
	 * @param attributes      The attributes. May be empty or null.
	 * @param osAccountId     The OS account id associated with the artifact.
	 *                        May be null.
	 *
	 * @return DataArtifact A new data artifact.
	 *
	 * @throws TskCoreException If a critical error occurs within tsk core.
	 */
	public DataArtifact newDataArtifact(BlackboardArtifact.Type artifactType, long sourceObjId, Long dataSourceObjId,
			Collection<BlackboardAttribute> attributes, Long osAccountId) throws TskCoreException {

		if (artifactType.getCategory() != BlackboardArtifact.Category.DATA_ARTIFACT) {
			throw new TskCoreException(String.format("Artifact type (name = %s) is not of Data Artifact category. ", artifactType.getTypeName()));
		}

		CaseDbTransaction transaction = caseDb.beginTransaction();
		try {
			DataArtifact dataArtifact = newDataArtifact(artifactType, sourceObjId, dataSourceObjId,
					attributes, osAccountId, transaction);
			transaction.commit();
			return dataArtifact;
		} catch (TskCoreException ex) {
			try {
				transaction.rollback();
			} catch (TskCoreException ex2) {
				LOGGER.log(Level.SEVERE, "Failed to rollback transaction after exception. "
						+ "Error invoking newDataArtifact with dataSourceObjId: " + dataSourceObjId + ",  sourceObjId: " + sourceObjId, ex2);
			}
			throw ex;
		}
	}

	/**
	 * Add a new data artifact with the given type.
	 *
	 * This api executes in the context of the given transaction.
	 *
	 * @param artifactType    The type of the data artifact.
	 * @param sourceObjId     The content that is the source of this artifact.
	 * @param dataSourceObjId The data source the artifact source content
	 *                        belongs to, may be the same as the sourceObjId.
	 *                        May be null.
	 * @param attributes      The attributes. May be empty or null.
	 * @param osAccountObjId  The OS account associated with the artifact. May
	 *                        be null.
	 * @param transaction     The transaction in the scope of which the
	 *                        operation is to be performed.
	 *
	 * @return DataArtifact New blackboard artifact
	 *
	 * @throws TskCoreException If a critical error occurs within tsk core.
	 */
	public DataArtifact newDataArtifact(BlackboardArtifact.Type artifactType, long sourceObjId, Long dataSourceObjId,
			Collection<BlackboardAttribute> attributes, Long osAccountObjId, final CaseDbTransaction transaction) throws TskCoreException {

		if (artifactType.getCategory() != BlackboardArtifact.Category.DATA_ARTIFACT) {
			throw new TskCoreException(String.format("Artifact type (name = %s) is not of Data Artifact category. ", artifactType.getTypeName()));
		}

		try {
			CaseDbConnection connection = transaction.getConnection();
			long artifact_obj_id = caseDb.addObject(sourceObjId, TskData.ObjectType.ARTIFACT.getObjectType(), connection);
			PreparedStatement statement = caseDb.createInsertArtifactStatement(artifactType.getTypeID(), sourceObjId, artifact_obj_id, dataSourceObjId, connection);

			connection.executeUpdate(statement);
			try (ResultSet resultSet = statement.getGeneratedKeys()) {
				resultSet.next();
				DataArtifact dataArtifact = new DataArtifact(caseDb, resultSet.getLong(1), //last_insert_rowid()
						sourceObjId, artifact_obj_id, dataSourceObjId, artifactType.getTypeID(),
						artifactType.getTypeName(), artifactType.getDisplayName(), BlackboardArtifact.ReviewStatus.UNDECIDED,
						osAccountObjId, true);

				// Add a row in tsk_data_artifact if the os account is present
				if (osAccountObjId != null) {
					String insertDataArtifactSQL = "INSERT INTO tsk_data_artifacts (artifact_obj_id, os_account_obj_id) VALUES (?, ?)";

					statement = connection.getPreparedStatement(insertDataArtifactSQL, Statement.NO_GENERATED_KEYS);
					statement.clearParameters();

					statement.setLong(1, artifact_obj_id);
					statement.setLong(2, osAccountObjId);
					connection.executeUpdate(statement);
				}

				// if attributes are provided, add them to the artifact.
				if (Objects.nonNull(attributes) && !attributes.isEmpty()) {
					dataArtifact.addAttributes(attributes, transaction);
				}

				return dataArtifact;
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error creating a data artifact with type id = %d, objId = %d, and data source oj id = %d ", artifactType.getTypeID(), sourceObjId, dataSourceObjId), ex);
		}
	}

	/**
	 * Returns a list of BlackboardArtifacts of the given artifact type and
	 * source object id.
	 *
	 * @param artifactType The artifact type.
	 * @param sourceObjId  The artifact parent source id (obj_id)
	 *
	 * @return A list of BlackboardArtifacts for the given parameters.
	 *
	 * @throws TskCoreException
	 */
	List<BlackboardArtifact> getArtifactsBySourceId(BlackboardArtifact.Type artifactType, long sourceObjId) throws TskCoreException {
		String whereClause = String.format("artifacts.obj_id = %d", sourceObjId);
		return getArtifactsWhere(artifactType, whereClause);
	}

	/**
	 * Returns a list of artifacts of the given type.
	 *
	 * @param artifactType The type of artifacts to retrieve.
	 *
	 * @return A list of artifacts of the given type.
	 *
	 * @throws TskCoreException
	 */
	List<BlackboardArtifact> getArtifactsByType(BlackboardArtifact.Type artifactType) throws TskCoreException {
		List<BlackboardArtifact> artifacts = new ArrayList<>();
		if (artifactType.getCategory() == BlackboardArtifact.Category.ANALYSIS_RESULT) {
			artifacts.addAll(getAnalysisResultsByType(artifactType.getTypeID()));
		} else {
			artifacts.addAll(getDataArtifacts(artifactType.getTypeID()));
		}
		return artifacts;
	}

	/**
	 * Returns a list of artifacts for the given artifact type with the given
	 * where clause.
	 *
	 * The Where clause will be added to the basic query for retrieving
	 * DataArtifacts or AnalysisResults from the DB. The where clause should not
	 * include the artifact type. This method will add the artifact type to the
	 * where clause.
	 *
	 * @param artifactType The artifact type.
	 * @param whereClause  Additional where clause.
	 *
	 * @return A list of BlackboardArtifacts of the given type with the given
	 *         conditional.
	 *
	 * @throws TskCoreException
	 */
	private List<BlackboardArtifact> getArtifactsWhere(BlackboardArtifact.Type artifactType, String whereClause) throws TskCoreException {
		List<BlackboardArtifact> artifacts = new ArrayList<>();
		String whereWithType = whereClause + " AND artifacts.artifact_type_id = " + artifactType.getTypeID();

		if (artifactType.getCategory() == BlackboardArtifact.Category.ANALYSIS_RESULT) {
			artifacts.addAll(getAnalysisResultsWhere(whereWithType));
		} else {
			artifacts.addAll(getDataArtifactsWhere(whereWithType));
		}

		return artifacts;
	}

	/**
	 * Event published by SleuthkitCase when one or more artifacts are posted. A
	 * posted artifact is complete (all attributes have been added) and ready
	 * for further processing.
	 */
	final public class ArtifactsPostedEvent {

		private final String moduleName;
		private final ImmutableSet<BlackboardArtifact.Type> artifactTypes;
		private final ImmutableSet<BlackboardArtifact> artifacts;

		private ArtifactsPostedEvent(Collection<BlackboardArtifact> artifacts, String moduleName) throws BlackboardException {
			Set<Integer> typeIDS = artifacts.stream()
					.map(BlackboardArtifact::getArtifactTypeID)
					.collect(Collectors.toSet());
			Set<BlackboardArtifact.Type> types = new HashSet<>();
			for (Integer typeID : typeIDS) {
				try {
					types.add(caseDb.getArtifactType(typeID));
				} catch (TskCoreException tskCoreException) {
					throw new BlackboardException("Error getting artifact type by id.", tskCoreException);
				}
			}
			artifactTypes = ImmutableSet.copyOf(types);
			this.artifacts = ImmutableSet.copyOf(artifacts);
			this.moduleName = moduleName;

		}

		public Collection<BlackboardArtifact> getArtifacts() {
			return ImmutableSet.copyOf(artifacts);
		}

		public Collection<BlackboardArtifact> getArtifacts(BlackboardArtifact.Type artifactType) {
			Set<BlackboardArtifact> tempSet = artifacts.stream()
					.filter(artifact -> artifact.getArtifactTypeID() == artifactType.getTypeID())
					.collect(Collectors.toSet());
			return ImmutableSet.copyOf(tempSet);
		}

		public String getModuleName() {
			return moduleName;
		}

		public Collection<BlackboardArtifact.Type> getArtifactTypes() {
			return ImmutableSet.copyOf(artifactTypes);
		}
	}
}
