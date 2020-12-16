/*
 * Sleuth Kit Data Model
 *
 * Copyright 2018-2020 Basis Technology Corp.
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
import java.util.stream.Collectors;
import java.util.logging.Logger;
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
	 * This assumes that the artifact type is of category EXTRACTED_DATA.
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

		return getOrAddArtifactType(typeName, displayName, BlackboardArtifact.Category.EXTRACTED_DATA);
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
	 * @param dataSourceObjId Data source object id.
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
	* @return AnalysisResultAdded The analysis return added and the
         current aggregate score of content.
	 *
	 * @throws BlackboardException exception thrown if a critical error occurs
	 *                             within TSK core
	 */
	public AnalysisResultAdded newAnalysisResult(BlackboardArtifact.Type artifactType, long objId, long dataSourceObjId, Score score, String conclusion, String configuration, String justification, Collection<BlackboardAttribute> attributesList, CaseDbTransaction transaction) throws BlackboardException {
		
		try {
			// add analysis result
			AnalysisResult analysisResult =  caseDb.newAnalysisResult(artifactType, objId, dataSourceObjId, score, conclusion, configuration, justification, transaction.getConnection());
			
			// add the given attributes
			if (attributesList != null && !attributesList.isEmpty()) {
				analysisResult.addAttributes(attributesList, transaction);
			}
			
			// update the final score for the object 
			Score aggregateScore = caseDb.getScoringManager().updateAggregateScore(objId, dataSourceObjId, analysisResult.getScore(), transaction);
			
			// return the analysis result and the current aggregate score.
			return new AnalysisResultAdded(analysisResult, aggregateScore);
			
		}  catch (TskCoreException ex) {
			throw new BlackboardException("Failed to add analysis result.", ex);
		}
	}
	
	private final static String ANALYSIS_RESULT_QUERY_STRING = "SELECT DISTINCT arts.artifact_id AS artifact_id, " //NON-NLS
				+ "arts.obj_id AS obj_id, arts.artifact_obj_id AS artifact_obj_id, arts.data_source_obj_id AS data_source_obj_id, arts.artifact_type_id AS artifact_type_id, "
				+ " types.type_name AS type_name, types.display_name AS display_name, types.category_type as category_type,"//NON-NLS
				+ " arts.review_status_id AS review_status_id, " //NON-NLS
				+ " results.conclusion AS conclusion,  results.significance AS significance,  results.confidence AS confidence,  "
				+ " results.configuration AS configuration,  results.justification AS justification "
				+ " FROM blackboard_artifacts AS arts, tsk_analysis_results AS results, blackboard_artifact_types AS types " //NON-NLS
				+ " WHERE arts.artifact_obj_id = results.obj_id " //NON-NLS
				+ " AND arts.artifact_type_id = types.artifact_type_id"
				+ " AND arts.review_status_id !=" + BlackboardArtifact.ReviewStatus.REJECTED.getID();

	/**
	 * Get all analysis results for a given object.
	 *
	 * @param objId Object id.
	
	 * @return list of analysis results.
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core.
	 */
	public List<AnalysisResult> getAnalysisResults(long objId) throws TskCoreException {
		return getAnalysisResultsWhere(" arts.obj_id = " + objId);
	}
	
	/**
	 * Get analysis results of the given type, for the given object.
	 *
	 * @param objId Object id.
	 * @param artifactTypeId Result type to get.
	
	 * @return list of analysis results.
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core.
	 */
	public List<AnalysisResult> getAnalysisResults(long objId, int artifactTypeId) throws TskCoreException {
		
		BlackboardArtifact.Type artifactType = new BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.fromID(artifactTypeId));
		if (artifactType.getCategory() != BlackboardArtifact.Category.ANALYSIS_RESULT) {
			throw new TskCoreException(String.format("Artifact type id %d is not in analysis result catgeory.", artifactTypeId));
		}
		
		String whereClause = " types.artifact_type_id = " + artifactTypeId
							 + " AND arts.obj_id = " + objId; 
		
		return getAnalysisResultsWhere(whereClause);
	}
	
	/**
	 * Get all analysis results of a given type, for a given data source.
	 *
	 * @param dataSourceObjId Data source to look under.
	 * @param artifactTypeId  Type of results to get.
	 *
	 * @return list of analysis results.
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core.
	 */

// To keep the public API footprint minimal and necessary, this API is commented out 
// till Autopsy implements and intgerates the concept of AnalysisResults. 
// At that time, this api could be uncommented or deleted if it is not needed.
	
//	public List<AnalysisResult> getAnalysisResultsForDataSource(long dataSourceObjId, int artifactTypeId) throws TskCoreException {
//		
//		BlackboardArtifact.Type artifactType = new BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.fromID(artifactTypeId));
//		if (artifactType.getCategory() != BlackboardArtifact.Category.ANALYSIS_RESULT) {
//			throw new TskCoreException(String.format("Artifact type id %d is not in analysis result catgeory.", artifactTypeId));
//		}
//
//		String whereClause = " types.artifact_type_id = " + artifactTypeId
//				+ " AND arts.data_source_obj_id = " + dataSourceObjId;  // NON-NLS
//		
//		return getAnalysisResultsWhere(whereClause);
//	}
	
	/**
	 * Get all analysis results matching the given where sub-clause.
	 * 
	 *
	 * @param whereClause Where sub clause, specifies conditions to match.  
	 * @return list of analysis results.
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core.
	 */
	public List<AnalysisResult> getAnalysisResultsWhere(String whereClause) throws TskCoreException {
		
		try (CaseDbConnection connection = caseDb.getConnection()) {
			return getAnalysisResultsWhere(whereClause, connection);
		}
	}
	/**
	 * Get all analysis results matching the given where sub-clause.
	 * Uses the given database connection to execute the query.
	 *
	 * @param whereClause Where sub clause, specifies conditions to match.  
	 * @param connection Database connection to use. 
	 * 
	 * @return list of analysis results.
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	List<AnalysisResult> getAnalysisResultsWhere(String whereClause, CaseDbConnection connection) throws TskCoreException {

		final String queryString = ANALYSIS_RESULT_QUERY_STRING
				+ " AND " + whereClause;
							
		caseDb.acquireSingleUserCaseReadLock();
		try (	Statement statement = connection.createStatement();
				ResultSet resultSet = connection.executeQuery(statement, queryString);) {
			
			List<AnalysisResult> analysisResults = resultSetToAnalysisResults(resultSet);
			return analysisResults;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting analysis results for WHERE caluse = '%s'", whereClause), ex);
		} finally {
			caseDb.releaseSingleUserCaseReadLock();
		}
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
					resultSet.getLong("artifact_obj_id"), resultSet.getLong("data_source_obj_id"),
					resultSet.getInt("artifact_type_id"), resultSet.getString("type_name"), resultSet.getString("display_name"),
					BlackboardArtifact.ReviewStatus.withID(resultSet.getInt("review_status_id")),
					new Score(Score.Significance.fromID(resultSet.getInt("significance")), Score.Confidence.fromID(resultSet.getInt("confidence"))),
					resultSet.getString("conclusion"), resultSet.getString("configuration"), resultSet.getString("justification")));
		} //end for each resultSet

		return analysisResults;
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
				+ "types.type_name AS type_name, types.display_name AS display_name "
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
						resultSet.getString("type_name"), resultSet.getString("display_name")));
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
		return caseDb.getArtifactsHelper("blackboard_artifacts.data_source_obj_id = " + dataSourceObjId
				+ " AND blackboard_artifact_types.artifact_type_id = " + artifactTypeID + ";");
	}
	
	/**
	 * Get all blackboard artifacts of the given type(s) for the given data source(s). Does not included rejected
	 * artifacts.
	 *
	 * @param artifactTypes  list of artifact types to get
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
		
		String typeQuery = "";
		for (BlackboardArtifact.Type type : artifactTypes) {
			if (!typeQuery.isEmpty()) {
				typeQuery += " OR ";
			}
			typeQuery += "blackboard_artifact_types.artifact_type_id = " + type.getTypeID();
		}
		
		String dsQuery = "";
		for (long dsId : dataSourceObjIds) {
			if (!dsQuery.isEmpty()) {
				dsQuery += " OR ";
			}
			dsQuery += "blackboard_artifacts.data_source_obj_id = " + dsId;
		}
		
		String fullQuery = "( " + typeQuery + " ) AND ( " + dsQuery + " );";
		
		return caseDb.getArtifactsHelper(fullQuery);
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
	 * Add a new blackboard artifact with the given type.
	 *
	 * This api executes in the context of a transaction if one is provided.
	 *
	 * @param artifactType    The type of the artifact.
	 * @param sourceObjId     The content that is the source of this artifact.
	 * @param dataSourceObjId The data source the artifact source content
	 *                        belongs to, may be the same as the sourceObjId.
	 * @param attributes      The attributes. May be empty or null. 
	 * @param transaction     The transaction in the scope of which the
	 *                        operation is to be performed. Null may be
	 *                        provided, if one is not available. 
	 *
	 * @return a new blackboard artifact
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within tsk core
	 */
	public BlackboardArtifact newBlackboardArtifact(BlackboardArtifact.Type artifactType, long sourceObjId, long dataSourceObjId,
			Collection<BlackboardAttribute> attributes, final CaseDbTransaction transaction) throws TskCoreException {

	    CaseDbTransaction localTrans = null;
		boolean isNewLocalTx = false;
		if (transaction == null) {
			localTrans = caseDb.beginTransaction();
			isNewLocalTx = true;
		}else {
			localTrans = transaction;
		}

		try {
			BlackboardArtifact blackboardArtifact = caseDb.newBlackboardArtifact(artifactType.getTypeID(), sourceObjId,
					artifactType.getTypeName(), artifactType.getDisplayName(),
					dataSourceObjId, localTrans.getConnection());

			if (Objects.nonNull(attributes) && !attributes.isEmpty()) {
				blackboardArtifact.addAttributes(attributes, localTrans);
			}

			if (isNewLocalTx) {
				localTrans.commit();
			}
			return blackboardArtifact;

		} catch (TskCoreException ex) {
			try {
				if (isNewLocalTx) {
					localTrans.rollback();
				}
			} catch (TskCoreException ex2) {
				LOGGER.log(Level.SEVERE, "Failed to rollback transaction after exception. "
						+ "Error invoking newBlackboardArtifact with dataSourceObjId: " + dataSourceObjId + ",  sourceObjId: " + sourceObjId, ex2);
			}
			throw ex;
		}
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
			return artifacts;
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
			return artifactTypes;
		}
	}
}
