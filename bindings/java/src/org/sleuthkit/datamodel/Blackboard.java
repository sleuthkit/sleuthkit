/*
 * Sleuth Kit Data Model
 *
 * Copyright 2018 Basis Technology Corp.
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

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

/**
 * A representation of the blackboard, a place where artifacts and their
 * attributes are posted.
 *
 */
public final class Blackboard {

	private final SleuthkitCase caseDb;

	/**
	 * Constructs a representation of the blackboard, a place where artifacts
	 * and their attributes are posted.
	 *
	 * @param casedb The case database.
	 */
	Blackboard(SleuthkitCase casedb) {
		this.caseDb = casedb;
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

		SleuthkitCase.CaseDbConnection connection = caseDb.getConnection();
		caseDb.acquireSingleUserCaseReadLock();
		Statement statement = null;
		ResultSet resultSet = null;
		try {
			statement = connection.createStatement();
			resultSet = connection.executeQuery(statement, queryString); //NON-NLS

			List<BlackboardArtifact.Type> uniqueArtifactTypes = new ArrayList<BlackboardArtifact.Type>();
			while (resultSet.next()) {
				uniqueArtifactTypes.add(new BlackboardArtifact.Type(resultSet.getInt("artifact_type_id"),
						resultSet.getString("type_name"), resultSet.getString("display_name")));
			}
			return uniqueArtifactTypes;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting artifact types is use for data source." + ex.getMessage(), ex);
		} finally {
			SleuthkitCase.closeResultSet(resultSet);
			SleuthkitCase.closeStatement(statement);
			connection.close();
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

		SleuthkitCase.CaseDbConnection connection = caseDb.getConnection();
		caseDb.acquireSingleUserCaseReadLock();
		Statement statement = null;
		ResultSet resultSet = null;

		try {
			statement = connection.createStatement();
			resultSet = connection.executeQuery(statement, queryString); //NON-NLS	
			long count = 0;
			if (resultSet.next()) {
				count = resultSet.getLong("count");
			}
			return count;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting artifact types is use for data source." + ex.getMessage(), ex);
		} finally {
			SleuthkitCase.closeResultSet(resultSet);
			SleuthkitCase.closeStatement(statement);
			connection.close();
			caseDb.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Determine if an artifact of a given type exists for given content with a
	 * specific list of attributes.
	 *
	 * @param content                  The content whose artifacts need to be
	 *                                 looked at.
	 * @param artifactType             The type of artifact to look for.
	 * @param expectedAttributesList   The list of attributes expected to be
	 *                                 found in a match.
	 *
	 * @return True if the specific artifact exists; otherwise false.
	 *
	 * @throws TskCoreException If there is a problem getting artifacts or
	 *                          attributes.
	 */
	public boolean artifactExists(Content content, BlackboardArtifact.ARTIFACT_TYPE artifactType,
			Collection<BlackboardAttribute> expectedAttributesList) throws TskCoreException {
		return artifactExists(content, artifactType, expectedAttributesList, new ArrayList<BlackboardAttribute>());
	}

	/**
	 * Determine if an artifact of a given type exists for given content with a
	 * specific list of attributes.
	 *
	 * @param content                  The content whose artifacts need to be
	 *                                 looked at.
	 * @param artifactType             The type of artifact to look for.
	 * @param expectedAttributesList   The list of attributes expected to be
	 *                                 found in a match.
	 * @param unexpectedAttributesList The list of attributes not expecting to
	 *                                 be found in a match.
	 *
	 * @return True if the specific artifact exists; otherwise false.
	 *
	 * @throws TskCoreException If there is a problem getting artifacts or
	 *                          attributes.
	 */
	public boolean artifactExists(Content content, BlackboardArtifact.ARTIFACT_TYPE artifactType,
			Collection<BlackboardAttribute> expectedAttributesList, Collection<BlackboardAttribute> unexpectedAttributesList) throws TskCoreException {

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
			if (attributesMatch(artifact.getAttributes(), expectedAttributesList, unexpectedAttributesList)) {
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
	 * @param fileAttributesList       The list of attributes to analyze.
	 * @param expectedAttributesList   The list of attributes expected to be
	 *                                 found in a match.
	 * @param unexpectedAttributesList The list of attributes not expecting to
	 *                                 be found in a match.
	 *
	 * @return True if all attributes are found; otherwise false.
	 */
	private boolean attributesMatch(Collection<BlackboardAttribute> fileAttributesList,
			Collection<BlackboardAttribute> expectedAttributesList, Collection<BlackboardAttribute> unexpectedAttributesList) {

		/*
		 * Check for attributes we expect to find in the file.
		 */
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
					case STRING:
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
		 * Check for attributes we expect to not find in the file.
		 */
		for (BlackboardAttribute unexpectedAttribute : unexpectedAttributesList) {
			for (BlackboardAttribute fileAttribute : fileAttributesList) {
				BlackboardAttribute.Type attributeType = fileAttribute.getAttributeType();

				if (attributeType.getTypeID() == unexpectedAttribute.getAttributeType().getTypeID()) {
					/*
					 * An artifact type was found in the file that was expected
					 * to not be found. Therefore, this is not a match.
					 */
					return false;
				}
			}
		}

		/*
		 * All attribute type/value combinations were found in the provided
		 * attributes list.
		 */
		return true;
	}
}
