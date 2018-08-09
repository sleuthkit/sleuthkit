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
	 * Posts the artifact. The artifact should be complete (all attributes have
	 * been added) before being posted. Posting the artifact includes making any
	 * events that may be derived from it, and broadcasting a notification that
	 * the artifact is ready for further analysis.
	 *
	 * @param artifact The artifact to be posted.
	 *
	 * @throws BlackboardException If there is a problem posting the artifact.
	 */
	public synchronized void postArtifact(BlackboardArtifact artifact) throws BlackboardException {
		if (null == caseDb) {
			throw new BlackboardException("Blackboard has been closed");
		}

		try {
			caseDb.getTimelineManager().addEventsFromArtifact(artifact);
		} catch (TskCoreException ex) {
			throw new BlackboardException("Failed to add events for artifact: " + artifact, ex);
		}
		caseDb.postTSKEvent(new ArtifactPostedEvent(artifact));

	}

	/**
	 * Posts a Collection of artifacts. The artifacts should be complete (all
	 * attributes have been added) before being posted. Posting the artifacts
	 * includes making any events that may be derived from them, and
	 * broadcasting notifications that the artifacts are ready for further
	 * analysis.
	 *
	 * @param artifacts The artifacts to be posted.
	 *
	 * @throws BlackboardException If there is a problem posting the artifacts.
	 */
	public synchronized void postArtifacts(Collection<BlackboardArtifact> artifacts) throws BlackboardException {
		/*
		 * For now this just posts them one by one, but in the future it could
		 * be smarter and use transactions, post a single bulk event, etc.
		 */
		for (BlackboardArtifact artifact : artifacts) {
			postArtifact(artifact);
		}
	}

	/**
	 * Gets an artifact type, creating it if it does not already exist. Use this
	 * method to define custom artifact types.
	 *
	 * @param typeName    The type name of the artifact type.
	 * @param displayName The display name of the artifact type.
	 *
	 * @return A type object representing the artifact type.
	 *
	 * @throws BlackboardException If there is a problem getting or adding the
	 *                             artifact type.
	 */
	public synchronized BlackboardArtifact.Type getOrAddArtifactType(String typeName, String displayName) throws BlackboardException {
		if (null == caseDb) {
			throw new BlackboardException("Blackboard has been closed");
		}
		try {
			return caseDb.addBlackboardArtifactType(typeName, displayName);
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
	public synchronized BlackboardAttribute.Type getOrAddAttributeType(String typeName, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE valueType, String displayName) throws BlackboardException {
		if (null == caseDb) {
			throw new BlackboardException("Blackboard has been closed");
		}
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
	 * Event published by SleuthkitCase when an artifact is posted. A posted
	 * artifact is complete (all attributes have been added) and ready for
	 * further processing.
	 */
	final public static class ArtifactPostedEvent {

		private final BlackboardArtifact artifact;

		public BlackboardArtifact getArtifact() {
			return artifact;
		}

		ArtifactPostedEvent(BlackboardArtifact artifact) {
			this.artifact = artifact;
		}
	}
}
