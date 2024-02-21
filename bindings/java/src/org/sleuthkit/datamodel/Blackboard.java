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

import com.google.common.annotations.Beta;
import com.google.common.collect.ImmutableSet;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbConnection;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbTransaction;
import static org.sleuthkit.datamodel.SleuthkitCase.closeConnection;
import static org.sleuthkit.datamodel.SleuthkitCase.closeResultSet;
import static org.sleuthkit.datamodel.SleuthkitCase.closeStatement;

/**
 * A representation of the blackboard, a place where artifacts and their
 * attributes are posted.
 */
public final class Blackboard {

	private static final Logger LOGGER = Logger.getLogger(Blackboard.class.getName());

	/*
	 * ConcurrentHashMap semantics are fine for these caches to which entries
	 * are added, but never removed. There is also no need to keep each pair of
	 * related caches strictly consistent with each other, because cache misses
	 * will be extremely rare (standard types are loaded when the case is
	 * opened), and the cost of a cache miss is low.
	 */
	private final Map<Integer, BlackboardArtifact.Type> typeIdToArtifactTypeMap = new ConcurrentHashMap<>();
	private final Map<Integer, BlackboardAttribute.Type> typeIdToAttributeTypeMap = new ConcurrentHashMap<>();
	private final Map<String, BlackboardArtifact.Type> typeNameToArtifactTypeMap = new ConcurrentHashMap<>();
	private final Map<String, BlackboardAttribute.Type> typeNameToAttributeTypeMap = new ConcurrentHashMap<>();

	static final int MIN_USER_DEFINED_TYPE_ID = 10000;

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
	 * Posts an artifact to the blackboard. The artifact should be complete (all
	 * attributes have been added) before it is posted. Posting the artifact
	 * triggers the creation of appropriate timeline events, if any, and
	 * broadcast of a notification that the artifact is ready for further
	 * analysis.
	 *
	 * @param artifact   The artifact.
	 * @param moduleName The display name of the module posting the artifact.
	 *
	 * @throws BlackboardException The exception is thrown if there is an issue
	 *                             posting the artifact.
	 * @deprecated Use postArtifact(BlackboardArtifact artifact, String
	 * moduleName, Long ingestJobId) instead.
	 */
	@Deprecated
	public void postArtifact(BlackboardArtifact artifact, String moduleName) throws BlackboardException {
		postArtifacts(Collections.singleton(artifact), moduleName, null);
	}

	/**
	 * Posts a collection of artifacts to the blackboard. The artifacts should
	 * be complete (all attributes have been added) before they are posted.
	 * Posting the artifacts triggers the creation of appropriate timeline
	 * events, if any, and broadcast of a notification that the artifacts are
	 * ready for further analysis.
	 *
	 * @param artifacts  The artifacts.
	 * @param moduleName The display name of the module posting the artifacts.
	 *
	 * @throws BlackboardException The exception is thrown if there is an issue
	 *                             posting the artifact.
	 * @deprecated postArtifacts(Collection\<BlackboardArtifact\> artifacts,
	 * String moduleName, Long ingestJobId)
	 */
	@Deprecated
	public void postArtifacts(Collection<BlackboardArtifact> artifacts, String moduleName) throws BlackboardException {
		postArtifacts(artifacts, moduleName, null);
	}

	/**
	 * Posts an artifact to the blackboard. The artifact should be complete (all
	 * attributes have been added) before it is posted. Posting the artifact
	 * triggers the creation of appropriate timeline events, if any, and
	 * broadcast of a notification that the artifact is ready for further
	 * analysis.
	 *
	 * @param artifact    The artifact.
	 * @param moduleName  The display name of the module posting the artifact.
	 * @param ingestJobId The numeric identifier of the ingest job for which the
	 *                    artifact was posted, may be null.
	 *
	 * @throws BlackboardException The exception is thrown if there is an issue
	 *                             posting the artifact.
	 */
	public void postArtifact(BlackboardArtifact artifact, String moduleName, Long ingestJobId) throws BlackboardException {
		postArtifacts(Collections.singleton(artifact), moduleName, ingestJobId);
	}

	/**
	 * Posts a collection of artifacts to the blackboard. The artifacts should
	 * be complete (all attributes have been added) before they are posted.
	 * Posting the artifacts triggers the creation of appropriate timeline
	 * events, if any, and broadcast of a notification that the artifacts are
	 * ready for further analysis.
	 *
	 * @param artifacts   The artifacts.
	 * @param moduleName  The display name of the module posting the artifacts.
	 * @param ingestJobId The numeric identifier of the ingest job for which the
	 *                    artifacts were posted, may be null.
	 *
	 * @throws BlackboardException The exception is thrown if there is an issue
	 *                             posting the artifact.
	 */
	public void postArtifacts(Collection<BlackboardArtifact> artifacts, String moduleName, Long ingestJobId) throws BlackboardException {
		for (BlackboardArtifact artifact : artifacts) {
			try {
				caseDb.getTimelineManager().addArtifactEvents(artifact);
			} catch (TskCoreException ex) {
				throw new BlackboardException(String.format("Failed to add events to timeline for artifact '%s'", artifact), ex);
			}
		}
		caseDb.fireTSKEvent(new ArtifactsPostedEvent(artifacts, moduleName, ingestJobId));
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

		if (typeNameToArtifactTypeMap.containsKey(typeName)) {
			return typeNameToArtifactTypeMap.get(typeName);
		}

		Statement s = null;
		ResultSet rs = null;
		CaseDbTransaction trans = null;
		try {
			trans = caseDb.beginTransaction();

			CaseDbConnection connection = trans.getConnection();
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT artifact_type_id FROM blackboard_artifact_types WHERE type_name = '" + typeName + "'"); //NON-NLS
			if (!rs.next()) {
				rs.close();
				rs = connection.executeQuery(s, "SELECT MAX(artifact_type_id) AS highest_id FROM blackboard_artifact_types");
				int maxID = 0;
				if (rs.next()) {
					maxID = rs.getInt("highest_id");
					if (maxID < MIN_USER_DEFINED_TYPE_ID) {
						maxID = MIN_USER_DEFINED_TYPE_ID;
					} else {
						maxID++;
					}
				}
				connection.executeUpdate(s, "INSERT INTO blackboard_artifact_types (artifact_type_id, type_name, display_name, category_type) VALUES ('" + maxID + "', '" + typeName + "', '" + displayName + "', " + category.getID() + " )"); //NON-NLS
				BlackboardArtifact.Type type = new BlackboardArtifact.Type(maxID, typeName, displayName, category);
				this.typeIdToArtifactTypeMap.put(type.getTypeID(), type);
				this.typeNameToArtifactTypeMap.put(type.getTypeName(), type);
				trans.commit();
				trans = null;
				return type;
			} else {
				trans.commit();
				trans = null;
				try {
					return getArtifactType(typeName);
				} catch (TskCoreException ex) {
					throw new BlackboardException("Failed to get or add artifact type: " + typeName, ex);
				}
			}
		} catch (SQLException | TskCoreException ex) {
			try {
				if (trans != null) {
					trans.rollback();
					trans = null;
				}
			} catch (TskCoreException ex2) {
				LOGGER.log(Level.SEVERE, "Error rolling back transaction", ex2);
			}
			throw new BlackboardException("Error adding artifact type: " + typeName, ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			if (trans != null) {
				try {
					trans.rollback();
				} catch (TskCoreException ex) {
					throw new BlackboardException("Error rolling back transaction", ex);
				}
			}
		}
	}

	/**
	 * Get the attribute type associated with an attribute type name.
	 *
	 * @param attrTypeName An attribute type name.
	 *
	 * @return An attribute type or null if the attribute type does not exist.
	 *
	 * @throws TskCoreException If an error occurs accessing the case database.
	 *
	 */
	public BlackboardAttribute.Type getAttributeType(String attrTypeName) throws TskCoreException {
		if (this.typeNameToAttributeTypeMap.containsKey(attrTypeName)) {
			return this.typeNameToAttributeTypeMap.get(attrTypeName);
		}
		CaseDbConnection connection = null;
		Statement s = null;
		ResultSet rs = null;
		caseDb.acquireSingleUserCaseReadLock();
		try {
			connection = caseDb.getConnection();
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT attribute_type_id, type_name, display_name, value_type FROM blackboard_attribute_types WHERE type_name = '" + attrTypeName + "'"); //NON-NLS
			BlackboardAttribute.Type type = null;
			if (rs.next()) {
				type = new BlackboardAttribute.Type(rs.getInt("attribute_type_id"), rs.getString("type_name"),
						rs.getString("display_name"), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.fromType(rs.getLong("value_type")));
				this.typeIdToAttributeTypeMap.put(type.getTypeID(), type);
				this.typeNameToAttributeTypeMap.put(attrTypeName, type);
			}
			return type;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting attribute type id", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			closeConnection(connection);
			caseDb.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get the attribute type associated with an attribute type ID.
	 *
	 * @param typeID An attribute type ID.
	 *
	 * @return An attribute type or null if the attribute type does not exist.
	 *
	 * @throws TskCoreException If an error occurs accessing the case database.
	 *
	 */
	BlackboardAttribute.Type getAttributeType(int typeID) throws TskCoreException {
		if (this.typeIdToAttributeTypeMap.containsKey(typeID)) {
			return this.typeIdToAttributeTypeMap.get(typeID);
		}
		CaseDbConnection connection = null;
		Statement s = null;
		ResultSet rs = null;
		caseDb.acquireSingleUserCaseReadLock();
		try {
			connection = caseDb.getConnection();
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT attribute_type_id, type_name, display_name, value_type FROM blackboard_attribute_types WHERE attribute_type_id = " + typeID + ""); //NON-NLS
			BlackboardAttribute.Type type = null;
			if (rs.next()) {
				type = new BlackboardAttribute.Type(rs.getInt("attribute_type_id"), rs.getString("type_name"),
						rs.getString("display_name"), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.fromType(rs.getLong("value_type")));
				this.typeIdToAttributeTypeMap.put(typeID, type);
				this.typeNameToAttributeTypeMap.put(type.getTypeName(), type);
			}
			return type;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting attribute type id", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			closeConnection(connection);
			caseDb.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get the artifact type associated with an artifact type name.
	 *
	 * @param artTypeName An artifact type name.
	 *
	 * @return An artifact type or null if the artifact type does not exist.
	 *
	 * @throws TskCoreException If an error occurs accessing the case database.
	 *
	 */
	public BlackboardArtifact.Type getArtifactType(String artTypeName) throws TskCoreException {
		if (this.typeNameToArtifactTypeMap.containsKey(artTypeName)) {
			return this.typeNameToArtifactTypeMap.get(artTypeName);
		}
		CaseDbConnection connection = null;
		Statement s = null;
		ResultSet rs = null;
		caseDb.acquireSingleUserCaseReadLock();
		try {
			connection = caseDb.getConnection();
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT artifact_type_id, type_name, display_name, category_type FROM blackboard_artifact_types WHERE type_name = '" + artTypeName + "'"); //NON-NLS
			BlackboardArtifact.Type type = null;
			if (rs.next()) {
				type = new BlackboardArtifact.Type(rs.getInt("artifact_type_id"),
						rs.getString("type_name"), rs.getString("display_name"),
						BlackboardArtifact.Category.fromID(rs.getInt("category_type")));
				this.typeIdToArtifactTypeMap.put(type.getTypeID(), type);
				this.typeNameToArtifactTypeMap.put(artTypeName, type);
			}
			return type;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting artifact type from the database", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			closeConnection(connection);
			caseDb.releaseSingleUserCaseReadLock();
		}
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
		if (this.typeIdToArtifactTypeMap.containsKey(artTypeId)) {
			return typeIdToArtifactTypeMap.get(artTypeId);
		}
		CaseDbConnection connection = null;
		Statement s = null;
		ResultSet rs = null;
		caseDb.acquireSingleUserCaseReadLock();
		try {
			connection = caseDb.getConnection();
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT artifact_type_id, type_name, display_name, category_type FROM blackboard_artifact_types WHERE artifact_type_id = " + artTypeId + ""); //NON-NLS
			BlackboardArtifact.Type type = null;
			if (rs.next()) {
				type = new BlackboardArtifact.Type(rs.getInt("artifact_type_id"),
						rs.getString("type_name"), rs.getString("display_name"),
						BlackboardArtifact.Category.fromID(rs.getInt("category_type")));
				this.typeIdToArtifactTypeMap.put(artTypeId, type);
				this.typeNameToArtifactTypeMap.put(type.getTypeName(), type);
				return type;
			} else {
				throw new TskCoreException("No artifact type found matching id: " + artTypeId);
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting artifact type from the database", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			closeConnection(connection);
			caseDb.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Get the list of attributes for the given artifact.
	 *
	 * @param artifact The artifact to load attributes for.
	 *
	 * @return The list of attributes.
	 *
	 * @throws TskCoreException
	 */
	public ArrayList<BlackboardAttribute> getBlackboardAttributes(final BlackboardArtifact artifact) throws TskCoreException {
		CaseDbConnection connection = null;
		Statement statement = null;
		ResultSet rs = null;
		
		String rowId;
		switch (caseDb.getDatabaseType()) {
			case POSTGRESQL: 
				rowId = "attrs.CTID";
				break;
			case SQLITE:
				rowId = "attrs.ROWID";
				break;
			default:
				throw new TskCoreException("Unknown database type: " + caseDb.getDatabaseType());
		}
		
		caseDb.acquireSingleUserCaseReadLock();
		try {
			connection = caseDb.getConnection();
			statement = connection.createStatement();
			rs = connection.executeQuery(statement, "SELECT attrs.artifact_id AS artifact_id, "
					+ "attrs.source AS source, attrs.context AS context, attrs.attribute_type_id AS attribute_type_id, "
					+ "attrs.value_type AS value_type, attrs.value_byte AS value_byte, "
					+ "attrs.value_text AS value_text, attrs.value_int32 AS value_int32, "
					+ "attrs.value_int64 AS value_int64, attrs.value_double AS value_double, "
					+ "types.type_name AS type_name, types.display_name AS display_name "
					+ "FROM blackboard_attributes AS attrs, blackboard_attribute_types AS types WHERE attrs.artifact_id = " + artifact.getArtifactID()
					+ " AND attrs.attribute_type_id = types.attribute_type_id " 
					+ " ORDER BY " + rowId);
			ArrayList<BlackboardAttribute> attributes = new ArrayList<>();
			while (rs.next()) {
				final BlackboardAttribute attr = createAttributeFromResultSet(rs);
				attr.setParentDataSourceID(artifact.getDataSourceObjectID());
				attributes.add(attr);
			}
			return attributes;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting attributes for artifact, artifact id = " + artifact.getArtifactID(), ex);
		} finally {
			closeResultSet(rs);
			closeStatement(statement);
			closeConnection(connection);
			caseDb.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Populate the attributes for all artifacts in the list. This is done using
	 * one database call as an efficient way to load many artifacts/attributes
	 * at once.
	 *
	 * @param arts The list of artifacts. When complete, each will have its
	 *             attributes loaded.
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	@Beta
	public <T extends BlackboardArtifact> void loadBlackboardAttributes(List<T> arts) throws TskCoreException {

		if (arts.isEmpty()) {
			return;
		}

		// Make a map of artifact ID to artifact
		Map<Long, BlackboardArtifact> artifactMap = new HashMap<>();
		for (BlackboardArtifact art : arts) {
			artifactMap.put(art.getArtifactID(), art);
		}

		// Make a map of artifact ID to attribute list
		Map<Long, List<BlackboardAttribute>> attributeMap = new HashMap<>();

		// Get all artifact IDs as a comma-separated string
		String idString = arts.stream().map(p -> Long.toString(p.getArtifactID())).collect(Collectors.joining(", "));

		String rowId;
		switch (caseDb.getDatabaseType()) {
			case POSTGRESQL:
				rowId = "attrs.CTID";
				break;
			case SQLITE:
				rowId = "attrs.ROWID";
				break;
			default:
				throw new TskCoreException("Unknown database type: " + caseDb.getDatabaseType());
		}

		// Get the attributes
		CaseDbConnection connection = null;
		Statement statement = null;
		ResultSet rs = null;
		caseDb.acquireSingleUserCaseReadLock();
		try {
			connection = caseDb.getConnection();
			statement = connection.createStatement();
			rs = connection.executeQuery(statement, "SELECT attrs.artifact_id AS artifact_id, "
					+ "attrs.source AS source, attrs.context AS context, attrs.attribute_type_id AS attribute_type_id, "
					+ "attrs.value_type AS value_type, attrs.value_byte AS value_byte, "
					+ "attrs.value_text AS value_text, attrs.value_int32 AS value_int32, "
					+ "attrs.value_int64 AS value_int64, attrs.value_double AS value_double, "
					+ "types.type_name AS type_name, types.display_name AS display_name "
					+ "FROM blackboard_attributes AS attrs, blackboard_attribute_types AS types WHERE attrs.artifact_id IN (" + idString + ") "
					+ " AND attrs.attribute_type_id = types.attribute_type_id"
					+ " ORDER BY " + rowId);
			while (rs.next()) {
				final BlackboardAttribute attr = createAttributeFromResultSet(rs);
				attr.setParentDataSourceID(artifactMap.get(attr.getArtifactID()).getDataSourceObjectID());

				// Collect the list of attributes for each artifact
				if (!attributeMap.containsKey(attr.getArtifactID())) {
					attributeMap.put(attr.getArtifactID(), new ArrayList<>());
				}
				attributeMap.get(attr.getArtifactID()).add(attr);
			}

			// Save the attributes to the artifacts
			for (Long artifactID : attributeMap.keySet()) {
				artifactMap.get(artifactID).setAttributes(attributeMap.get(artifactID));
			}

		} catch (SQLException ex) {
			throw new TskCoreException("Error loading attributes", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(statement);
			closeConnection(connection);
			caseDb.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Create a BlackboardAttribute artifact from the result set. Does not set
	 * the data source ID.
	 *
	 * @param rs The result set.
	 *
	 * @return The corresponding BlackboardAttribute object.
	 */
	private BlackboardAttribute createAttributeFromResultSet(ResultSet rs) throws SQLException {
		int attributeTypeId = rs.getInt("attribute_type_id");
		String attributeTypeName = rs.getString("type_name");
		BlackboardAttribute.Type attributeType;
		if (this.typeIdToAttributeTypeMap.containsKey(attributeTypeId)) {
			attributeType = this.typeIdToAttributeTypeMap.get(attributeTypeId);
		} else {
			attributeType = new BlackboardAttribute.Type(attributeTypeId, attributeTypeName,
					rs.getString("display_name"),
					BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.fromType(rs.getInt("value_type")));
			this.typeIdToAttributeTypeMap.put(attributeTypeId, attributeType);
			this.typeNameToAttributeTypeMap.put(attributeTypeName, attributeType);
		}

		return new BlackboardAttribute(
				rs.getLong("artifact_id"),
				attributeType,
				rs.getString("source"),
				rs.getString("context"),
				rs.getInt("value_int32"),
				rs.getLong("value_int64"),
				rs.getDouble("value_double"),
				rs.getString("value_text"),
				rs.getBytes("value_byte"), caseDb
		);
	}
	
	/**
	 * Update file attributes for file with the given object ID.
	 * For each attribute present, the current attribute of that type will be overwitten with the new value.
	 * 
	 * @param fileObjId  File object ID
	 * @param attributes List of attributes. Each of the given attributes types should already be present in the database.
	 * 
	 * @throws TskCoreException
	 */
	@Beta
	public void updateFileAttributes(long fileObjId, List<Attribute> attributes) throws TskCoreException {

		caseDb.acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = caseDb.getConnection()) {
			for (Attribute attr : attributes) {
				String updateString = "UPDATE tsk_file_attributes SET value_byte = ?, value_text = ?, value_int32 = ?, "
					+ " value_int64 = ?, value_double = ? WHERE attribute_type_id = " + attr.getAttributeType().getTypeID() 
					+ " AND obj_id = " + fileObjId;
				
				try (PreparedStatement preparedStatement = connection.getPreparedStatement(updateString, Statement.NO_GENERATED_KEYS);) {
					preparedStatement.clearParameters();

					if (attr.getAttributeType().getValueType() == BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.BYTE) {
						preparedStatement.setBytes(1, attr.getValueBytes());
					} else {
						preparedStatement.setBytes(1, null);
					}

					if (attr.getAttributeType().getValueType() == BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING
							|| attr.getAttributeType().getValueType() == BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.JSON) {
						preparedStatement.setString(2, attr.getValueString());
					} else {
						preparedStatement.setString(2, null);
					}
					
					if (attr.getAttributeType().getValueType() == BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER) {
						preparedStatement.setInt(3, attr.getValueInt());
					} else {
						preparedStatement.setNull(3, java.sql.Types.INTEGER);
					}

					if (attr.getAttributeType().getValueType() == BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME
							|| attr.getAttributeType().getValueType() == BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG) {
						preparedStatement.setLong(4, attr.getValueLong());
					} else {
						preparedStatement.setNull(4, java.sql.Types.BIGINT);
					}

					if (attr.getAttributeType().getValueType() == BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE) {
						preparedStatement.setDouble(5, attr.getValueDouble());
					} else {
						preparedStatement.setNull(5, java.sql.Types.DOUBLE);
					}
					
					connection.executeUpdate(preparedStatement);

				} catch (SQLException ex) {
					throw new TskCoreException(String.format("Error updating attribute using query = '%s'", updateString), ex);
				}
			}
		} finally {
			caseDb.releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Get the attributes associated with the given file.
	 *
	 * @param file
	 *
	 * @return
	 *
	 * @throws TskCoreException
	 */
	ArrayList<Attribute> getFileAttributes(final AbstractFile file) throws TskCoreException {
		CaseDbConnection connection = null;
		Statement statement = null;
		ResultSet rs = null;
		caseDb.acquireSingleUserCaseReadLock();
		try {
			connection = caseDb.getConnection();
			statement = connection.createStatement();
			rs = connection.executeQuery(statement, "SELECT attrs.id as id,  attrs.obj_id AS obj_id, "
					+ "attrs.attribute_type_id AS attribute_type_id, "
					+ "attrs.value_type AS value_type, attrs.value_byte AS value_byte, "
					+ "attrs.value_text AS value_text, attrs.value_int32 AS value_int32, "
					+ "attrs.value_int64 AS value_int64, attrs.value_double AS value_double, "
					+ "types.type_name AS type_name, types.display_name AS display_name "
					+ "FROM tsk_file_attributes AS attrs "
					+ " INNER JOIN blackboard_attribute_types AS types "
					+ " ON attrs.attribute_type_id = types.attribute_type_id "
					+ " WHERE attrs.obj_id = " + file.getId());

			ArrayList<Attribute> attributes = new ArrayList<Attribute>();
			while (rs.next()) {
				int attributeTypeId = rs.getInt("attribute_type_id");
				String attributeTypeName = rs.getString("type_name");
				BlackboardAttribute.Type attributeType;
				if (this.typeIdToAttributeTypeMap.containsKey(attributeTypeId)) {
					attributeType = this.typeIdToAttributeTypeMap.get(attributeTypeId);
				} else {
					attributeType = new BlackboardAttribute.Type(attributeTypeId, attributeTypeName,
							rs.getString("display_name"),
							BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.fromType(rs.getInt("value_type")));
					this.typeIdToAttributeTypeMap.put(attributeTypeId, attributeType);
					this.typeNameToAttributeTypeMap.put(attributeTypeName, attributeType);
				}

				final Attribute attr = new Attribute(
						rs.getLong("id"),
						rs.getLong("obj_id"),
						attributeType,
						rs.getInt("value_int32"),
						rs.getLong("value_int64"),
						rs.getDouble("value_double"),
						rs.getString("value_text"),
						rs.getBytes("value_byte"), caseDb
				);
				attributes.add(attr);
			}
			return attributes;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting attributes for file, file id = " + file.getId(), ex);
		} finally {
			closeResultSet(rs);
			closeStatement(statement);
			closeConnection(connection);
			caseDb.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Adds the standard artifact types to the blackboard_artifact_types table
	 * and the artifact type caches.
	 *
	 * @param connection A connection to the case database.
	 *
	 * @throws SQLException Thrown if there is an error adding a type to the
	 *                      table.
	 */
	void initBlackboardArtifactTypes(CaseDbConnection connection) throws SQLException {
		caseDb.acquireSingleUserCaseWriteLock();
		try (Statement statement = connection.createStatement()) {
			/*
			 * Determine which types, if any, have already been added to the
			 * case database, and load them into the type caches. For a case
			 * that is being reopened, this should reduce the number of separate
			 * INSERT staements that will be executed below.
			 */
			ResultSet resultSet = connection.executeQuery(statement, "SELECT artifact_type_id, type_name, display_name, category_type FROM blackboard_artifact_types"); //NON-NLS
			while (resultSet.next()) {
				BlackboardArtifact.Type type = new BlackboardArtifact.Type(resultSet.getInt("artifact_type_id"),
						resultSet.getString("type_name"), resultSet.getString("display_name"),
						BlackboardArtifact.Category.fromID(resultSet.getInt("category_type")));
				typeIdToArtifactTypeMap.put(type.getTypeID(), type);
				typeNameToArtifactTypeMap.put(type.getTypeName(), type);
			}

			/*
			 * INSERT any missing standard types. A conflict clause is used to
			 * avoid a potential race condition. It also eliminates the need to
			 * add schema update code when new types are added.
			 *
			 * The use here of the soon to be deprecated
			 * BlackboardArtifact.ARTIFACT_TYPE enum instead of the
			 * BlackboardArtifact.Type.STANDARD_TYPES collection currently
			 * ensures that the deprecated types in the former, and not in the
			 * latter, are added to the case database.
			 */
			for (BlackboardArtifact.ARTIFACT_TYPE type : BlackboardArtifact.ARTIFACT_TYPE.values()) {
				if (typeIdToArtifactTypeMap.containsKey(type.getTypeID())) {
					continue;
				}
				if (caseDb.getDatabaseType() == TskData.DbType.POSTGRESQL) {
					statement.execute("INSERT INTO blackboard_artifact_types (artifact_type_id, type_name, display_name, category_type) VALUES (" + type.getTypeID() + " , '" + type.getLabel() + "', '" + type.getDisplayName() + "' , " + type.getCategory().getID() + ") ON CONFLICT DO NOTHING"); //NON-NLS
				} else {
					statement.execute("INSERT OR IGNORE INTO blackboard_artifact_types (artifact_type_id, type_name, display_name, category_type) VALUES (" + type.getTypeID() + " , '" + type.getLabel() + "', '" + type.getDisplayName() + "' , " + type.getCategory().getID() + ")"); //NON-NLS
				}
				typeIdToArtifactTypeMap.put(type.getTypeID(), new BlackboardArtifact.Type(type));
				typeNameToArtifactTypeMap.put(type.getLabel(), new BlackboardArtifact.Type(type));
			}
			if (caseDb.getDatabaseType() == TskData.DbType.POSTGRESQL) {
				int newPrimaryKeyIndex = Collections.max(Arrays.asList(BlackboardArtifact.ARTIFACT_TYPE.values())).getTypeID() + 1;
				statement.execute("ALTER SEQUENCE blackboard_artifact_types_artifact_type_id_seq RESTART WITH " + newPrimaryKeyIndex); //NON-NLS
			}
		} finally {
			caseDb.releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Adds the standard attribute types to the blackboard_attribute_types table
	 * and the attribute type caches.
	 *
	 * @param connection A connection to the case database.
	 *
	 * @throws SQLException Thrown if there is an error adding a type to the
	 *                      table.
	 */
	void initBlackboardAttributeTypes(CaseDbConnection connection) throws SQLException {
		caseDb.acquireSingleUserCaseWriteLock();
		try (Statement statement = connection.createStatement()) {
			/*
			 * Determine which types, if any, have already been added to the
			 * case database, and load them into the type caches. For a case
			 * that is being reopened, this should reduce the number of separate
			 * INSERT staements that will be executed below.
			 */
			ResultSet resultSet = connection.executeQuery(statement, "SELECT attribute_type_id, type_name, display_name, value_type FROM blackboard_attribute_types"); //NON-NLS
			while (resultSet.next()) {
				BlackboardAttribute.Type type = new BlackboardAttribute.Type(resultSet.getInt("attribute_type_id"),
						resultSet.getString("type_name"), resultSet.getString("display_name"),
						BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.fromType(resultSet.getLong("value_type")));
				typeIdToAttributeTypeMap.put(type.getTypeID(), type);
				typeNameToAttributeTypeMap.put(type.getTypeName(), type);
			}

			/*
			 * INSERT any missing standard types. A conflict clause is used to
			 * avoid a potential race condition. It also eliminates the need to
			 * add schema update code when new types are added.
			 *
			 * The use here of the soon to be deprecated
			 * BlackboardAttribute.ATTRIBUTE_TYPE enum instead of the
			 * BlackboardAttribute.Type.STANDARD_TYPES collection currently
			 * ensures that the deprecated types in the former, and not in the
			 * latter, are added to the case database.
			 */
			for (BlackboardAttribute.ATTRIBUTE_TYPE type : BlackboardAttribute.ATTRIBUTE_TYPE.values()) {
				if (typeIdToAttributeTypeMap.containsKey(type.getTypeID())) {
					continue;
				}
				if (caseDb.getDatabaseType() == TskData.DbType.POSTGRESQL) {
					statement.execute("INSERT INTO blackboard_attribute_types (attribute_type_id, type_name, display_name, value_type) VALUES (" + type.getTypeID() + ", '" + type.getLabel() + "', '" + type.getDisplayName() + "', '" + type.getValueType().getType() + "') ON CONFLICT DO NOTHING"); //NON-NLS
				} else {
					statement.execute("INSERT OR IGNORE INTO blackboard_attribute_types (attribute_type_id, type_name, display_name, value_type) VALUES (" + type.getTypeID() + ", '" + type.getLabel() + "', '" + type.getDisplayName() + "', '" + type.getValueType().getType() + "')"); //NON-NLS
				}
				typeIdToAttributeTypeMap.put(type.getTypeID(), new BlackboardAttribute.Type(type));
				typeNameToAttributeTypeMap.put(type.getLabel(), new BlackboardAttribute.Type(type));
			}
			if (caseDb.getDatabaseType() == TskData.DbType.POSTGRESQL) {
				int newPrimaryKeyIndex = Collections.max(Arrays.asList(BlackboardAttribute.ATTRIBUTE_TYPE.values())).getTypeID() + 1;
				statement.execute("ALTER SEQUENCE blackboard_attribute_types_attribute_type_id_seq RESTART WITH " + newPrimaryKeyIndex); //NON-NLS
			}
		} finally {
			caseDb.releaseSingleUserCaseWriteLock();
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

	private final static String ANALYSIS_RESULT_QUERY_STRING_GENERIC = "SELECT DISTINCT artifacts.artifact_id AS artifact_id, " //NON-NLS
			+ " artifacts.obj_id AS obj_id, artifacts.artifact_obj_id AS artifact_obj_id, artifacts.data_source_obj_id AS data_source_obj_id, artifacts.artifact_type_id AS artifact_type_id, "
			+ " types.type_name AS type_name, types.display_name AS display_name, types.category_type as category_type,"//NON-NLS
			+ " artifacts.review_status_id AS review_status_id, " //NON-NLS
			+ " results.conclusion AS conclusion,  results.significance AS significance,  results.priority AS priority,  "
			+ " results.configuration AS configuration,  results.justification AS justification "
			+ " FROM blackboard_artifacts AS artifacts "
			+ " JOIN blackboard_artifact_types AS types " //NON-NLS
			+ "		ON artifacts.artifact_type_id = types.artifact_type_id" //NON-NLS
			+ " LEFT JOIN tsk_analysis_results AS results "
			+ "		ON artifacts.artifact_obj_id = results.artifact_obj_id "; //NON-NLS

	private final static String ANALYSIS_RESULT_QUERY_STRING_WITH_ATTRIBUTES
			= ANALYSIS_RESULT_QUERY_STRING_GENERIC
			+ " JOIN blackboard_attributes AS attributes " //NON-NLS 
			+ " ON artifacts.artifact_id = attributes.artifact_id " //NON-NLS 
			+ " WHERE types.category_type = " + BlackboardArtifact.Category.ANALYSIS_RESULT.getID(); // NON-NLS

	private final static String ANALYSIS_RESULT_QUERY_STRING_WHERE
			= ANALYSIS_RESULT_QUERY_STRING_GENERIC
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
	 * Gets all analysis results of a given type for a given data source. To get
	 * all the analysis results for the data source, pass null for the type ID.
	 *
	 * @param dataSourceObjId The object ID of the data source.
	 * @param artifactTypeID  The type ID of the desired analysis results or
	 *                        null.
	 *
	 * @return A list of the analysis results, possibly empty.
	 *
	 * @throws TskCoreException This exception is thrown if there is an error
	 *                          querying the case database.
	 */
	public List<AnalysisResult> getAnalysisResults(long dataSourceObjId, Integer artifactTypeID) throws TskCoreException {
		caseDb.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = caseDb.getConnection()) {
			String whereClause = " artifacts.data_source_obj_id = " + dataSourceObjId;
			if (artifactTypeID != null) {
				whereClause += " AND artifacts.artifact_type_id = " + artifactTypeID;
			}
			return getAnalysisResultsWhere(whereClause, connection);
		} finally {
			caseDb.releaseSingleUserCaseReadLock();
		}
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
		BlackboardArtifact.Type artifactType = getArtifactType(artifactTypeId);
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

		final String queryString = ANALYSIS_RESULT_QUERY_STRING_WHERE
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

	private final static String DATA_ARTIFACT_QUERY_STRING_GENERIC = "SELECT DISTINCT artifacts.artifact_id AS artifact_id, " //NON-NLS
			+ "artifacts.obj_id AS obj_id, artifacts.artifact_obj_id AS artifact_obj_id, artifacts.data_source_obj_id AS data_source_obj_id, artifacts.artifact_type_id AS artifact_type_id, " //NON-NLS
			+ " types.type_name AS type_name, types.display_name AS display_name, types.category_type as category_type,"//NON-NLS
			+ " artifacts.review_status_id AS review_status_id, " //NON-NLS
			+ " data_artifacts.os_account_obj_id as os_account_obj_id " //NON-NLS
			+ " FROM blackboard_artifacts AS artifacts " //NON-NLS 
			+ " JOIN blackboard_artifact_types AS types " //NON-NLS
			+ "		ON artifacts.artifact_type_id = types.artifact_type_id" //NON-NLS
			+ " LEFT JOIN tsk_data_artifacts AS data_artifacts " //NON-NLS 
			+ "		ON artifacts.artifact_obj_id = data_artifacts.artifact_obj_id "; //NON-NLS

	private final static String DATA_ARTIFACT_QUERY_STRING_WITH_ATTRIBUTES
			= DATA_ARTIFACT_QUERY_STRING_GENERIC
			+ " JOIN blackboard_attributes AS attributes " //NON-NLS 
			+ " ON artifacts.artifact_id = attributes.artifact_id " //NON-NLS 
			+ " WHERE types.category_type = " + BlackboardArtifact.Category.DATA_ARTIFACT.getID(); // NON-NLS	

	private final static String DATA_ARTIFACT_QUERY_STRING_WHERE
			= DATA_ARTIFACT_QUERY_STRING_GENERIC
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
		BlackboardArtifact.Type artifactType = getArtifactType(artifactTypeID);
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
		BlackboardArtifact.Type artifactType = getArtifactType(artifactTypeID);
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
	public List<DataArtifact> getDataArtifactsWhere(String whereClause) throws TskCoreException {
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

		final String queryString = DATA_ARTIFACT_QUERY_STRING_WHERE
				+ " AND " + whereClause + " ";

		try (Statement statement = connection.createStatement();
				ResultSet resultSet = connection.executeQuery(statement, queryString);) {

			List<DataArtifact> dataArtifacts = resultSetToDataArtifacts(resultSet);
			return dataArtifacts;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting data artifacts with queryString = %s", queryString), ex);
		}
	}

	/**
	 * Creates DataArtifacts objects for the resultset of a table query of the
	 * form "SELECT * FROM blackboard_artifacts JOIN data_artifacts WHERE ...".
	 *
	 * @param resultSet A result set from a query of the blackboard_artifacts
	 *                  table of the form "SELECT * FROM blackboard_artifacts,
	 *                  tsk_data_artifacts WHERE ...".
	 *
	 * @return A list of DataArtifact objects.
	 *
	 * @throws SQLException     Thrown if there is a problem iterating through
	 *                          the result set.
	 * @throws TskCoreException Thrown if there is an error looking up the
	 *                          artifact type id.
	 */
	private List<DataArtifact> resultSetToDataArtifacts(ResultSet resultSet) throws SQLException, TskCoreException {
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
	 * Gets an attribute type, creating it if it does not already exist. Use
	 * this method to define custom attribute types.
	 *
	 * NOTE: This method is synchronized to prevent simultaneous access from
	 * different threads, but there is still the possibility of concurrency 
	 * issues from different clients.
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
		// check local cache
		if (typeNameToAttributeTypeMap.containsKey(typeName)) {
			return typeNameToAttributeTypeMap.get(typeName);
		}

		CaseDbTransaction trans = null;
		try {
			trans = this.caseDb.beginTransaction();
			String matchingAttrQuery = "SELECT attribute_type_id, type_name, display_name, value_type "
					+ "FROM blackboard_attribute_types WHERE type_name = ?";
			// find matching attribute name
			PreparedStatement query = trans.getConnection().getPreparedStatement(matchingAttrQuery, Statement.RETURN_GENERATED_KEYS);
			query.clearParameters();
			query.setString(1, typeName);
			try (ResultSet rs = query.executeQuery()) {
				// if previously existing, commit the results and return the attribute type
				if (rs.next()) {
					trans.commit();
					trans = null;
					BlackboardAttribute.Type foundType = new BlackboardAttribute.Type(
							rs.getInt("attribute_type_id"),
							rs.getString("type_name"),
							rs.getString("display_name"),
							BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.fromType(rs.getLong("value_type"))
					);

					this.typeIdToAttributeTypeMap.put(foundType.getTypeID(), foundType);
					this.typeNameToAttributeTypeMap.put(foundType.getTypeName(), foundType);

					return foundType;
				}
			}

			// if not found in database, insert
			String insertStatement = "INSERT INTO blackboard_attribute_types (attribute_type_id, type_name, display_name, value_type) VALUES (\n"
					// get the maximum of the attribute type id's or the min user defined type id and add 1 to it for the new id
					+ "(SELECT MAX(q.attribute_type_id) FROM (SELECT attribute_type_id FROM blackboard_attribute_types UNION SELECT " + (MIN_USER_DEFINED_TYPE_ID - 1) + ") q) + 1,\n"
					// typeName, displayName, valueType
					+ "?, ?, ?)";

			PreparedStatement insertPreparedStatement = trans.getConnection().getPreparedStatement(insertStatement, Statement.RETURN_GENERATED_KEYS);
			insertPreparedStatement.clearParameters();
			insertPreparedStatement.setString(1, typeName);
			insertPreparedStatement.setString(2, displayName);
			insertPreparedStatement.setLong(3, valueType.getType());

			int numUpdated = insertPreparedStatement.executeUpdate();

			// get id for inserted to create new attribute.
			Integer attrId = null;

			if (numUpdated > 0) {
				try (ResultSet insertResult = insertPreparedStatement.getGeneratedKeys()) {
					if (insertResult.next()) {
						attrId = insertResult.getInt(1);
					}
				}
			}

			if (attrId == null) {
				throw new BlackboardException(MessageFormat.format(
						"Error adding attribute type.  Item with name {0} was not inserted successfully into the database.", typeName));
			}

			trans.commit();
			trans = null;

			BlackboardAttribute.Type type = new BlackboardAttribute.Type(attrId, typeName, displayName, valueType);
			this.typeIdToAttributeTypeMap.put(type.getTypeID(), type);
			this.typeNameToAttributeTypeMap.put(type.getTypeName(), type);
			return type;
		} catch (SQLException | TskCoreException ex) {
			throw new BlackboardException("Error adding attribute type: " + typeName, ex);
		} finally {
			try {
				if (trans != null) {
					trans.rollback();
					trans = null;
				}
			} catch (TskCoreException ex2) {
				LOGGER.log(Level.SEVERE, "Error rolling back transaction", ex2);
			}
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
	 * Get count of all blackboard artifacts of a given type. Does not include
	 * rejected artifacts.
	 *
	 * @param artifactTypeID artifact type id (must exist in database)
	 *
	 * @return count of blackboard artifacts
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	public long getArtifactsCount(int artifactTypeID) throws TskCoreException {
		return getArtifactsCountHelper(artifactTypeID, null);
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
		return getArtifactsWhere(getArtifactType(artifactTypeID), whereClause);
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
	 * Get all blackboard artifacts of the given type that contain attribute of
	 * given type and value, for a given data source(s).
	 *
	 * @param artifactType		  artifact type to get
	 * @param attributeType		 attribute type to be included
	 * @param value				       attribute value to be included. can be empty.
	 * @param dataSourceObjId	data source to look under. If Null, then search
	 *                        all data sources.
	 * @param showRejected		  a flag whether to display rejected artifacts
	 *
	 * @return list of blackboard artifacts
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 *                          within TSK core
	 */
	public List<BlackboardArtifact> getArtifacts(BlackboardArtifact.Type artifactType,
			BlackboardAttribute.Type attributeType, String value, Long dataSourceObjId,
			boolean showRejected) throws TskCoreException {

		String query = " AND artifacts.artifact_type_id = " + artifactType.getTypeID() //NON-NLS 
				+ " AND attributes.attribute_type_id = " + attributeType.getTypeID() //NON-NLS
				+ ((value == null || value.isEmpty()) ? "" : " AND attributes.value_text = '" + value + "'") //NON-NLS
				+ (showRejected ? "" : " AND artifacts.review_status_id != " + BlackboardArtifact.ReviewStatus.REJECTED.getID()) //NON-NLS
				+ (dataSourceObjId != null ? " AND artifacts.data_source_obj_id = " + dataSourceObjId : ""); //NON-NLS

		List<BlackboardArtifact> artifacts = new ArrayList<>();
		caseDb.acquireSingleUserCaseReadLock();

		String finalQuery = (artifactType.getCategory() == BlackboardArtifact.Category.ANALYSIS_RESULT
				? ANALYSIS_RESULT_QUERY_STRING_WITH_ATTRIBUTES + query
				: DATA_ARTIFACT_QUERY_STRING_WITH_ATTRIBUTES + query);

		try (CaseDbConnection connection = caseDb.getConnection()) {
			try (Statement statement = connection.createStatement();
					ResultSet resultSet = connection.executeQuery(statement, finalQuery);) {

				if (artifactType.getCategory() == BlackboardArtifact.Category.ANALYSIS_RESULT) {
					artifacts.addAll(resultSetToAnalysisResults(resultSet));
				} else {
					artifacts.addAll(resultSetToDataArtifacts(resultSet));
				}
			} catch (SQLException ex) {
				throw new TskCoreException(String.format("Error getting results with queryString = '%s'", finalQuery), ex);
			}
		} finally {
			caseDb.releaseSingleUserCaseReadLock();
		}
		return artifacts;
	}

	/**
	 * Returns a list of "Exact match / Literal" keyword hits blackboard
	 * artifacts according to the input conditions.
	 *
	 * @param keyword      The keyword string to search for. This should always
	 *                     be populated unless you are trying to get all keyword
	 *                     hits of specific keyword search type or keyword list
	 *                     name.
	 * @param searchType   Type of keyword search query.
	 * @param kwsListName  (Optional) Name of the keyword list for which the
	 *                     search results are for. If not specified, then the
	 *                     results will be for ad-hoc keyword searches.
	 * @param dataSourceId (Optional) Data source id of the target data source.
	 *                     If null, then the results will be for all data
	 *                     sources.
	 *
	 * @return A list of keyword hits blackboard artifacts
	 *
	 * @throws TskCoreException If an exception is encountered while running
	 *                          database query to obtain the keyword hits.
	 */
	public List<BlackboardArtifact> getExactMatchKeywordSearchResults(String keyword, TskData.KeywordSearchQueryType searchType, String kwsListName, Long dataSourceId) throws TskCoreException {
		return getKeywordSearchResults(keyword, "", searchType, kwsListName, dataSourceId);
	}

	/**
	 * Returns a list of keyword hits blackboard artifacts according to the
	 * input conditions.
	 *
	 * @param keyword      The keyword string to search for. This should always
	 *                     be populated unless you are trying to get all keyword
	 *                     hits of specific keyword search type or keyword list
	 *                     name.
	 * @param regex        For substring and regex keyword search types, the
	 *                     regex/substring query string should be specified as
	 *                     well as the keyword. It should be empty for literal
	 *                     exact match keyword search types.
	 * @param searchType   Type of keyword search query.
	 * @param kwsListName  (Optional) Name of the keyword list for which the
	 *                     search results are for. If not specified, then the
	 *                     results will be for ad-hoc keyword searches.
	 * @param dataSourceId (Optional) Data source id of the target data source.
	 *                     If null, then the results will be for all data
	 *                     sources.
	 *
	 * @return A list of keyword hits blackboard artifacts
	 *
	 * @throws TskCoreException If an exception is encountered while running
	 *                          database query to obtain the keyword hits.
	 */
	public List<BlackboardArtifact> getKeywordSearchResults(String keyword, String regex, TskData.KeywordSearchQueryType searchType, String kwsListName, Long dataSourceId) throws TskCoreException {
		
		String dataSourceClause = dataSourceId == null
				? ""
				: " AND artifacts.data_source_obj_id = ? "; // dataSourceId

		String kwsListClause = (kwsListName == null || kwsListName.isEmpty()
				? " WHERE r.set_name IS NULL "
				: " WHERE r.set_name = ? ");

		String keywordClause = (keyword == null || keyword.isEmpty()
				? ""
				: " AND r.keyword = ? ");

		String searchTypeClause = (searchType == null
				? ""
				: " AND r.search_type = ? ");

		String regexClause = (regex == null || regex.isEmpty()
				? ""
				: " AND r.regexp_str = ? ");

		String query = "SELECT r.* FROM ( "
				+ " SELECT DISTINCT artifacts.artifact_id AS artifact_id, "
				+ " artifacts.obj_id AS obj_id, "
				+ " artifacts.artifact_obj_id AS artifact_obj_id, "
				+ " artifacts.data_source_obj_id AS data_source_obj_id, "
				+ " artifacts.artifact_type_id AS artifact_type_id, "
				+ " types.type_name AS type_name, "
				+ " types.display_name AS display_name, "
				+ " types.category_type as category_type,"
				+ " artifacts.review_status_id AS review_status_id, "
				+ " results.conclusion AS conclusion, "
				+ " results.significance AS significance, "
				+ " results.priority AS priority, "
				+ " results.configuration AS configuration, "
				+ " results.justification AS justification, "
				+ " (SELECT value_text FROM blackboard_attributes attr WHERE attr.artifact_id = artifacts.artifact_id AND attr.attribute_type_id = "
				+ BlackboardAttribute.Type.TSK_SET_NAME.getTypeID() + " LIMIT 1) AS set_name, "
				+ " (SELECT value_int32 FROM blackboard_attributes attr WHERE attr.artifact_id = artifacts.artifact_id AND attr.attribute_type_id = "
				+ BlackboardAttribute.ATTRIBUTE_TYPE.TSK_KEYWORD_SEARCH_TYPE.getTypeID() + " LIMIT 1) AS search_type, "
				+ " (SELECT value_text FROM blackboard_attributes attr WHERE attr.artifact_id = artifacts.artifact_id AND attr.attribute_type_id = "
				+ BlackboardAttribute.Type.TSK_KEYWORD_REGEXP.getTypeID() + " LIMIT 1) AS regexp_str, "
				+ " (SELECT value_text FROM blackboard_attributes attr WHERE attr.artifact_id = artifacts.artifact_id AND attr.attribute_type_id = "
				+ BlackboardAttribute.Type.TSK_KEYWORD.getTypeID() + " LIMIT 1) AS keyword "
				+ " FROM blackboard_artifacts artifacts "
				+ " JOIN blackboard_artifact_types AS types "
				+ " ON artifacts.artifact_type_id = types.artifact_type_id "
				+ " LEFT JOIN tsk_analysis_results AS results "
				+ " ON artifacts.artifact_obj_id = results.artifact_obj_id "
				+ " WHERE types.category_type = " + BlackboardArtifact.Category.ANALYSIS_RESULT.getID()
				+ " AND artifacts.artifact_type_id = " + BlackboardArtifact.Type.TSK_KEYWORD_HIT.getTypeID() + " "
				+ dataSourceClause + " ) r "
				+ kwsListClause
				+ keywordClause
				+ searchTypeClause
				+ regexClause;

		List<BlackboardArtifact> artifacts = new ArrayList<>();
		caseDb.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = caseDb.getConnection()) {

			try {
				PreparedStatement preparedStatement = connection.getPreparedStatement(query, Statement.RETURN_GENERATED_KEYS);
				preparedStatement.clearParameters();
				int paramIdx = 0;
				if (dataSourceId != null) {
					preparedStatement.setLong(++paramIdx, dataSourceId);
				}
								
				if (!(kwsListName == null || kwsListName.isEmpty())) {
					preparedStatement.setString(++paramIdx, kwsListName);
				}

				if (!(keyword == null || keyword.isEmpty())) {
					preparedStatement.setString(++paramIdx, keyword);
				}

				if (searchType != null) {
					preparedStatement.setInt(++paramIdx, searchType.getType());
				}

				if (!(regex == null || regex.isEmpty())) {
					preparedStatement.setString(++paramIdx, regex);
				}
				
				try (ResultSet resultSet = connection.executeQuery(preparedStatement)) {
					artifacts.addAll(resultSetToAnalysisResults(resultSet));
				}

			} catch (SQLException ex) {
				throw new TskCoreException(String.format("Error getting keyword search results with queryString = '%s'", query), ex);
			}
		} finally {
			caseDb.releaseSingleUserCaseReadLock();
		}
		return artifacts;
	}
	
	/**
	 * Gets count of blackboard artifacts of given type that match a given WHERE
	 * clause. Uses a SELECT COUNT(*) FROM blackboard_artifacts statement
	 *
	 * @param artifactTypeID artifact type to count
	 * @param whereClause    The WHERE clause to append to the SELECT statement
	 *                       (may be null).
	 *
	 * @return A count of matching BlackboardArtifact .
	 *
	 * @throws TskCoreException If there is a problem querying the case
	 *                          database.
	 */
	private long getArtifactsCountHelper(int artifactTypeID, String whereClause) throws TskCoreException {
		String queryString = "SELECT COUNT(*) AS count FROM blackboard_artifacts "
				+ "WHERE blackboard_artifacts.artifact_type_id = " + artifactTypeID
				+ " AND blackboard_artifacts.review_status_id !=" + BlackboardArtifact.ReviewStatus.REJECTED.getID();

		if (whereClause != null) {
			queryString += " AND " + whereClause;
		}

		caseDb.acquireSingleUserCaseReadLock();
		try (SleuthkitCase.CaseDbConnection connection = caseDb.getConnection();
				Statement statement = connection.createStatement();
				ResultSet resultSet = connection.executeQuery(statement, queryString);) {
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

	/**
	 * Determines whether or not an artifact of a given type with a given set of
	 * attributes already exists for a given content.
	 *
	 * @param content      The content.
	 * @param artifactType The artifact type.
	 * @param attributes   The attributes.
	 *
	 * @return True or false
	 *
	 * @throws TskCoreException The exception is thrown if there is an issue
	 *                          querying the case database.
	 */
	public boolean artifactExists(Content content, BlackboardArtifact.Type artifactType, Collection<BlackboardAttribute> attributes) throws TskCoreException {
		List<BlackboardArtifact> existingArtifacts = content.getArtifacts(artifactType.getTypeID());
		for (BlackboardArtifact artifact : existingArtifacts) {
			if (attributesMatch(artifact.getAttributes(), attributes)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Determines whether or not an artifact of a given type with a given set of
	 * attributes already exists for a given content.
	 *
	 * @param content      The content.
	 * @param artifactType The artifact type.
	 * @param attributes   The attributes.
	 *
	 * @return True or false
	 *
	 * @throws TskCoreException The exception is thrown if there is an issue
	 *                          querying the case database.
	 * @deprecated Use artifactExists(Content content, BlackboardArtifact.Type
	 * artifactType, Collection\<BlackboardAttribute\> attributes) instead.
	 */
	@Deprecated
	public boolean artifactExists(Content content, BlackboardArtifact.ARTIFACT_TYPE artifactType, Collection<BlackboardAttribute> attributes) throws TskCoreException {
		return artifactExists(content, getArtifactType(artifactType.getTypeID()), attributes);
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
	 * @param osAccountObjId  The OS account associated with the artifact.
	 *                        This method adds a instance type of ACCESSED to this account.
	 *                        May be null.
	 * @param transaction     The transaction in the scope of which the
	 *                        operation is to be performed.
	 *
	 * @return DataArtifact New blackboard artifact
	 *
	 * @throws TskCoreException If a critical error occurs within tsk core.
	 */
	public DataArtifact newDataArtifact(BlackboardArtifact.Type artifactType, long sourceObjId, Long dataSourceObjId,
			Collection<BlackboardAttribute> attributes, Long osAccountObjId, final CaseDbTransaction transaction) throws TskCoreException {

		return newDataArtifact(artifactType, sourceObjId, dataSourceObjId,
				attributes, osAccountObjId, OsAccountInstance.OsAccountInstanceType.ACCESSED, transaction);
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
	 * @param osAccountInstanceType The instance type to associate with the osAccountObjId.
	 *                        May be null.
	 * @param transaction     The transaction in the scope of which the
	 *                        operation is to be performed.
	 *
	 * @return DataArtifact New blackboard artifact
	 *
	 * @throws TskCoreException If a critical error occurs within tsk core.
	 */
	public DataArtifact newDataArtifact(BlackboardArtifact.Type artifactType, long sourceObjId, Long dataSourceObjId,
			Collection<BlackboardAttribute> attributes,
			Long osAccountObjId, OsAccountInstance.OsAccountInstanceType osAccountInstanceType,
			final CaseDbTransaction transaction) throws TskCoreException {

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
					
					// Add an OS account instance 
					if (Objects.nonNull(osAccountInstanceType)) {
						caseDb.getOsAccountManager().newOsAccountInstance(osAccountObjId, dataSourceObjId, osAccountInstanceType, connection);
					}
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
	 * An event published by SleuthkitCase when one or more artifacts are
	 * posted. Posted artifacts should be complete (all attributes have been
	 * added) and ready for further analysis.
	 */
	final public class ArtifactsPostedEvent {

		private final String moduleName;
		private final ImmutableSet<BlackboardArtifact.Type> artifactTypes;
		private final ImmutableSet<BlackboardArtifact> artifacts;
		private final Long ingestJobId;

		/**
		 * Constructs an event published by SleuthkitCase when one or more
		 * artifacts are posted. Posted artifacts should be complete (all
		 * attributes have been added) and ready for further analysis.
		 *
		 * @param artifacts   The artifacts. 
		 * @param moduleName  The display name of the module posting the
		 *                    artifacts.
		 * @param ingestJobId The numeric identifier of the ingest job within
		 *                    which the artifacts were posted, may be null.
		 */
		private ArtifactsPostedEvent(Collection<BlackboardArtifact> artifacts, String moduleName, Long ingestJobId) throws BlackboardException {
			Set<Integer> typeIDS = artifacts.stream()
					.map(BlackboardArtifact::getArtifactTypeID)
					.collect(Collectors.toSet());
			Set<BlackboardArtifact.Type> types = new HashSet<>();
			for (Integer typeID : typeIDS) {
				try {
					types.add(getArtifactType(typeID));
				} catch (TskCoreException tskCoreException) {
					throw new BlackboardException("Error getting artifact type by id.", tskCoreException);
				}
			}
			artifactTypes = ImmutableSet.copyOf(types);
			this.artifacts = ImmutableSet.copyOf(artifacts);
			this.moduleName = moduleName;
			this.ingestJobId = ingestJobId;
		}

		/**
		 * Gets the posted artifacts.
		 *
		 * @return The artifacts (data artifacts and/or analysis results).
		 */
		public Collection<BlackboardArtifact> getArtifacts() {
			return ImmutableSet.copyOf(artifacts);
		}

		/**
		 * Gets the posted artifacts of a given type.
		 *
		 * @param artifactType The artifact type.
		 *
		 * @return The artifacts, if any.
		 */
		public Collection<BlackboardArtifact> getArtifacts(BlackboardArtifact.Type artifactType) {
			Set<BlackboardArtifact> tempSet = artifacts.stream()
					.filter(artifact -> artifact.getArtifactTypeID() == artifactType.getTypeID())
					.collect(Collectors.toSet());
			return ImmutableSet.copyOf(tempSet);
		}

		/**
		 * Gets the display name of the module that posted the artifacts.
		 *
		 * @return The display name.
		 */
		public String getModuleName() {
			return moduleName;
		}

		/**
		 * Gets the types of artifacts that were posted.
		 *
		 * @return The types.
		 */
		public Collection<BlackboardArtifact.Type> getArtifactTypes() {
			return ImmutableSet.copyOf(artifactTypes);
		}

		/**
		 * Gets the numeric identifier of the ingest job for which the artifacts
		 * were posted.
		 *
		 * @return The ingest job ID, may be null.
		 */
		public Optional<Long> getIngestJobId() {
			return Optional.ofNullable(ingestJobId);
		}

	}
}
