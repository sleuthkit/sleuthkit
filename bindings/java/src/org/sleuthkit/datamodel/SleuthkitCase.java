/*
 * Sleuth Kit Data Model
 *
 * Copyright 2012-2014 Basis Technology Corp.
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

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE;
import org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE;
import org.sleuthkit.datamodel.SleuthkitJNI.CaseDbHandle.AddImageProcess;
import org.sleuthkit.datamodel.TskData.FileKnown;
import org.sleuthkit.datamodel.TskData.ObjectType;
import org.sleuthkit.datamodel.TskData.TSK_DB_FILES_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_META_FLAG_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_META_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_FLAG_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_TYPE_ENUM;
import org.sqlite.SQLiteConfig;
import org.sqlite.SQLiteJDBCLoader;

/**
 * Represents the case database with methods that provide abstractions for
 * database operations.
 */
public class SleuthkitCase {

	private static final int SCHEMA_VERSION_NUMBER = 3; // This must be the same as TSK_SCHEMA_VER in tsk/auto/db_sqlite.cpp.				
	private static final int DATABASE_LOCKED_ERROR = 0; // This should be 6 according to documentation, but it has been observed to be 0.
	private static final int SQLITE_BUSY_ERROR = 5;
	private static final long BASE_ARTIFACT_ID = Long.MIN_VALUE; // Artifact ids will start at the lowest negative value
	private static final Logger logger = Logger.getLogger(SleuthkitCase.class.getName());
	private static final ResourceBundle bundle = ResourceBundle.getBundle("org.sleuthkit.datamodel.Bundle");
	private final ConnectionPerThreadDispenser connections = new ConnectionPerThreadDispenser();
	private final ResultSetHelper rsHelper = new ResultSetHelper(this);
	private final Map<Long, Long> carvedFileContainersCache = new HashMap<Long, Long>(); // Caches the IDs of the root $CarvedFiles for each volume.
	private final Map<Long, FileSystem> fileSystemIdMap = new HashMap<Long, FileSystem>(); // Cache for file system results.
	private final ArrayList<ErrorObserver> errorObservers = new ArrayList<ErrorObserver>();
	private final String dbPath;
	private final String dbDirPath;
	private SleuthkitJNI.CaseDbHandle caseHandle; // Not currently used.
	private int versionNumber;
	private String dbBackupPath;
	private long nextArtifactId; // Used to ensure artifact ids come from the desired range.

	// This read/write lock is used to implement a layer of locking on top of 
	// the locking protocol provided by the underlying SQLite database. The Java
	// locking protocol improves performance for reasons that are not currently
	// understood. Note that the lock is contructed to use a fairness policy.
	private final ReentrantReadWriteLock rwLock = new ReentrantReadWriteLock(true);

	/**
	 * Private constructor, clients must use newCase() or openCase() method to
	 * create an instance of this class.
	 *
	 * @param dbPath The full path to a SQLite case database file.
	 * @param caseHandle A handle to a case database object in the native code
	 * SleuthKit layer.
	 * @throws Exception
	 */
	private SleuthkitCase(String dbPath, SleuthkitJNI.CaseDbHandle caseHandle) throws Exception {
		Class.forName("org.sqlite.JDBC");
		this.dbPath = dbPath;
		this.dbDirPath = new java.io.File(dbPath).getParentFile().getAbsolutePath();
		this.caseHandle = caseHandle;
		initBlackboardArtifactTypes();
		initBlackboardAttributeTypes();
		initNextArtifactId();
		updateDatabaseSchema();
		logSQLiteJDBCDriverInfo();
	}

	/**
	 * Make sure the predefined artifact types are in the artifact types table.
	 *
	 * @throws SQLException
	 */
	private void initBlackboardArtifactTypes() throws SQLException, TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		Statement statement = null;
		ResultSet resultSet = null;
		try {
			statement = connection.createStatement();
			for (ARTIFACT_TYPE type : ARTIFACT_TYPE.values()) {
				resultSet = connection.executeQuery(statement, "SELECT COUNT(*) from blackboard_artifact_types WHERE artifact_type_id = '" + type.getTypeID() + "'"); //NON-NLS
				if (resultSet.getLong(1) == 0) {
					connection.executeUpdate(statement, "INSERT INTO blackboard_artifact_types (artifact_type_id, type_name, display_name) VALUES (" + type.getTypeID() + " , '" + type.getLabel() + "', '" + type.getDisplayName() + "')"); //NON-NLS
				}
				resultSet.close();
				resultSet = null;
			}
		} finally {
			closeResultSet(resultSet);
			closeStatement(statement);
		}
	}

	/**
	 * Make sure the predefined artifact attribute types are in the artifact
	 * attribute types table.
	 *
	 * @throws SQLException
	 */
	private void initBlackboardAttributeTypes() throws SQLException, TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		Statement statement = null;
		ResultSet resultSet = null;
		try {
			statement = connection.createStatement();
			for (ATTRIBUTE_TYPE type : ATTRIBUTE_TYPE.values()) {
				resultSet = connection.executeQuery(statement, "SELECT COUNT(*) from blackboard_attribute_types WHERE attribute_type_id = '" + type.getTypeID() + "'"); //NON-NLS
				if (resultSet.getLong(1) == 0) {
					connection.executeUpdate(statement, "INSERT INTO blackboard_attribute_types (attribute_type_id, type_name, display_name) VALUES (" + type.getTypeID() + ", '" + type.getLabel() + "', '" + type.getDisplayName() + "')"); //NON-NLS
				}
				resultSet.close();
				resultSet = null;
			}
		} finally {
			closeResultSet(resultSet);
			closeStatement(statement);
		}
	}

	/**
	 * Initialize the next artifact id. If there are entries in the 
	 * blackboard_artifacts table we will use max(artifact_id) + 1
	 * otherwise we will initialize the value to 0x8000000000000000
	 * (the maximum negative signed long).
	 * @throws TskCoreException
	 * @throws SQLException 
	 */
	private void initNextArtifactId() throws TskCoreException, SQLException {
		CaseDbConnection connection = connections.getConnection();
		Statement statement = null;
		ResultSet resultSet = null;
		try {
			statement = connection.createStatement();
			resultSet = connection.executeQuery(statement, "SELECT MAX(artifact_id) FROM blackboard_artifacts");
			this.nextArtifactId = resultSet.getLong(1) + 1;
			if (this.nextArtifactId == 1) {
				this.nextArtifactId = BASE_ARTIFACT_ID;
			}
		} finally {
			closeResultSet(resultSet);
			closeStatement(statement);
		}		
	}
	
	/**
	 * Modify the case database to bring it up-to-date with the current version
	 * of the database schema.
	 *
	 * @throws Exception
	 */
	private void updateDatabaseSchema() throws Exception {
		CaseDbConnection connection = connections.getConnection();
		ResultSet resultSet = null;
		Statement statement = null;
		try {
			connection.beginTransaction();

			// Get the schema version number of the case database from the tsk_db_info table.
			int schemaVersionNumber = SCHEMA_VERSION_NUMBER;
			statement = connection.createStatement();
			resultSet = connection.executeQuery(statement, "SELECT schema_ver FROM tsk_db_info"); //NON-NLS
			if (resultSet.next()) {
				schemaVersionNumber = resultSet.getInt("schema_ver"); //NON-NLS
			}
			resultSet.close();
			resultSet = null;

			// Do the schema update(s), if needed.
			if (SCHEMA_VERSION_NUMBER != schemaVersionNumber) {
				// Make a backup copy of the database. Client code can get the path of the backup
				// using the getBackupDatabasePath() method.
				String backupFilePath = dbPath + ".schemaVer" + schemaVersionNumber + ".backup"; //NON-NLS
				copyCaseDB(backupFilePath);
				dbBackupPath = backupFilePath;

				// ***CALL SCHEMA UPDATE METHODS HERE***
				// Each method should examine the schema number passed to it and either:
				//    a. do nothing and return the schema version number unchanged, or
				//    b. upgrade the database and then increment and return the schema version number.
				schemaVersionNumber = updateFromSchema2toSchema3(schemaVersionNumber);

				// Write the updated schema version number to the the tsk_db_info table.
				connection.executeUpdate(statement, "UPDATE tsk_db_info SET schema_ver = " + schemaVersionNumber); //NON-NLS
			}
			versionNumber = schemaVersionNumber;

			connection.commitTransaction();
		} catch (Exception ex) { // Cannot do exception multi-catch in Java 6, so use catch-all.
			connection.rollbackTransaction();
			throw ex;
		} finally {
			closeResultSet(resultSet);
			closeStatement(statement);
		}
	}

	/**
	 * Make a duplicate / backup copy of the current case database. Makes a new
	 * copy only, and continues to use the current connection.
	 *
	 * @param newDBPath Path to the copy to be created. File will be overwritten
	 * if it exists.
	 * @throws IOException if copying fails.
	 */
	public void copyCaseDB(String newDBPath) throws IOException {
		InputStream in = null;
		OutputStream out = null;
		acquireExclusiveLock();
		try {
			InputStream inFile = new FileInputStream(dbPath);
			in = new BufferedInputStream(inFile);
			OutputStream outFile = new FileOutputStream(newDBPath);
			out = new BufferedOutputStream(outFile);
			int bytesRead = 0;
			while ((bytesRead = in.read()) != -1) {
				out.write(bytesRead);
			}
		} finally {
			try {
				if (in != null) {
					in.close();
				}
				if (out != null) {
					out.flush();
					out.close();
				}
			} catch (IOException e) {
				logger.log(Level.WARNING, "Could not close streams after db copy", e); //NON-NLS
			}
			releaseExclusiveLock();
		}
	}

	/**
	 * Write some SQLite JDBC driver details to the log file.
	 */
	private void logSQLiteJDBCDriverInfo() {
		try {
			SleuthkitCase.logger.info(String.format("sqlite-jdbc version %s loaded in %s mode", //NON-NLS
					SQLiteJDBCLoader.getVersion(), SQLiteJDBCLoader.isNativeMode()
							? "native" : "pure-java")); //NON-NLS		
		} catch (Exception ex) {
			SleuthkitCase.logger.log(Level.SEVERE, "Error querying case database mode", ex);
		}
	}

	/**
	 * Update a version 2 database schema to a version 3 database schema.
	 *
	 * @param schemaVersionNumber The schema version number of the database.
	 * @return 3, if the input database schema version number was 2.
	 * @throws SQLException
	 * @throws TskCoreException
	 */
	@SuppressWarnings("deprecation")
	private int updateFromSchema2toSchema3(int schemaVersionNumber) throws SQLException, TskCoreException {
		if (schemaVersionNumber != 2) {
			return schemaVersionNumber;
		}

		CaseDbConnection connection = connections.getConnection();
		Statement statement = null;
		Statement updateStatement = null;
		ResultSet resultSet = null;
		try {
			statement = connection.createStatement();

			// Add new tables for tags.
			statement.execute("CREATE TABLE tag_names (tag_name_id INTEGER PRIMARY KEY, display_name TEXT UNIQUE, description TEXT NOT NULL, color TEXT NOT NULL)"); //NON-NLS
			statement.execute("CREATE TABLE content_tags (tag_id INTEGER PRIMARY KEY, obj_id INTEGER NOT NULL, tag_name_id INTEGER NOT NULL, comment TEXT NOT NULL, begin_byte_offset INTEGER NOT NULL, end_byte_offset INTEGER NOT NULL)"); //NON-NLS
			statement.execute("CREATE TABLE blackboard_artifact_tags (tag_id INTEGER PRIMARY KEY, artifact_id INTEGER NOT NULL, tag_name_id INTEGER NOT NULL, comment TEXT NOT NULL)"); //NON-NLS

			// Add a new table for reports.
			statement.execute("CREATE TABLE reports (report_id INTEGER PRIMARY KEY, path TEXT NOT NULL, crtime INTEGER NOT NULL, src_module_name TEXT NOT NULL, report_name TEXT NOT NULL)"); //NON-NLS

			// Add new columns to the image info table.
			statement.execute("ALTER TABLE tsk_image_info ADD COLUMN size INTEGER;"); //NON-NLS
			statement.execute("ALTER TABLE tsk_image_info ADD COLUMN md5 TEXT;"); //NON-NLS
			statement.execute("ALTER TABLE tsk_image_info ADD COLUMN display_name TEXT;"); //NON-NLS

			// Add a new column to the file system info table.
			statement.execute("ALTER TABLE tsk_fs_info ADD COLUMN display_name TEXT;"); //NON-NLS

			// Add a new column to the file table.
			statement.execute("ALTER TABLE tsk_files ADD COLUMN meta_seq INTEGER;"); //NON-NLS

			// Add new columns and indexes to the attributes table and populate the
			// new column. Note that addition of the new column is a denormalization 
			// to optimize attribute queries.
			statement.execute("ALTER TABLE blackboard_attributes ADD COLUMN artifact_type_id INTEGER NULL NOT NULL DEFAULT -1;"); //NON-NLS
			statement.execute("CREATE INDEX attribute_artifactTypeId ON blackboard_attributes(artifact_type_id);"); //NON-NLS
			statement.execute("CREATE INDEX attribute_valueText ON blackboard_attributes(value_text);"); //NON-NLS
			statement.execute("CREATE INDEX attribute_valueInt32 ON blackboard_attributes(value_int32);"); //NON-NLS
			statement.execute("CREATE INDEX attribute_valueInt64 ON blackboard_attributes(value_int64);"); //NON-NLS
			statement.execute("CREATE INDEX attribute_valueDouble ON blackboard_attributes(value_double);"); //NON-NLS
			resultSet = statement.executeQuery(
					"SELECT attrs.artifact_id, arts.artifact_type_id " + //NON-NLS
					"FROM blackboard_attributes AS attrs " + //NON-NLS
					"INNER JOIN blackboard_artifacts AS arts " + //NON-NLS
					"WHERE attrs.artifact_id = arts.artifact_id;"); //NON-NLS
			updateStatement = connection.createStatement();
			while (resultSet.next()) {
				long artifactId = resultSet.getLong(1);
				int artifactTypeId = resultSet.getInt(2);
				updateStatement.executeUpdate(
						"UPDATE blackboard_attributes " + //NON-NLS
						"SET artifact_type_id = " + artifactTypeId + " " + //NON-NLS
						"WHERE blackboard_attributes.artifact_id = " + artifactId + ";"); //NON-NLS					
			}
			resultSet.close();
			resultSet = null;

			// Convert existing tag artifact and attribute rows to rows in the new tags tables.
			// TODO: This code depends on prepared statements that could evolve with
			// time, breaking this upgrade. The code that follows should be rewritten 
			// to do everything with SQL specific to case database schema version 2.
			HashMap<String, TagName> tagNames = new HashMap<String, TagName>();
			for (BlackboardArtifact artifact : getBlackboardArtifacts(ARTIFACT_TYPE.TSK_TAG_FILE)) {
				Content content = getContentById(artifact.getObjectID());
				String name = ""; //NON-NLS
				String comment = ""; //NON-NLS
				ArrayList<BlackboardAttribute> attributes = getBlackboardAttributes(artifact);
				for (BlackboardAttribute attribute : attributes) {
					if (attribute.getAttributeTypeID() == ATTRIBUTE_TYPE.TSK_TAG_NAME.getTypeID()) {
						name = attribute.getValueString();
					} else if (attribute.getAttributeTypeID() == ATTRIBUTE_TYPE.TSK_COMMENT.getTypeID()) {
						comment = attribute.getValueString();
					}
				}
				if (!name.isEmpty()) {
					TagName tagName;
					if (tagNames.containsKey(name)) {
						tagName = tagNames.get(name);
					} else {
						tagName = addTagName(name, "", TagName.HTML_COLOR.NONE); //NON-NLS
						tagNames.put(name, tagName);
					}
					addContentTag(content, tagName, comment, 0, content.getSize() - 1);
				}
			}
			for (BlackboardArtifact artifact : getBlackboardArtifacts(ARTIFACT_TYPE.TSK_TAG_ARTIFACT)) {
				long taggedArtifactId = -1;
				String name = ""; //NON-NLS
				String comment = ""; //NON-NLS
				ArrayList<BlackboardAttribute> attributes = getBlackboardAttributes(artifact);
				for (BlackboardAttribute attribute : attributes) {
					if (attribute.getAttributeTypeID() == ATTRIBUTE_TYPE.TSK_TAG_NAME.getTypeID()) {
						name = attribute.getValueString();
					} else if (attribute.getAttributeTypeID() == ATTRIBUTE_TYPE.TSK_COMMENT.getTypeID()) {
						comment = attribute.getValueString();
					} else if (attribute.getAttributeTypeID() == ATTRIBUTE_TYPE.TSK_TAGGED_ARTIFACT.getTypeID()) {
						taggedArtifactId = attribute.getValueLong();
					}
				}
				if (taggedArtifactId != -1 && !name.isEmpty()) {
					TagName tagName;
					if (tagNames.containsKey(name)) {
						tagName = tagNames.get(name);
					} else {
						tagName = addTagName(name, "", TagName.HTML_COLOR.NONE); //NON-NLS
						tagNames.put(name, tagName);
					}
					addBlackboardArtifactTag(getBlackboardArtifact(taggedArtifactId), tagName, comment);
				}
			}
			statement.execute(
					"DELETE FROM blackboard_attributes WHERE artifact_id IN " + //NON-NLS
					"(SELECT artifact_id FROM blackboard_artifacts WHERE artifact_type_id = " + ARTIFACT_TYPE.TSK_TAG_FILE.getTypeID() + //NON-NLS
					" OR artifact_type_id = " + ARTIFACT_TYPE.TSK_TAG_ARTIFACT.getTypeID() + ");"); //NON-NLS
			statement.execute(
					"DELETE FROM blackboard_artifacts WHERE " + //NON-NLS
					"artifact_type_id = " + ARTIFACT_TYPE.TSK_TAG_FILE.getTypeID() + //NON-NLS	
					" OR artifact_type_id = " + ARTIFACT_TYPE.TSK_TAG_ARTIFACT.getTypeID() + ";"); //NON-NLS

			return 3;
		} finally {
			closeStatement(updateStatement);
			closeResultSet(resultSet);
			closeStatement(statement);
		}
	}

	/**
	 * Returns case database schema version number.
	 *
	 * @return The schema version number as an integer.
	 */
	public int getSchemaVersion() {
		return this.versionNumber;
	}

	/**
	 * Returns the path of a backup copy of the database made when a schema
	 * version upgrade has occurred.
	 *
	 * @return The path of the backup file or null if no backup was made.
	 */
	public String getBackupDatabasePath() {
		return dbBackupPath;
	}

	/**
	 * Create a new transaction on the case database. The transaction object
	 * that is returned can be passed to methods that take a CaseDbTransaction.
	 * The caller is responsible for calling either commit() or rollback() on
	 * the transaction object.
	 *
	 * @return A CaseDbTransaction object.
	 * @throws TskCoreException
	 */
	public CaseDbTransaction beginTransaction() throws TskCoreException {
		return new CaseDbTransaction(connections.getConnection());
	}

	/**
	 * Get the full path to the case database directory.
	 *
	 * @return Absolute database directory path.
	 */
	public String getDbDirPath() {
		return dbDirPath;
	}

	/**
	 * Acquire the lock that provides exclusive access to the case database.
	 * Call this method in a try block with a call to the lock release method in
	 * an associated finally block.
	 */
	public void acquireExclusiveLock() {
		rwLock.writeLock().lock();
	}

	/**
	 * Release the lock that provides exclusive access to the database. This
	 * method should always be called in the finally block of a try block in
	 * which the lock was acquired.
	 */
	public void releaseExclusiveLock() {
		rwLock.writeLock().unlock();
	}

	/**
	 * Acquire the lock that provides shared access to the case database. Call
	 * this method in a try block with a call to the lock release method in an
	 * associated finally block.
	 */
	public void acquireSharedLock() {
		rwLock.readLock().lock();
	}

	/**
	 * Release the lock that provides shared access to the database. This method
	 * should always be called in the finally block of a try block in which the
	 * lock was acquired.
	 */
	public void releaseSharedLock() {
		rwLock.readLock().unlock();
	}

	/**
	 * Open an existing case database.
	 *
	 * @param dbPath Path to SQLite case database.
	 * @return Case database object.
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	public static SleuthkitCase openCase(String dbPath) throws TskCoreException {
		final SleuthkitJNI.CaseDbHandle caseHandle = SleuthkitJNI.openCaseDb(dbPath);
		try {
			return new SleuthkitCase(dbPath, caseHandle);
		} catch (Exception ex) {
			throw new TskCoreException("Failed to open case database at " + dbPath, ex);
		}
	}

	/**
	 * Create a new case database.
	 *
	 * @param dbPath Path to where SQlite case database should be created.
	 * @return Case database object.
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	public static SleuthkitCase newCase(String dbPath) throws TskCoreException {
		SleuthkitJNI.CaseDbHandle caseHandle = SleuthkitJNI.newCaseDb(dbPath);
		try {
			return new SleuthkitCase(dbPath, caseHandle);
		} catch (Exception ex) {
			throw new TskCoreException("Failed to create case database at " + dbPath, ex);
		}
	}

	/**
	 * Start process of adding a image to the case. Adding an image is a
	 * multi-step process and this returns an object that allows it to happen.
	 *
	 * @param timezone TZ time zone string to use for ingest of image.
	 * @param processUnallocSpace Set to true to process unallocated space in
	 * the image.
	 * @param noFatFsOrphans Set to true to skip processing orphan files of FAT
	 * file systems.
	 * @return Object that encapsulates control of adding an image via the
	 * SleuthKit native code layer.
	 */
	public AddImageProcess makeAddImageProcess(String timezone, boolean processUnallocSpace, boolean noFatFsOrphans) {
		return this.caseHandle.initAddImageProcess(timezone, processUnallocSpace, noFatFsOrphans);
	}

	/**
	 * Get the list of root objects (data sources) from the case database, e.g.,
	 * image files, logical (local) files, virtual directories.
	 *
	 * @return List of content objects representing root objects.
	 * @throws TskCoreException
	 */
	public List<Content> getRootObjects() throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT obj_id, type from tsk_objects " //NON-NLS
					+ "WHERE par_obj_id IS NULL"); //NON-NLS			
			Collection<ObjectInfo> infos = new ArrayList<ObjectInfo>();
			while (rs.next()) {
				infos.add(new ObjectInfo(rs.getLong("obj_id"), ObjectType.valueOf(rs.getShort("type")))); //NON-NLS
			}

			List<Content> rootObjs = new ArrayList<Content>();
			for (ObjectInfo i : infos) {
				if (i.type == ObjectType.IMG) {
					rootObjs.add(getImageById(i.id));
				} else if (i.type == ObjectType.ABSTRACTFILE) {
					// Check if virtual dir for local files.
					AbstractFile af = getAbstractFileById(i.id);
					if (af instanceof VirtualDirectory) {
						rootObjs.add(af);
					} else {
						throw new TskCoreException("Parentless object has wrong type to be a root (ABSTRACTFILE, but not VIRTUAL_DIRECTORY: " + i.type);
					}
				} else {
					throw new TskCoreException("Parentless object has wrong type to be a root: " + i.type);
				}
			}
			return rootObjs;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting root objects", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseSharedLock();
		}
	}

	/**
	 * Get all blackboard artifacts of a given type.
	 *
	 * @param artifactTypeID artifact type id (must exist in database)
	 * @return list of blackboard artifacts.
	 * @throws TskCoreException
	 */
	public ArrayList<BlackboardArtifact> getBlackboardArtifacts(int artifactTypeID) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		ResultSet rs = null;
		try {
			String artifactTypeName = getArtifactTypeString(artifactTypeID);
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.SELECT_ARTIFACTS_BY_TYPE);
			statement.clearParameters();
			statement.setInt(1, artifactTypeID);
			rs = connection.executeQuery(statement);
			ArrayList<BlackboardArtifact> artifacts = new ArrayList<BlackboardArtifact>();
			while (rs.next()) {
				artifacts.add(new BlackboardArtifact(this, rs.getLong(1), rs.getLong(2),
						artifactTypeID, artifactTypeName, ARTIFACT_TYPE.fromID(artifactTypeID).getDisplayName()));
			}
			return artifacts;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting or creating a blackboard artifact", ex);
		} finally {
			closeResultSet(rs);
			releaseSharedLock();
		}
	}

	/**
	 * Get a count of blackboard artifacts for a given content.
	 *
	 * @param objId Id of the content.
	 * @return The artifacts count for the content.
	 * @throws TskCoreException
	 */
	public long getBlackboardArtifactsCount(long objId) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		ResultSet rs = null;
		try {
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.COUNT_ARTIFACTS_FROM_SOURCE);
			statement.clearParameters();
			statement.setLong(1, objId);
			rs = connection.executeQuery(statement);
			long count = 0;
			if (rs.next()) {
				count = rs.getLong(1);
			}
			return count;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting number of blackboard artifacts by content", ex);
		} finally {
			closeResultSet(rs);
			releaseSharedLock();
		}
	}

	/**
	 * Get a count of artifacts of a given type.
	 *
	 * @param artifactTypeID Id of the artifact type.
	 * @return The artifacts count for the type.
	 * @throws TskCoreException
	 */
	public long getBlackboardArtifactsTypeCount(int artifactTypeID) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		ResultSet rs = null;
		try {
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.COUNT_ARTIFACTS_OF_TYPE);
			statement.clearParameters();
			statement.setInt(1, artifactTypeID);
			rs = connection.executeQuery(statement);
			long count = 0;
			if (rs.next()) {
				count = rs.getLong(1);
			}
			return count;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting number of blackboard artifacts by type", ex);
		} finally {
			closeResultSet(rs);
			releaseSharedLock();
		}
	}

	/**
	 * Helper to iterate over blackboard artifacts result set containing all
	 * columns and return a list of artifacts in the set. Must be enclosed in
	 * acquireSharedLock. Result set and statement must be freed by the caller.
	 *
	 * @param rs existing, active result set (not closed by this method)
	 * @return a list of blackboard artifacts in the result set
	 * @throws SQLException if result set could not be iterated upon
	 */
	private List<BlackboardArtifact> getArtifactsHelper(ResultSet rs) throws SQLException {
		ArrayList<BlackboardArtifact> artifacts = new ArrayList<BlackboardArtifact>();
		while (rs.next()) {
			final int artifactTypeID = rs.getInt(3);
			final ARTIFACT_TYPE artType = ARTIFACT_TYPE.fromID(artifactTypeID);
			artifacts.add(new BlackboardArtifact(this, rs.getLong(1), rs.getLong(2),
					artifactTypeID, artType.getLabel(), artType.getDisplayName()));
		}
		return artifacts;
	}

	/**
	 * Get all blackboard artifacts that have an attribute of the given type and
	 * String value
	 *
	 * @param attrType attribute of this attribute type to look for in the
	 * artifacts
	 * @param value value of the attribute of the attrType type to look for
	 * @return a list of blackboard artifacts with such an attribute
	 * @throws TskCoreException exception thrown if a critical error occurred
	 * within tsk core and artifacts could not be queried
	 */
	public List<BlackboardArtifact> getBlackboardArtifacts(BlackboardAttribute.ATTRIBUTE_TYPE attrType, String value) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT DISTINCT blackboard_artifacts.artifact_id, " //NON-NLS
					+ "blackboard_artifacts.obj_id, blackboard_artifacts.artifact_type_id " //NON-NLS
					+ "FROM blackboard_artifacts, blackboard_attributes " //NON-NLS
					+ "WHERE blackboard_artifacts.artifact_id = blackboard_attributes.artifact_id " //NON-NLS
					+ "AND blackboard_attributes.attribute_type_id IS " + attrType.getTypeID() //NON-NLS
					+ " AND blackboard_attributes.value_text IS '" + value + "'");	 //NON-NLS
			return getArtifactsHelper(rs);
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting blackboard artifacts by attribute", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseSharedLock();
		}
	}

	/**
	 * Get all blackboard artifacts that have an attribute of the given type and
	 * String value
	 *
	 * @param attrType attribute of this attribute type to look for in the
	 * artifacts
	 * @param subString value substring of the string attribute of the attrType
	 * type to look for
	 * @param startsWith if true, the artifact attribute string should start
	 * with the substring, if false, it should just contain it
	 * @return a list of blackboard artifacts with such an attribute
	 * @throws TskCoreException exception thrown if a critical error occurred
	 * within tsk core and artifacts could not be queried
	 */
	public List<BlackboardArtifact> getBlackboardArtifacts(BlackboardAttribute.ATTRIBUTE_TYPE attrType, String subString, boolean startsWith) throws TskCoreException {
		subString = "%" + subString; //NON-NLS
		if (startsWith == false) {
			subString = subString + "%"; //NON-NLS
		}
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT DISTINCT blackboard_artifacts.artifact_id, " //NON-NLS
					+ "blackboard_artifacts.obj_id, blackboard_artifacts.artifact_type_id " //NON-NLS
					+ "FROM blackboard_artifacts, blackboard_attributes " //NON-NLS
					+ "WHERE blackboard_artifacts.artifact_id = blackboard_attributes.artifact_id " //NON-NLS
					+ "AND blackboard_attributes.attribute_type_id IS " + attrType.getTypeID() //NON-NLS
					+ " AND blackboard_attributes.value_text LIKE '" + subString + "'"); //NON-NLS			
			return getArtifactsHelper(rs);
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting blackboard artifacts by attribute. " + ex.getMessage(), ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseSharedLock();
		}
	}

	/**
	 * Get all blackboard artifacts that have an attribute of the given type and
	 * integer value
	 *
	 * @param attrType attribute of this attribute type to look for in the
	 * artifacts
	 * @param value value of the attribute of the attrType type to look for
	 * @return a list of blackboard artifacts with such an attribute
	 * @throws TskCoreException exception thrown if a critical error occurred
	 * within tsk core and artifacts could not be queried
	 */
	public List<BlackboardArtifact> getBlackboardArtifacts(BlackboardAttribute.ATTRIBUTE_TYPE attrType, int value) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT DISTINCT blackboard_artifacts.artifact_id, " //NON-NLS
					+ "blackboard_artifacts.obj_id, blackboard_artifacts.artifact_type_id " //NON-NLS
					+ "FROM blackboard_artifacts, blackboard_attributes " //NON-NLS
					+ "WHERE blackboard_artifacts.artifact_id = blackboard_attributes.artifact_id " //NON-NLS
					+ "AND blackboard_attributes.attribute_type_id IS " + attrType.getTypeID() //NON-NLS
					+ " AND blackboard_attributes.value_int32 IS " + value); //NON-NLS
			return getArtifactsHelper(rs);
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting blackboard artifacts by attribute", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseSharedLock();
		}
	}

	/**
	 * Get all blackboard artifacts that have an attribute of the given type and
	 * long value
	 *
	 * @param attrType attribute of this attribute type to look for in the
	 * artifacts
	 * @param value value of the attribute of the attrType type to look for
	 * @return a list of blackboard artifacts with such an attribute
	 * @throws TskCoreException exception thrown if a critical error occurred
	 * within tsk core and artifacts could not be queried
	 */
	public List<BlackboardArtifact> getBlackboardArtifacts(BlackboardAttribute.ATTRIBUTE_TYPE attrType, long value) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT DISTINCT blackboard_artifacts.artifact_id, " //NON-NLS
					+ "blackboard_artifacts.obj_id, blackboard_artifacts.artifact_type_id " //NON-NLS
					+ "FROM blackboard_artifacts, blackboard_attributes " //NON-NLS
					+ "WHERE blackboard_artifacts.artifact_id = blackboard_attributes.artifact_id " //NON-NLS
					+ "AND blackboard_attributes.attribute_type_id IS " + attrType.getTypeID() //NON-NLS
					+ " AND blackboard_attributes.value_int64 IS " + value); //NON-NLS			
			return getArtifactsHelper(rs);
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting blackboard artifacts by attribute. " + ex.getMessage(), ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseSharedLock();
		}
	}

	/**
	 * Get all blackboard artifacts that have an attribute of the given type and
	 * double value
	 *
	 * @param attrType attribute of this attribute type to look for in the
	 * artifacts
	 * @param value value of the attribute of the attrType type to look for
	 * @return a list of blackboard artifacts with such an attribute
	 * @throws TskCoreException exception thrown if a critical error occurred
	 * within tsk core and artifacts could not be queried
	 */
	public List<BlackboardArtifact> getBlackboardArtifacts(BlackboardAttribute.ATTRIBUTE_TYPE attrType, double value) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT DISTINCT blackboard_artifacts.artifact_id, " //NON-NLS
					+ "blackboard_artifacts.obj_id, blackboard_artifacts.artifact_type_id " //NON-NLS
					+ "FROM blackboard_artifacts, blackboard_attributes " //NON-NLS
					+ "WHERE blackboard_artifacts.artifact_id = blackboard_attributes.artifact_id " //NON-NLS
					+ "AND blackboard_attributes.attribute_type_id IS " + attrType.getTypeID() //NON-NLS
					+ " AND blackboard_attributes.value_double IS " + value); //NON-NLS
			return getArtifactsHelper(rs);
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting blackboard artifacts by attribute", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseSharedLock();
		}
	}

	/**
	 * Get all blackboard artifacts that have an attribute of the given type and
	 * byte value
	 *
	 * @param attrType attribute of this attribute type to look for in the
	 * artifacts
	 * @param value value of the attribute of the attrType type to look for
	 * @return a list of blackboard artifacts with such an attribute
	 * @throws TskCoreException exception thrown if a critical error occurred
	 * within tsk core and artifacts could not be queried
	 */
	public List<BlackboardArtifact> getBlackboardArtifacts(BlackboardAttribute.ATTRIBUTE_TYPE attrType, byte value) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT DISTINCT blackboard_artifacts.artifact_id, " //NON-NLS
					+ "blackboard_artifacts.obj_id, blackboard_artifacts.artifact_type_id " //NON-NLS
					+ "FROM blackboard_artifacts, blackboard_attributes " //NON-NLS
					+ "WHERE blackboard_artifacts.artifact_id = blackboard_attributes.artifact_id " //NON-NLS
					+ "AND blackboard_attributes.attribute_type_id IS " + attrType.getTypeID() //NON-NLS
					+ " AND blackboard_attributes.value_byte IS " + value); //NON-NLS
			return getArtifactsHelper(rs);
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting blackboard artifacts by attribute", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseSharedLock();
		}
	}

	/**
	 * Get _standard_ blackboard artifact types in use. This does not currently
	 * return user-defined ones.
	 *
	 * @return list of blackboard artifact types
	 * @throws TskCoreException exception thrown if a critical error occurred
	 * within tsk core
	 */
	public ArrayList<BlackboardArtifact.ARTIFACT_TYPE> getBlackboardArtifactTypes() throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT artifact_type_id FROM blackboard_artifact_types"); //NON-NLS			
			ArrayList<BlackboardArtifact.ARTIFACT_TYPE> artifact_types = new ArrayList<BlackboardArtifact.ARTIFACT_TYPE>();
			while (rs.next()) {
				/*
				 * Only return ones in the enum because otherwise exceptions
				 * get thrown down the call stack. Need to remove use of enum
				 * for the attribute types */
				for (BlackboardArtifact.ARTIFACT_TYPE artType : BlackboardArtifact.ARTIFACT_TYPE.values()) {
					if (artType.getTypeID() == rs.getInt(1)) {
						artifact_types.add(artType);
					}
				}
			}
			return artifact_types;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting artifact types", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseSharedLock();
		}
	}

	/**
	 * Get all of the blackboard artifact types that are in use in the
	 * blackboard.
	 *
	 * @return List of blackboard artifact types
	 * @throws TskCoreException
	 */
	public ArrayList<BlackboardArtifact.ARTIFACT_TYPE> getBlackboardArtifactTypesInUse() throws TskCoreException {
		// @@@ TODO: This should be rewritten as a single query. 		
		ArrayList<BlackboardArtifact.ARTIFACT_TYPE> allArts = getBlackboardArtifactTypes();
		ArrayList<BlackboardArtifact.ARTIFACT_TYPE> usedArts = new ArrayList<BlackboardArtifact.ARTIFACT_TYPE>();
		for (BlackboardArtifact.ARTIFACT_TYPE art : allArts) {
			if (getBlackboardArtifactsTypeCount(art.getTypeID()) > 0) {
				usedArts.add(art);
			}
		}
		return usedArts;
	}

	/**
	 * Get all blackboard attribute types
	 *
	 * Gets both static (in enum) and dynamic attributes types (created by
	 * modules at runtime)
	 *
	 * @return list of blackboard attribute types
	 * @throws TskCoreException exception thrown if a critical error occurred
	 * within tsk core
	 */
	public ArrayList<BlackboardAttribute.ATTRIBUTE_TYPE> getBlackboardAttributeTypes() throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT type_name FROM blackboard_attribute_types"); //NON-NLS
			ArrayList<BlackboardAttribute.ATTRIBUTE_TYPE> attribute_types = new ArrayList<BlackboardAttribute.ATTRIBUTE_TYPE>();
			while (rs.next()) {
				attribute_types.add(BlackboardAttribute.ATTRIBUTE_TYPE.fromLabel(rs.getString(1)));
			}
			return attribute_types;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting attribute types", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseSharedLock();
		}
	}

	/**
	 * Get count of blackboard attribute types
	 *
	 * Counts both static (in enum) and dynamic attributes types (created by
	 * modules at runtime)
	 *
	 * @return count of attribute types
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within TSK core
	 */
	public int getBlackboardAttributeTypesCount() throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT COUNT(*) FROM blackboard_attribute_types"); //NON-NLS
			int count = 0;
			if (rs.next()) {
				count = rs.getInt(1);
			}
			return count;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting number of blackboard artifacts by type", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseSharedLock();
		}
	}

	/**
	 * Helper method to get all artifacts matching the type id name and object
	 * id
	 *
	 * @param artifactTypeID artifact type id
	 * @param artifactTypeName artifact type name
	 * @param obj_id associated object id
	 * @return list of blackboard artifacts
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within TSK core
	 */
	private ArrayList<BlackboardArtifact> getArtifactsHelper(int artifactTypeID, String artifactTypeName, long obj_id) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		ResultSet rs = null;
		try {
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.SELECT_ARTIFACTS_BY_SOURCE_AND_TYPE);
			statement.clearParameters();
			statement.setLong(1, obj_id);
			statement.setInt(2, artifactTypeID);
			rs = connection.executeQuery(statement);
			ArrayList<BlackboardArtifact> artifacts = new ArrayList<BlackboardArtifact>();
			while (rs.next()) {
				artifacts.add(new BlackboardArtifact(this, rs.getLong(1), obj_id, artifactTypeID, artifactTypeName, this.getArtifactTypeDisplayName(artifactTypeID)));
			}
			return artifacts;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting or creating a blackboard artifact", ex);
		} finally {
			closeResultSet(rs);
			releaseSharedLock();
		}
	}

	/**
	 * Helper method to get count of all artifacts matching the type id name and
	 * object id
	 *
	 * @param artifactTypeID artifact type id
	 * @param obj_id associated object id
	 * @return count of matching blackboard artifacts
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within TSK core
	 */
	private long getArtifactsCountHelper(int artifactTypeID, long obj_id) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		ResultSet rs = null;
		try {
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.COUNT_ARTIFACTS_BY_SOURCE_AND_TYPE);
			statement.clearParameters();
			statement.setLong(1, obj_id);
			statement.setInt(2, artifactTypeID);
			rs = connection.executeQuery(statement);
			long count = 0;
			if (rs.next()) {
				count = rs.getLong(1);
			}
			return count;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting blackboard artifact count", ex);
		} finally {
			closeResultSet(rs);
			releaseSharedLock();
		}
	}

	/**
	 * Helper method to get all artifacts matching the type id name.
	 *
	 * @param artifactTypeID artifact type id
	 * @param artifactTypeName artifact type name
	 * @return list of blackboard artifacts
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within TSK core
	 */
	private ArrayList<BlackboardArtifact> getArtifactsHelper(int artifactTypeID, String artifactTypeName) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		ResultSet rs = null;
		try {
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.SELECT_ARTIFACTS_BY_TYPE);
			statement.clearParameters();
			statement.setInt(1, artifactTypeID);
			rs = connection.executeQuery(statement);
			ArrayList<BlackboardArtifact> artifacts = new ArrayList<BlackboardArtifact>();
			while (rs.next()) {
				artifacts.add(new BlackboardArtifact(this, rs.getLong(1), rs.getLong(2), artifactTypeID, artifactTypeName, this.getArtifactTypeDisplayName(artifactTypeID)));
			}
			return artifacts;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting or creating a blackboard artifact", ex);
		} finally {
			closeResultSet(rs);
			releaseSharedLock();
		}
	}

	/**
	 * Get all blackboard artifacts of a given type for the given object id
	 *
	 * @param artifactTypeName artifact type name
	 * @param obj_id object id
	 * @return list of blackboard artifacts
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within TSK core
	 */
	public ArrayList<BlackboardArtifact> getBlackboardArtifacts(String artifactTypeName, long obj_id) throws TskCoreException {
		int artifactTypeID = this.getArtifactTypeID(artifactTypeName);
		if (artifactTypeID == -1) {
			return new ArrayList<BlackboardArtifact>();
		}
		return getArtifactsHelper(artifactTypeID, artifactTypeName, obj_id);
	}

	/**
	 * Get all blackboard artifacts of a given type for the given object id
	 *
	 * @param artifactTypeID artifact type id (must exist in database)
	 * @param obj_id object id
	 * @return list of blackboard artifacts
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within TSK core
	 */
	public ArrayList<BlackboardArtifact> getBlackboardArtifacts(int artifactTypeID, long obj_id) throws TskCoreException {
		String artifactTypeName = this.getArtifactTypeString(artifactTypeID);
		return getArtifactsHelper(artifactTypeID, artifactTypeName, obj_id);
	}

	/**
	 * Get all blackboard artifacts of a given type for the given object id
	 *
	 * @param artifactType artifact type enum
	 * @param obj_id object id
	 * @return list of blackboard artifacts
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within TSK core
	 */
	public ArrayList<BlackboardArtifact> getBlackboardArtifacts(ARTIFACT_TYPE artifactType, long obj_id) throws TskCoreException {
		return getArtifactsHelper(artifactType.getTypeID(), artifactType.getLabel(), obj_id);
	}

	/**
	 * Get count of all blackboard artifacts of a given type for the given
	 * object id
	 *
	 * @param artifactTypeName artifact type name
	 * @param obj_id object id
	 * @return count of blackboard artifacts
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within TSK core
	 */
	public long getBlackboardArtifactsCount(String artifactTypeName, long obj_id) throws TskCoreException {
		int artifactTypeID = this.getArtifactTypeID(artifactTypeName);
		if (artifactTypeID == -1) {
			return 0;
		}
		return getArtifactsCountHelper(artifactTypeID, obj_id);
	}

	/**
	 * Get count of all blackboard artifacts of a given type for the given
	 * object id
	 *
	 * @param artifactTypeID artifact type id (must exist in database)
	 * @param obj_id object id
	 * @return count of blackboard artifacts
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within TSK core
	 */
	public long getBlackboardArtifactsCount(int artifactTypeID, long obj_id) throws TskCoreException {
		return getArtifactsCountHelper(artifactTypeID, obj_id);
	}

	/**
	 * Get count of all blackboard artifacts of a given type for the given
	 * object id
	 *
	 * @param artifactType artifact type enum
	 * @param obj_id object id
	 * @return count of blackboard artifacts
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within TSK core
	 */
	public long getBlackboardArtifactsCount(ARTIFACT_TYPE artifactType, long obj_id) throws TskCoreException {
		return getArtifactsCountHelper(artifactType.getTypeID(), obj_id);
	}

	/**
	 * Get all blackboard artifacts of a given type
	 *
	 * @param artifactTypeName artifact type name
	 * @return list of blackboard artifacts
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within TSK core
	 */
	public ArrayList<BlackboardArtifact> getBlackboardArtifacts(String artifactTypeName) throws TskCoreException {
		int artifactTypeID = this.getArtifactTypeID(artifactTypeName);
		if (artifactTypeID == -1) {
			return new ArrayList<BlackboardArtifact>();
		}
		return getArtifactsHelper(artifactTypeID, artifactTypeName);
	}

	/**
	 * Get all blackboard artifacts of a given type
	 *
	 * @param artifactType artifact type enum
	 * @return list of blackboard artifacts
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within TSK core
	 */
	public ArrayList<BlackboardArtifact> getBlackboardArtifacts(ARTIFACT_TYPE artifactType) throws TskCoreException {
		return getArtifactsHelper(artifactType.getTypeID(), artifactType.getLabel());
	}

	/**
	 * Get all blackboard artifacts of a given type with an attribute of a given
	 * type and String value.
	 *
	 * @param artifactType artifact type enum
	 * @param attrType attribute type enum
	 * @param value String value of attribute
	 * @return list of blackboard artifacts
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within TSK core
	 */
	public List<BlackboardArtifact> getBlackboardArtifacts(ARTIFACT_TYPE artifactType, BlackboardAttribute.ATTRIBUTE_TYPE attrType, String value) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT DISTINCT blackboard_artifacts.artifact_id, " //NON-NLS
					+ "blackboard_artifacts.obj_id, blackboard_artifacts.artifact_type_id " //NON-NLS
					+ "FROM blackboard_artifacts, blackboard_attributes " //NON-NLS
					+ "WHERE blackboard_artifacts.artifact_id = blackboard_attributes.artifact_id " //NON-NLS
					+ "AND blackboard_attributes.attribute_type_id IS " + attrType.getTypeID() //NON-NLS
					+ " AND blackboard_artifacts.artifact_type_id = " + artifactType.getTypeID() //NON-NLS
					+ " AND blackboard_attributes.value_text IS '" + value + "'"); //NON-NLS
			return getArtifactsHelper(rs);
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting blackboard artifacts by artifact type and attribute. " + ex.getMessage(), ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseSharedLock();
		}
	}

	/**
	 * Get the blackboard artifact with the given artifact id
	 *
	 * @param artifactID artifact ID
	 * @return blackboard artifact
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within TSK core
	 */
	public BlackboardArtifact getBlackboardArtifact(long artifactID) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		ResultSet rs = null;
		try {
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.SELECT_ARTIFACT_BY_ID);
			statement.clearParameters();
			statement.setLong(1, artifactID);
			rs = connection.executeQuery(statement);
			long obj_id = rs.getLong(1);
			int artifact_type_id = rs.getInt(2);
			return new BlackboardArtifact(this, artifactID, obj_id, artifact_type_id,
					this.getArtifactTypeString(artifact_type_id), this.getArtifactTypeDisplayName(artifact_type_id));
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting a blackboard artifact. " + ex.getMessage(), ex);
		} finally {
			closeResultSet(rs);
			releaseSharedLock();
		}
	}

	/**
	 * Add a blackboard attribute.
	 *
	 * @param attr A blackboard attribute.
	 * @param artifactTypeId The type of artifact associated with the attribute.
	 * @throws TskCoreException thrown if a critical error occurs.
	 */
	public void addBlackboardAttribute(BlackboardAttribute attr, int artifactTypeId) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireExclusiveLock();
		try {
			addBlackBoardAttribute(attr, artifactTypeId, connection);
		} catch (SQLException ex) {
			throw new TskCoreException("Error adding blackboard attribute " + attr.toString(), ex);
		} finally {
			releaseExclusiveLock();
		}
	}

	/**
	 * Add a set blackboard attributes.
	 *
	 * @param attributes A set of blackboard attribute.
	 * @param artifactTypeId The type of artifact associated with the
	 * attributes.
	 * @throws TskCoreException thrown if a critical error occurs.
	 */
	public void addBlackboardAttributes(Collection<BlackboardAttribute> attributes, int artifactTypeId) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireExclusiveLock();
		try {
			connection.beginTransaction();
			for (final BlackboardAttribute attr : attributes) {
				addBlackBoardAttribute(attr, artifactTypeId, connection);
			}
			connection.commitTransaction();
		} catch (SQLException ex) {
			connection.rollbackTransaction();
			throw new TskCoreException("Error adding blackboard attributes", ex);
		} finally {
			releaseExclusiveLock();
		}
	}

	private void addBlackBoardAttribute(BlackboardAttribute attr, int artifactTypeId, CaseDbConnection connection) throws SQLException, TskCoreException {
		PreparedStatement statement;
		switch (attr.getValueType()) {
			case STRING:
				statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.INSERT_STRING_ATTRIBUTE);
				statement.clearParameters();
				statement.setString(7, escapeForBlackboard(attr.getValueString()));
				break;
			case BYTE:
				statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.INSERT_BYTE_ATTRIBUTE);
				statement.clearParameters();
				statement.setBytes(7, attr.getValueBytes());
				break;
			case INTEGER:
				statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.INSERT_INT_ATTRIBUTE);
				statement.clearParameters();
				statement.setInt(7, attr.getValueInt());
				break;
			case LONG:
				statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.INSERT_LONG_ATTRIBUTE);
				statement.clearParameters();
				statement.setLong(7, attr.getValueLong());
				break;
			case DOUBLE:
				statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.INSERT_DOUBLE_ATTRIBUTE);
				statement.clearParameters();
				statement.setDouble(7, attr.getValueDouble());
				break;
			default:
				throw new TskCoreException("Unrecognized artifact attribute value type");
		}
		statement.setLong(1, attr.getArtifactID());
		statement.setInt(2, artifactTypeId);
		statement.setString(3, attr.getModuleName());
		statement.setString(4, attr.getContext());
		statement.setInt(5, attr.getAttributeTypeID());
		statement.setLong(6, attr.getValueType().getType());
		connection.executeUpdate(statement);
	}

	/**
	 * add an attribute type with the given name
	 *
	 * @param attrTypeString name of the new attribute
	 * @param displayName the (non-unique) display name of the attribute type
	 * @return the id of the new attribute
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within tsk core
	 */
	public int addAttrType(String attrTypeString, String displayName) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireExclusiveLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			connection.beginTransaction();
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT attribute_type_id FROM blackboard_attribute_types WHERE type_name = '" + attrTypeString + "'"); //NON-NLS
			if (!rs.next()) {
				rs.close();
				connection.executeUpdate(s, "INSERT INTO blackboard_artifact_types (type_name, display_name) VALUES ('" + attrTypeString + "', '" + displayName + "')"); //NON-NLS
				rs = s.getGeneratedKeys();
			}
			int type = rs.getInt(1);
			connection.commitTransaction();
			return type;
		} catch (SQLException ex) {
			connection.rollbackTransaction();
			throw new TskCoreException("Error adding attribute type", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseExclusiveLock();
		}
	}

	/**
	 * Get the attribute type id associated with an attribute type name.
	 *
	 * @param attrTypeName An attribute type name.
	 * @return An attribute id or -1 if the attribute type does not exist.
	 * @throws TskCoreException If an error occurs accessing the case database.
	 *
	 */
	public int getAttrTypeID(String attrTypeName) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT attribute_type_id FROM blackboard_attribute_types WHERE type_name = '" + attrTypeName + "'"); //NON-NLS
			int typeId = -1;
			if (rs.next()) {
				typeId = rs.getInt(1);
			}
			return typeId;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting attribute type id", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseSharedLock();
		}
	}

	/**
	 * Get the string associated with the given id. Will throw an error if that
	 * id does not exist
	 *
	 * @param attrTypeID attribute id
	 * @return string associated with the given id
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within tsk core
	 */
	public String getAttrTypeString(int attrTypeID) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT type_name FROM blackboard_attribute_types WHERE attribute_type_id = " + attrTypeID); //NON-NLS
			if (rs.next()) {
				return rs.getString(1);
			} else {
				throw new TskCoreException("No type with that id");
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting or creating a attribute type name", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseSharedLock();
		}
	}

	/**
	 * Get the display name for the attribute with the given id. Will throw an
	 * error if that id does not exist
	 *
	 * @param attrTypeID attribute id
	 * @return string associated with the given id
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within tsk core
	 */
	public String getAttrTypeDisplayName(int attrTypeID) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT display_name FROM blackboard_attribute_types WHERE attribute_type_id = " + attrTypeID); //NON-NLS
			if (rs.next()) {
				return rs.getString(1);
			} else {
				throw new TskCoreException("No type with that id");
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting or creating a attribute type name", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseSharedLock();
		}
	}

	/**
	 * Get the artifact type id associated with an artifact type name.
	 *
	 * @param artifactTypeName An artifact type name.
	 * @return An artifact id or -1 if the attribute type does not exist.
	 * @throws TskCoreException If an error occurs accessing the case database.
	 *
	 */
	public int getArtifactTypeID(String artifactTypeName) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT artifact_type_id FROM blackboard_artifact_types WHERE type_name = '" + artifactTypeName + "'"); //NON-NLS
			int typeId = -1;
			if (rs.next()) {
				typeId = rs.getInt(1);
			}
			return typeId;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting artifact type id", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseSharedLock();
		}
	}

	/**
	 * Get artifact type name for the given string. Will throw an error if that
	 * artifact doesn't exist. Use addArtifactType(...) to create a new one.
	 *
	 * @param artifactTypeID id for an artifact type
	 * @return name of that artifact type
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within tsk core
	 */
	String getArtifactTypeString(int artifactTypeID) throws TskCoreException {
		// TODO: This should return null, not throw an exception
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT type_name FROM blackboard_artifact_types WHERE artifact_type_id = " + artifactTypeID); //NON-NLS
			if (rs.next()) {
				return rs.getString(1);
			} else {
				throw new TskCoreException("Error getting artifact type name, artifact type id = " + artifactTypeID + " not found");
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting artifact type name, artifact type id = " + artifactTypeID, ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseSharedLock();
		}
	}

	/**
	 * Get artifact type display name for the given string. Will throw an error
	 * if that artifact doesn't exist. Use addArtifactType(...) to create a new
	 * one.
	 *
	 * @param artifactTypeID id for an artifact type
	 * @return display name of that artifact type
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within tsk core
	 */
	String getArtifactTypeDisplayName(int artifactTypeID) throws TskCoreException {
		// TODO: This should return null, not throw an exception
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT display_name FROM blackboard_artifact_types WHERE artifact_type_id = " + artifactTypeID); //NON-NLS
			if (rs.next()) {
				return rs.getString(1);
			} else {
				throw new TskCoreException("Error getting artifact type display name, artifact type id = " + artifactTypeID + " not found");
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting artifact type display name, artifact type id = " + artifactTypeID, ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseSharedLock();
		}
	}

	/**
	 * Add an artifact type with the given name. Will return an id that can be
	 * used to look that artifact type up.
	 *
	 * @param artifactTypeName System (unique) name of artifact
	 * @param displayName Display (non-unique) name of artifact
	 * @return ID of artifact added
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within tsk core
	 */
	public int addArtifactType(String artifactTypeName, String displayName) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireExclusiveLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			connection.beginTransaction();
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT artifact_type_id FROM blackboard_artifact_types WHERE type_name = '" + artifactTypeName + "'"); //NON-NLS
			if (!rs.next()) {
				rs.close();
				connection.executeUpdate(s, "INSERT INTO blackboard_artifact_types (type_name, display_name) VALUES ('" + artifactTypeName + "', '" + displayName + "')"); //NON-NLS
				rs = s.getGeneratedKeys();
			}
			int id = rs.getInt(1);
			connection.commitTransaction();
			return id;
		} catch (SQLException ex) {
			connection.rollbackTransaction();
			throw new TskCoreException("Error adding artifact type", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseExclusiveLock();
		}
	}

	public ArrayList<BlackboardAttribute> getBlackboardAttributes(final BlackboardArtifact artifact) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		ResultSet rs = null;
		try {
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.SELECT_ATTRIBUTES_OF_ARTIFACT);
			statement.clearParameters();
			statement.setLong(1, artifact.getArtifactID());
			rs = connection.executeQuery(statement);
			ArrayList<BlackboardAttribute> attributes = new ArrayList<BlackboardAttribute>();
			while (rs.next()) {
				final BlackboardAttribute attr = new BlackboardAttribute(
						rs.getLong(1),
						rs.getInt(4),
						rs.getString(2),
						rs.getString(3),
						BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.fromType(rs.getInt(5)),
						rs.getInt(8),
						rs.getLong(9),
						rs.getDouble(10),
						rs.getString(7),
						rs.getBytes(6), this);
				attributes.add(attr);
			}
			return attributes;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting attributes for artifact, artifact id = " + artifact.getArtifactID(), ex);
		} finally {
			closeResultSet(rs);
			releaseSharedLock();
		}
	}

	/**
	 * Get all attributes that match a where clause. The clause should begin
	 * with "WHERE" or "JOIN". To use this method you must know the database
	 * tables
	 *
	 * @param whereClause a sqlite where clause
	 * @return a list of matching attributes
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within tsk core
	 */
	public ArrayList<BlackboardAttribute> getMatchingAttributes(String whereClause) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "Select artifact_id, source, context, attribute_type_id, value_type, " //NON-NLS
					+ "value_byte, value_text, value_int32, value_int64, value_double FROM blackboard_attributes " + whereClause); //NON-NLS
			ArrayList<BlackboardAttribute> matches = new ArrayList<BlackboardAttribute>();
			while (rs.next()) {
				BlackboardAttribute attr = new BlackboardAttribute(rs.getLong("artifact_id"), rs.getInt("attribute_type_id"), rs.getString("source"), rs.getString("context"), //NON-NLS
						BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.fromType(rs.getInt("value_type")), rs.getInt("value_int32"), rs.getLong("value_int64"), rs.getDouble("value_double"), //NON-NLS
						rs.getString("value_text"), rs.getBytes("value_byte"), this); //NON-NLS
				matches.add(attr);
			}
			return matches;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting attributes using this where clause: " + whereClause, ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseSharedLock();
		}
	}

	/**
	 * Get all artifacts that match a where clause. The clause should begin with
	 * "WHERE" or "JOIN". To use this method you must know the database tables
	 *
	 * @param whereClause a sqlite where clause
	 * @return a list of matching artifacts
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within tsk core
	 */
	public ArrayList<BlackboardArtifact> getMatchingArtifacts(String whereClause) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		ResultSet rs = null;
		Statement s = null;
		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT artifact_id, obj_id, artifact_type_id FROM blackboard_artifacts " + whereClause); //NON-NLS
			ArrayList<BlackboardArtifact> matches = new ArrayList<BlackboardArtifact>();
			while (rs.next()) {
				BlackboardArtifact artifact = new BlackboardArtifact(this, rs.getLong(1), rs.getLong(2), rs.getInt(3), this.getArtifactTypeString(rs.getInt(3)), this.getArtifactTypeDisplayName(rs.getInt(3)));
				matches.add(artifact);
			}
			return matches;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting attributes using this where clause: " + whereClause, ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseSharedLock();
		}
	}

	/**
	 * Add a new blackboard artifact with the given type. If that artifact type
	 * does not exist an error will be thrown. The artifact type name can be
	 * looked up in the returned blackboard artifact.
	 *
	 * @param artifactTypeID the type the given artifact should have
	 * @param obj_id the content object id associated with this artifact
	 * @return a new blackboard artifact
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within tsk core
	 */
	public BlackboardArtifact newBlackboardArtifact(int artifactTypeID, long obj_id) throws TskCoreException {
		return newBlackboardArtifact(artifactTypeID, obj_id, getArtifactTypeString(artifactTypeID), getArtifactTypeDisplayName(artifactTypeID));
	}

	/**
	 * Add a new blackboard artifact with the given type.
	 *
	 * @param artifactType the type the given artifact should have
	 * @param obj_id the content object id associated with this artifact
	 * @return a new blackboard artifact
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within tsk core
	 */
	public BlackboardArtifact newBlackboardArtifact(ARTIFACT_TYPE artifactType, long obj_id) throws TskCoreException {
		return newBlackboardArtifact(artifactType.getTypeID(), obj_id, artifactType.getLabel(), artifactType.getDisplayName());
	}

	private BlackboardArtifact newBlackboardArtifact(int artifact_type_id, long obj_id, String artifactTypeName, String artifactDisplayName) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireExclusiveLock();
		ResultSet rs = null;
		try {
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.INSERT_ARTIFACT);
			statement.clearParameters();
			statement.setLong(1, this.nextArtifactId++);
			statement.setLong(2, obj_id);
			statement.setInt(3, artifact_type_id);
			connection.executeUpdate(statement);
			rs = statement.getGeneratedKeys();
			return new BlackboardArtifact(this, rs.getLong(1), obj_id, artifact_type_id, artifactTypeName, artifactDisplayName, true);
		} catch (SQLException ex) {
			throw new TskCoreException("Error creating a blackboard artifact", ex);
		} finally {
			closeResultSet(rs);
			releaseExclusiveLock();
		}		
	}
	/**
	 * Checks if the content object has children. Note: this is generally more
	 * efficient then preloading all children and checking if the set is empty,
	 * and facilities lazy loading.
	 *
	 * @param content content object to check for children
	 * @return true if has children, false otherwise
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within tsk core
	 */
	boolean getContentHasChildren(Content content) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		ResultSet rs = null;
		try {
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.COUNT_CHILD_OBJECTS_BY_PARENT);
			statement.clearParameters();
			statement.setLong(1, content.getId());
			rs = connection.executeQuery(statement);
			boolean hasChildren = false;
			if (rs.next()) {
				hasChildren = rs.getInt(1) > 0;
			}
			return hasChildren;
		} catch (SQLException e) {
			throw new TskCoreException("Error checking for children of parent " + content, e);
		} finally {
			closeResultSet(rs);
			releaseSharedLock();
		}
	}

	/**
	 * Counts if the content object children. Note: this is generally more
	 * efficient then preloading all children and counting, and facilities lazy
	 * loading.
	 *
	 * @param content content object to check for children count
	 * @return children count
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within tsk core
	 */
	int getContentChildrenCount(Content content) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		ResultSet rs = null;
		try {
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.COUNT_CHILD_OBJECTS_BY_PARENT);
			statement.clearParameters();
			statement.setLong(1, content.getId());
			rs = connection.executeQuery(statement);
			int countChildren = -1;
			if (rs.next()) {
				countChildren = rs.getInt(1);
			}
			return countChildren;
		} catch (SQLException e) {
			throw new TskCoreException("Error checking for children of parent " + content, e);
		} finally {
			closeResultSet(rs);
			releaseSharedLock();
		}
	}

	/**
	 * Returns the list of AbstractFile Children of a given type for a given
	 * AbstractFileParent
	 *
	 * @param parent the content parent to get abstract file children for
	 * @param type children type to look for, defined in TSK_DB_FILES_TYPE_ENUM
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within tsk core
	 */
	List<Content> getAbstractFileChildren(Content parent, TSK_DB_FILES_TYPE_ENUM type) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		ResultSet rs = null;
		try {
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.SELECT_FILES_BY_PARENT_AND_TYPE);
			statement.clearParameters();
			long parentId = parent.getId();
			statement.setLong(1, parentId);
			statement.setShort(2, type.getFileType());
			rs = connection.executeQuery(statement);
			return rsHelper.fileChildren(rs, parentId);
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting AbstractFile children for Content", ex);
		} finally {
			closeResultSet(rs);
			releaseSharedLock();
		}
	}

	/**
	 * Returns the list of all AbstractFile Children for a given
	 * AbstractFileParent
	 *
	 * @param parent the content parent to get abstract file children for
	 * @param type children type to look for, defined in TSK_DB_FILES_TYPE_ENUM
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within tsk core
	 */
	List<Content> getAbstractFileChildren(Content parent) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		ResultSet rs = null;
		try {
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.SELECT_FILES_BY_PARENT);
			statement.clearParameters();
			long parentId = parent.getId();
			statement.setLong(1, parentId);
			rs = connection.executeQuery(statement);
			return rsHelper.fileChildren(rs, parentId);
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting AbstractFile children for Content", ex);
		} finally {
			closeResultSet(rs);
			releaseSharedLock();
		}
	}

	/**
	 * Get list of IDs for abstract files of a given type that are children of a
	 * given content.
	 *
	 * @param parent Object to find children for
	 * @param type Type of children to find IDs for
	 * @return
	 * @throws TskCoreException
	 */
	List<Long> getAbstractFileChildrenIds(Content parent, TSK_DB_FILES_TYPE_ENUM type) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		ResultSet rs = null;
		try {
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.SELECT_FILE_IDS_BY_PARENT_AND_TYPE);
			statement.clearParameters();
			statement.setLong(1, parent.getId());
			statement.setShort(2, type.getFileType());
			rs = connection.executeQuery(statement);
			List<Long> children = new ArrayList<Long>();
			while (rs.next()) {
				children.add(rs.getLong(1));
			}
			return children;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting AbstractFile children for Content", ex);
		} finally {
			closeResultSet(rs);
			releaseSharedLock();
		}
	}

	/**
	 * Get list of IDs for abstract files that are children of a given content.
	 *
	 * @param parent Object to find children for
	 * @return
	 * @throws TskCoreException
	 */
	List<Long> getAbstractFileChildrenIds(Content parent) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		ResultSet rs = null;
		try {
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.SELECT_FILE_IDS_BY_PARENT);
			statement.clearParameters();
			statement.setLong(1, parent.getId());
			rs = connection.executeQuery(statement);
			List<Long> children = new ArrayList<Long>();
			while (rs.next()) {
				children.add(rs.getLong(1));
			}
			return children;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting AbstractFile children for Content", ex);
		} finally {
			closeResultSet(rs);
			releaseSharedLock();
		}
	}

	/**
	 * Stores a pair of object ID and its type
	 */
	static class ObjectInfo {

		long id;
		TskData.ObjectType type;

		ObjectInfo(long id, ObjectType type) {
			this.id = id;
			this.type = type;
		}
	}

	/**
	 * Get info about children of a given Content from the database. TODO: the
	 * results of this method are volumes, file systems, and fs files.
	 *
	 * @param c Parent object to run query against
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within tsk core
	 */
	Collection<ObjectInfo> getChildrenInfo(Content c) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT tsk_objects.obj_id, tsk_objects.type " //NON-NLS
					+ "FROM tsk_objects left join tsk_files " //NON-NLS
					+ "ON tsk_objects.obj_id=tsk_files.obj_id " //NON-NLS
					+ "WHERE tsk_objects.par_obj_id = " + c.getId()); //NON-NLS
			Collection<ObjectInfo> infos = new ArrayList<ObjectInfo>();
			while (rs.next()) {
				infos.add(new ObjectInfo(rs.getLong("obj_id"), ObjectType.valueOf(rs.getShort("type")))); //NON-NLS
			}
			return infos;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting Children Info for Content", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseSharedLock();
		}
	}

	/**
	 * Get parent info for the parent of the content object
	 *
	 * @param c content object to get parent info for
	 * @return the parent object info with the parent object type and id
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within tsk core
	 */
	ObjectInfo getParentInfo(Content c) throws TskCoreException {
		// TODO: This should not throw an exception if Content has no parent, 
		// return null instead.
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT parent.obj_id, parent.type " //NON-NLS
					+ "FROM tsk_objects AS parent INNER JOIN tsk_objects AS child " //NON-NLS
					+ "ON child.par_obj_id = parent.obj_id " //NON-NLS
					+ "WHERE child.obj_id = " + c.getId()); //NON-NLS
			if (rs.next()) {
				return new ObjectInfo(rs.getLong(1), ObjectType.valueOf(rs.getShort(2)));
			} else {
				throw new TskCoreException("Given content (id: " + c.getId() + ") has no parent");
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting Parent Info for Content", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseSharedLock();
		}
	}

	/**
	 * Get parent info for the parent of the content object id
	 *
	 * @param id content object id to get parent info for
	 * @return the parent object info with the parent object type and id
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within tsk core
	 */
	ObjectInfo getParentInfo(long contentId) throws TskCoreException {
		// TODO: This should not throw an exception if Content has no parent, 
		// return null instead.
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT parent.obj_id, parent.type " //NON-NLS
					+ "FROM tsk_objects AS parent INNER JOIN tsk_objects AS child " //NON-NLS
					+ "ON child.par_obj_id = parent.obj_id " //NON-NLS
					+ "WHERE child.obj_id = " + contentId); //NON-NLS
			if (rs.next()) {
				return new ObjectInfo(rs.getLong(1), ObjectType.valueOf(rs.getShort(2)));
			} else {
				throw new TskCoreException("Given content (id: " + contentId + ") has no parent.");
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting Parent Info for Content: " + contentId, ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseSharedLock();
		}
	}

	/**
	 * Gets parent directory for FsContent object
	 *
	 * @param fsc FsContent to get parent dir for
	 * @return the parent Directory
	 * @throws TskCoreException thrown if critical error occurred within tsk
	 * core
	 */
	Directory getParentDirectory(FsContent fsc) throws TskCoreException {
		// TODO: This should not throw an exception if Content has no parent, 
		// return null instead.
		if (fsc.isRoot()) {
			throw new TskCoreException("Given FsContent (id: " + fsc.getId() + ") is a root object (can't have parent directory).");
		} else {
			ObjectInfo parentInfo = getParentInfo(fsc);
			Directory parent = null;
			if (parentInfo.type == ObjectType.ABSTRACTFILE) {
				parent = getDirectoryById(parentInfo.id, fsc.getFileSystem());
			} else {
				throw new TskCoreException("Parent of FsContent (id: " + fsc.getId() + ") has wrong type to be directory: " + parentInfo.type);
			}
			return parent;
		}
	}

	/**
	 * Get content object by content id
	 *
	 * @param id to get content object for
	 * @return instance of a Content object (one of its subclasses), or null if
	 * not found.
	 * @throws TskCoreException thrown if critical error occurred within tsk
	 * core
	 */
	public Content getContentById(long id) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT * FROM tsk_objects WHERE obj_id = " + id + " LIMIT  1"); //NON-NLS
			if (!rs.next()) {
				return null;
			}

			AbstractContent content = null;
			long parentId = rs.getLong("par_obj_id"); //NON-NLS
			final TskData.ObjectType type = TskData.ObjectType.valueOf(rs.getShort("type")); //NON-NLS
			switch (type) {
				case IMG:
					content = getImageById(id);
					break;
				case VS:
					content = getVolumeSystemById(id, parentId);
					break;
				case VOL:
					content = getVolumeById(id, parentId);
					break;
				case FS:
					content = getFileSystemById(id, parentId);
					break;
				case ABSTRACTFILE:
					content = getAbstractFileById(id);
					break;
				default:
					throw new TskCoreException("Could not obtain Content object with ID: " + id);
			}
			return content;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting Content by ID.", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseSharedLock();
		}
	}

	/**
	 * Get a path of a file in tsk_files_path table or null if there is none
	 *
	 * @param id id of the file to get path for
	 * @return file path or null
	 */
	String getFilePath(long id) {
		CaseDbConnection connection;
		try {
			connection = connections.getConnection();
		} catch (TskCoreException ex) {
			logger.log(Level.SEVERE, "Error getting file path for file " + id, ex); //NON-NLS			
			return null;
		}
		String filePath = null;
		acquireSharedLock();
		ResultSet rs = null;
		try {
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.SELECT_LOCAL_PATH_FOR_FILE);
			statement.clearParameters();
			statement.setLong(1, id);
			rs = connection.executeQuery(statement);
			if (rs.next()) {
				filePath = rs.getString(1);
			}
		} catch (SQLException ex) {
			logger.log(Level.SEVERE, "Error getting file path for file " + id, ex); //NON-NLS
		} finally {
			closeResultSet(rs);
			releaseSharedLock();
		}
		return filePath;
	}

	/**
	 * Get a parent_path of a file in tsk_files table or null if there is none
	 *
	 * @param id id of the file to get path for
	 * @return file path or null
	 */
	String getFileParentPath(long id) {
		CaseDbConnection connection;
		try {
			connection = connections.getConnection();
		} catch (TskCoreException ex) {
			logger.log(Level.SEVERE, "Error getting parent file path for file " + id, ex); //NON-NLS			
			return null;
		}
		String parentPath = null;
		acquireSharedLock();
		ResultSet rs = null;
		try {
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.SELECT_PATH_FOR_FILE);
			statement.clearParameters();
			statement.setLong(1, id);
			rs = connection.executeQuery(statement);
			if (rs.next()) {
				parentPath = rs.getString(1);
			}
		} catch (SQLException ex) {
			logger.log(Level.SEVERE, "Error getting file parent_path for file " + id, ex); //NON-NLS
		} finally {
			closeResultSet(rs);
			releaseSharedLock();
		}
		return parentPath;
	}

	/**
	 * Get a name of a file in tsk_files table or null if there is none
	 *
	 * @param id id of the file to get name for
	 * @return file name or null
	 */
	String getFileName(long id) {
		CaseDbConnection connection;
		try {
			connection = connections.getConnection();
		} catch (TskCoreException ex) {
			logger.log(Level.SEVERE, "Error getting file name for file " + id, ex); //NON-NLS			
			return null;
		}
		String fileName = null;
		acquireSharedLock();
		ResultSet rs = null;
		try {
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.SELECT_FILE_NAME);
			statement.clearParameters();
			statement.setLong(1, id);
			rs = connection.executeQuery(statement);
			if (rs.next()) {
				fileName = rs.getString(1);
			}
		} catch (SQLException ex) {
			logger.log(Level.SEVERE, "Error getting file parent_path for file " + id, ex); //NON-NLS
		} finally {
			closeResultSet(rs);
			releaseSharedLock();
		}
		return fileName;
	}

	/**
	 * Get a derived method for a file, or null if none
	 *
	 * @param id id of the derived file
	 * @return derived method or null if not present
	 * @throws TskCoreException exception throws if core error occurred and
	 * method could not be queried
	 */
	DerivedFile.DerivedMethod getDerivedMethod(long id) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		DerivedFile.DerivedMethod method = null;
		acquireSharedLock();
		ResultSet rs1 = null;
		ResultSet rs2 = null;
		try {
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.SELECT_DERIVED_FILE);
			statement.clearParameters();
			statement.setLong(1, id);
			rs1 = connection.executeQuery(statement);
			if (rs1.next()) {
				int method_id = rs1.getInt(1);
				String rederive = rs1.getString(1);
				method = new DerivedFile.DerivedMethod(method_id, rederive);
				statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.SELECT_FILE_DERIVATION_METHOD);
				statement.clearParameters();
				statement.setInt(1, method_id);
				rs2 = connection.executeQuery(statement);
				if (rs2.next()) {
					method.setToolName(rs2.getString(1));
					method.setToolVersion(rs2.getString(2));
					method.setOther(rs2.getString(3));
				}
			}
		} catch (SQLException e) {
			logger.log(Level.SEVERE, "Error getting derived method for file: " + id, e); //NON-NLS
		} finally {
			closeResultSet(rs2);
			closeResultSet(rs1);
			releaseSharedLock();
		}
		return method;
	}

	/**
	 * Get abstract file object from tsk_files table by its id
	 *
	 * @param id id of the file object in tsk_files table
	 * @return AbstractFile object populated, or null if not found.
	 * @throws TskCoreException thrown if critical error occurred within tsk
	 * core and file could not be queried
	 */
	public AbstractFile getAbstractFileById(long id) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		ResultSet rs = null;
		try {
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.SELECT_FILE_BY_ID);
			statement.clearParameters();
			statement.setLong(1, id);
			rs = connection.executeQuery(statement);
			List<AbstractFile> results;
			if ((results = resultSetToAbstractFiles(rs)).size() > 0) {
				return results.get(0);
			} else {
				return null;
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting file by id, id = " + id, ex);
		} finally {
			closeResultSet(rs);
			releaseSharedLock();
		}
	}

	/**
	 * Get the object ID of the file system that a file is located in.
	 *
	 * Note: for FsContent files, this is the real fs for other non-fs
	 * AbstractFile files, this field is used internally for data source id (the
	 * root content obj)
	 *
	 * @param fileId object id of the file to get fs column id for
	 * @return fs_id or -1 if not present
	 */
	private long getFileSystemId(long fileId) {
		CaseDbConnection connection;
		try {
			connection = connections.getConnection();
		} catch (TskCoreException ex) {
			logger.log(Level.SEVERE, "Error getting file system id for file " + fileId, ex); //NON-NLS			
			return -1;
		}
		acquireSharedLock();
		ResultSet rs = null;
		long ret = -1;
		try {
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.SELECT_FILE_SYSTEM_BY_OBJECT);
			statement.clearParameters();
			statement.setLong(1, fileId);
			rs = connection.executeQuery(statement);
			if (rs.next()) {
				ret = rs.getLong(1);
				if (ret == 0) {
					ret = -1;
				}
			}
		} catch (SQLException e) {
			logger.log(Level.SEVERE, "Error checking file system id of a file, id = " + fileId, e); //NON-NLS
		} finally {
			closeResultSet(rs);
			releaseSharedLock();
		}
		return ret;
	}

	/**
	 * Checks if the file is a (sub)child of the data source (parentless Content
	 * object such as Image or VirtualDirectory representing filesets)
	 *
	 * @param dataSource dataSource to check
	 * @param fileId id of file to check
	 * @return true if the file is in the dataSource hierarchy
	 * @throws TskCoreException thrown if check failed
	 */
	public boolean isFileFromSource(Content dataSource, long fileId) throws TskCoreException {
		if (dataSource.getParent() != null) {
			final String msg = MessageFormat.format(bundle.getString("SleuthkitCase.isFileFromSource.exception.msg.text"), dataSource);
			logger.log(Level.SEVERE, msg);
			throw new IllegalArgumentException(msg);
		}

		//get fs_id for file id
		long fsId = getFileSystemId(fileId);
		if (fsId == -1) {
			return false;
		}

		//if image, check if one of fs in data source
		if (dataSource instanceof Image) {
			Collection<FileSystem> fss = getFileSystems((Image) dataSource);
			for (FileSystem fs : fss) {
				if (fs.getId() == fsId) {
					return true;
				}
			}
			return false;
		} //if VirtualDirectory, check if dataSource id is the fs_id
		else if (dataSource instanceof VirtualDirectory) {
			//fs_obj_id is not a real fs in this case
			//we are currently using this field internally to get to data source of non-fs files quicker
			//this will be fixed in 2.5 schema
			return dataSource.getId() == fsId;
		} else {
			final String msg = MessageFormat.format(bundle.getString("SleuthkitCase.isFileFromSource.exception.msg2.text"), dataSource);
			logger.log(Level.SEVERE, msg);
			throw new IllegalArgumentException(msg);
		}
	}

	/**
	 * @param dataSource the dataSource (Image, parent-less VirtualDirectory) to
	 * search for the given file name
	 * @param fileName Pattern of the name of the file or directory to match
	 * (case insensitive, used in LIKE SQL statement).
	 * @return a list of AbstractFile for files/directories whose name matches
	 * the given fileName
	 * @throws TskCoreException thrown if check failed
	 */
	public List<AbstractFile> findFiles(Content dataSource, String fileName) throws TskCoreException {
		if (dataSource.getParent() != null) {
			final String msg = MessageFormat.format(bundle.getString("SleuthkitCase.isFileFromSource.exception.msg1.text"), dataSource);
			logger.log(Level.SEVERE, msg);
			throw new IllegalArgumentException(msg);
		}

		List<AbstractFile> files = new ArrayList<AbstractFile>();
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		ResultSet rs = null;
		try {
			if (dataSource instanceof Image) {
				PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.SELECT_FILES_BY_FILE_SYSTEM_AND_NAME);
					
				for (FileSystem fileSystem : getFileSystems((Image) dataSource)) {
					statement.clearParameters();
					statement.setString(1, fileName.toLowerCase());
					statement.setLong(2, fileSystem.getId());
					rs = connection.executeQuery(statement);
					files.addAll(resultSetToAbstractFiles(rs));
				}
			} else if (dataSource instanceof VirtualDirectory) {
				// A future database schema could probably make this cleaner. 
				// fs_obj_id is set only for file system files. 
				// We will match the VirtualDirectory's name in the parent path
				Statement s = connection.createStatement();
				rs = connection.executeQuery(s, "SELECT * FROM tsk_files WHERE LOWER(name) LIKE '" + fileName.toLowerCase() + "'  and LOWER(name) NOT LIKE '%journal%' AND parent_path LIKE '/" + dataSource.getName() +"/%'"); //NON-NLS
				files = resultSetToAbstractFiles(rs);
			} else {
				final String msg = MessageFormat.format(bundle.getString("SleuthkitCase.findFiles.exception.msg2.text"), dataSource);
				logger.log(Level.SEVERE, msg);
				throw new IllegalArgumentException(msg);
			}
		} catch (SQLException e) {
			throw new TskCoreException(bundle.getString("SleuthkitCase.findFiles.exception.msg3.text"), e);
		} finally {
			closeResultSet(rs);
			releaseSharedLock();
		}
		return files;
	}

	/**
	 * @param dataSource the dataSource (Image, parent-less VirtualDirectory) to
	 * search for the given file name
	 * @param fileName Pattern of the name of the file or directory to match
	 * (case insensitive, used in LIKE SQL statement).
	 * @param dirName Pattern of the name of a parent directory of fileName
	 * (case insensitive, used in LIKE SQL statement)
	 * @return a list of AbstractFile for files/directories whose name matches
	 * fileName and whose parent directory contains dirName.
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	public List<AbstractFile> findFiles(Content dataSource, String fileName, String dirName) throws TskCoreException {
		if (dataSource.getParent() != null) {
			final String msg = MessageFormat.format(bundle.getString("SleuthkitCase.findFiles3.exception.msg1.text"), dataSource);
			logger.log(Level.SEVERE, msg);
			throw new IllegalArgumentException(msg);
		}

		List<AbstractFile> files = new ArrayList<AbstractFile>();
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		ResultSet rs = null;
		try {
			if (dataSource instanceof Image) {
				PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.SELECT_FILES_BY_FILE_SYSTEM_AND_PATH);
			
				for (FileSystem fileSystem : getFileSystems((Image) dataSource)) {
					statement.clearParameters();
					statement.setString(1, fileName.toLowerCase());
					statement.setString(2, "%" + dirName.toLowerCase() + "%"); //NON-NLS
					statement.setLong(3, fileSystem.getId());
					rs = connection.executeQuery(statement);
					files.addAll(resultSetToAbstractFiles(rs));
				}
			} else if (dataSource instanceof VirtualDirectory) {
				// A future database schema could probably make this cleaner. 
				// fs_obj_id is set only for file system files. 
				// We will match the VirtualDirectory's name in the parent path
				Statement s = connection.createStatement();
				rs = connection.executeQuery(s, "SELECT * FROM tsk_files WHERE LOWER(name) LIKE '" + fileName.toLowerCase() + "' and LOWER(name) NOT LIKE '%journal%' AND parent_path LIKE '/" + dataSource.getName() +"/%' AND lower(parent_path) LIKE '%" + dirName.toLowerCase() + "%'"); //NON-NLS
				files = resultSetToAbstractFiles(rs);
			} else {
				final String msg = MessageFormat.format(bundle.getString("SleuthkitCase.findFiles3.exception.msg2.text"), dataSource);
				logger.log(Level.SEVERE, msg);
				throw new IllegalArgumentException(msg);
			}
		} catch (SQLException e) {
			throw new TskCoreException(bundle.getString("SleuthkitCase.findFiles3.exception.msg3.text"), e);
		} finally {
			if (rs != null) {
				try {
					rs.close();
				} catch (SQLException ex) {
					logger.log(Level.WARNING, "Error closing result set after finding files", ex); //NON-NLS
				}
			}
			releaseSharedLock();
		}
		return files;
	}

	/**
	 * wraps the version of addVirtualDirectory that takes a Transaction in a
	 * transaction local to this method
	 *
	 * @param parentId
	 * @param directoryName
	 * @return
	 * @throws TskCoreException
	 */
	public VirtualDirectory addVirtualDirectory(long parentId, String directoryName) throws TskCoreException {
		acquireExclusiveLock();
		CaseDbTransaction localTrans = beginTransaction();
		try {
			VirtualDirectory newVD = addVirtualDirectory(parentId, directoryName, localTrans);
			localTrans.commit();
			return newVD;
		} catch (TskCoreException ex) {
			localTrans.rollback();
			throw ex;
		} finally {
			releaseExclusiveLock();
		}
	}

	/**
	 * Adds a virtual directory to the database and returns a VirtualDirectory
	 * object representing it.
	 *
	 * @param parentId the ID of the parent, or 0 if NULL
	 * @param directoryName the name of the virtual directory to create
	 * @param trans the transaction in the scope of which the operation is to be
	 * performed, managed by the caller
	 * @return a VirtualDirectory object representing the one added to the
	 * database.
	 * @throws TskCoreException
	 */
	public VirtualDirectory addVirtualDirectory(long parentId, String directoryName, CaseDbTransaction trans) throws TskCoreException {
		if (trans == null) {
			throw new TskCoreException("Passed null CaseDbTransaction");
		}

		acquireExclusiveLock();
		ResultSet resultSet = null;
		try {
			// Get the parent path.
			String parentPath = getFileParentPath(parentId);
			if (parentPath == null) {
				parentPath = "/"; //NON-NLS
			}
			String parentName = getFileName(parentId);
			if (parentName != null) {
				parentPath = parentPath + parentName + "/"; //NON-NLS
			}

			// Insert a row for the virtual directory into the tsk_objects table.
			// INSERT INTO tsk_objects (par_obj_id, type) VALUES (?, ?)
			CaseDbConnection connection = trans.getConnection();
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.INSERT_OBJECT);
			statement.clearParameters();
			if (parentId != 0) {
				statement.setLong(1, parentId);
			}
			statement.setLong(2, TskData.ObjectType.ABSTRACTFILE.getObjectType());
			connection.executeUpdate(statement);
			resultSet = statement.getGeneratedKeys();
			long newObjId = resultSet.getLong(1);

			// Insert a row for the virtual directory into the tsk_files table.
			// INSERT INTO tsk_files (obj_id, fs_obj_id, name, type, has_path, dir_type, meta_type, 
			// dir_flags, meta_flags, size, ctime, crtime, atime, mtime, parent_path) 
			// VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)			
			statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.INSERT_FILE);
			statement.clearParameters();
			statement.setLong(1, newObjId);

			// If the parent is part of a file system, grab its file system ID
			long parentFs = this.getFileSystemId(parentId);
			if (parentFs != -1) {
				statement.setLong(2, parentFs);
			}
			statement.setString(3, directoryName);

			//type, has_path
			statement.setShort(4, TskData.TSK_DB_FILES_TYPE_ENUM.VIRTUAL_DIR.getFileType());
			statement.setBoolean(5, true);

			//flags
			final TSK_FS_NAME_TYPE_ENUM dirType = TSK_FS_NAME_TYPE_ENUM.DIR;
			statement.setShort(6, dirType.getValue());
			final TSK_FS_META_TYPE_ENUM metaType = TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_DIR;
			statement.setShort(7, metaType.getValue());

			//note: using alloc under assumption that derived files derive from alloc files
			final TSK_FS_NAME_FLAG_ENUM dirFlag = TSK_FS_NAME_FLAG_ENUM.ALLOC;
			statement.setShort(8, dirFlag.getValue());
			final short metaFlags = (short) (TSK_FS_META_FLAG_ENUM.ALLOC.getValue()
					| TSK_FS_META_FLAG_ENUM.USED.getValue());
			statement.setShort(9, metaFlags);

			//size
			long size = 0;
			statement.setLong(10, size);

			//parent path, nulls for params 11-14
			statement.setString(15, parentPath);

			connection.executeUpdate(statement);

			return new VirtualDirectory(this, newObjId, directoryName, dirType,
					metaType, dirFlag, metaFlags, size, null, FileKnown.UNKNOWN,
					parentPath);
		} catch (SQLException e) {
			throw new TskCoreException("Error creating virtual directory '" + directoryName + "'", e);
		} finally {
			closeResultSet(resultSet);
			releaseExclusiveLock();
		}
	}

	/**
	 * Get IDs of the virtual folder roots (at the same level as image), used
	 * for containers such as for local files.
	 *
	 * @return IDs of virtual directory root objects.
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	public List<VirtualDirectory> getVirtualDirectoryRoots() throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT tsk_files.* FROM tsk_objects, tsk_files WHERE " //NON-NLS
					+ "tsk_objects.par_obj_id IS NULL AND " //NON-NLS
					+ "tsk_objects.type = " + TskData.ObjectType.ABSTRACTFILE.getObjectType() + " AND " //NON-NLS
					+ "tsk_objects.obj_id = tsk_files.obj_id AND " //NON-NLS
					+ "tsk_files.type = " + TskData.TSK_DB_FILES_TYPE_ENUM.VIRTUAL_DIR.getFileType()
					+ " ORDER BY tsk_files.dir_type, tsk_files.name COLLATE NOCASE"); //NON-NLS
			List<VirtualDirectory> virtDirRootIds = new ArrayList<VirtualDirectory>();
			while (rs.next()) {
				virtDirRootIds.add(rsHelper.virtualDirectory(rs));
			}
			return virtDirRootIds;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting local files virtual folder id", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseSharedLock();
		}
	}

	/**
	 * Adds a carved file to the VirtualDirectory '$CarvedFiles' in the volume
	 * or image given by systemId. Creates $CarvedFiles virtual directory if it
	 * does not exist already.
	 *
	 * @param carvedFileName the name of the carved file to add
	 * @param carvedFileSize the size of the carved file to add
	 * @param containerId the ID of the parent volume, file system, or image
	 * @param data the layout information - a list of offsets that make up this
	 * carved file.
	 * @return A LayoutFile object representing the carved file.
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	public LayoutFile addCarvedFile(String carvedFileName, long carvedFileSize, long containerId, List<TskFileRange> data) throws TskCoreException {

		List<CarvedFileContainer> carvedFileContainer = new ArrayList<CarvedFileContainer>();
		carvedFileContainer.add(new CarvedFileContainer(carvedFileName, carvedFileSize, containerId, data));

		List<LayoutFile> layoutCarvedFiles = addCarvedFiles(carvedFileContainer);
		if (layoutCarvedFiles != null) {
			return layoutCarvedFiles.get(0);
		} else {
			return null;
		}
	}

	/**
	 * Adds a collection of carved files to the VirtualDirectory '$CarvedFiles'
	 * in the volume or image given by systemId. Creates $CarvedFiles virtual
	 * directory if it does not exist already.
	 *
	 * @param filesToAdd a list of CarvedFileContainer files to add as carved
	 * files
	 * @return List<LayoutFile> This is a list of the files added to the
	 * database
	 * @throws org.sleuthkit.datamodel.TskCoreException
	 */
	public List<LayoutFile> addCarvedFiles(List<CarvedFileContainer> filesToAdd) throws TskCoreException {
		if (filesToAdd != null && filesToAdd.isEmpty() == false) {
			List<LayoutFile> addedFiles = new ArrayList<LayoutFile>();
			CaseDbTransaction localTrans = null;
			Statement s = null;
			ResultSet rs = null;
			acquireExclusiveLock();
			try {
				localTrans = beginTransaction();
				CaseDbConnection connection = localTrans.getConnection();

				// get the ID of the appropriate '$CarvedFiles' directory
				long firstItemId = filesToAdd.get(0).getId();
				long id = 0;
				// first, check the cache
				Long carvedDirId = carvedFileContainersCache.get(firstItemId);
				if (carvedDirId != null) {
					id = carvedDirId;
				} else {
					// it's not in the cache. Go to the DB
					// determine if we've got a volume system or file system ID
					Content parent = getContentById(firstItemId);
					if (parent == null) {
						throw new TskCoreException("No Content object found with this ID (" + firstItemId + ").");
					}

					List<Content> children = Collections.<Content>emptyList();
					if (parent instanceof FileSystem) {
						FileSystem fs = (FileSystem) parent;
						children = fs.getRootDirectory().getChildren();
					} else if (parent instanceof Volume
							|| parent instanceof Image) {
						children = parent.getChildren();
					} else {
						throw new TskCoreException("The given ID (" + firstItemId + ") was not an image, volume or file system.");
					}

					// see if any of the children are a '$CarvedFiles' directory
					Content carvedFilesDir = null;
					for (Content child : children) {
						if (child.getName().equals(VirtualDirectory.NAME_CARVED)) {
							carvedFilesDir = child;
							break;
						}
					}

					// if we found it, add it to the cache and grab its ID
					if (carvedFilesDir != null) {
						// add it to the cache
						carvedFileContainersCache.put(firstItemId, carvedFilesDir.getId());
						id = carvedFilesDir.getId();
					} else {
						// a carved files directory does not exist; create one
						VirtualDirectory vd = addVirtualDirectory(firstItemId, VirtualDirectory.NAME_CARVED, localTrans);
						id = vd.getId();
						// add it to the cache
						carvedFileContainersCache.put(firstItemId, id);
					}
				}

				// get the parent path for the $CarvedFiles directory		
				String parentPath = getFileParentPath(id);
				if (parentPath == null) {
					parentPath = "/"; //NON-NLS
				}
				String parentName = getFileName(id);
				if (parentName != null) {
					parentPath = parentPath + parentName + "/"; //NON-NLS
				}

				// we should cache this when we start adding lots of carved files...
				boolean isContainerAFs = false;
				s = connection.createStatement();
				rs = connection.executeQuery(s, "select * from tsk_fs_info " //NON-NLS
						+ "where obj_id = " + firstItemId); //NON-NLS
				if (rs.next()) {
					isContainerAFs = true;
				}
				rs.close();
				rs = null;

				for (CarvedFileContainer itemToAdd : filesToAdd) {

					// Insert a row for the carved file into the tsk_objects table.
					// INSERT INTO tsk_objects (par_obj_id, type) VALUES (?, ?)
					PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.INSERT_OBJECT);
					statement.clearParameters();
					statement.setLong(1, id);
					statement.setLong(2, TskData.ObjectType.ABSTRACTFILE.getObjectType());
					connection.executeUpdate(statement);
					rs = statement.getGeneratedKeys();
					long newObjId = rs.getLong(1);

					// Insert a row for the carved file into the tsk_files table.
					// INSERT INTO tsk_files (obj_id, fs_obj_id, name, type, has_path, dir_type, meta_type, 
					// dir_flags, meta_flags, size, ctime, crtime, atime, mtime, parent_path) 
					// VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)			
					statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.INSERT_FILE);
					statement.clearParameters();
					statement.setLong(1, newObjId);

					// only insert into the fs_obj_id column if container is a FS
					if (isContainerAFs) {
						statement.setLong(2, itemToAdd.getId());
					}
					statement.setString(3, itemToAdd.getName());

					// type
					final TSK_DB_FILES_TYPE_ENUM type = TSK_DB_FILES_TYPE_ENUM.CARVED;
					statement.setShort(4, type.getFileType());

					// has_path
					statement.setBoolean(5, true);

					// dirType
					final TSK_FS_NAME_TYPE_ENUM dirType = TSK_FS_NAME_TYPE_ENUM.REG;
					statement.setShort(6, dirType.getValue());

					// metaType
					final TSK_FS_META_TYPE_ENUM metaType = TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_REG;
					statement.setShort(7, metaType.getValue());

					// dirFlag
					final TSK_FS_NAME_FLAG_ENUM dirFlag = TSK_FS_NAME_FLAG_ENUM.UNALLOC;
					statement.setShort(8, dirFlag.getValue());

					// metaFlags
					final short metaFlags = TSK_FS_META_FLAG_ENUM.UNALLOC.getValue();
					statement.setShort(9, metaFlags);

					// size
					statement.setLong(10, itemToAdd.getSize());

					//parent path, nulls for params 11-14
					statement.setString(15, parentPath);

					connection.executeUpdate(statement);

					// Add a row in the tsk_layout_file table for each TskFileRange.
					// INSERT INTO tsk_file_layout (obj_id, byte_start, byte_len, sequence) 
					// VALUES (?, ?, ?, ?)
					statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.INSERT_LAYOUT_FILE);
					for (TskFileRange tskFileRange : itemToAdd.getRanges()) {
						statement.clearParameters();

						// set the object ID
						statement.setLong(1, newObjId);

						// set byte_start
						statement.setLong(2, tskFileRange.getByteStart());

						// set byte_len
						statement.setLong(3, tskFileRange.getByteLen());

						// set the sequence number
						statement.setLong(4, tskFileRange.getSequence());

						// execute it
						connection.executeUpdate(statement);
					}

					addedFiles.add(new LayoutFile(this, newObjId, itemToAdd.getName(),
							type, dirType, metaType, dirFlag, metaFlags,
							itemToAdd.getSize(), null, FileKnown.UNKNOWN, parentPath));
				}
				localTrans.commit();
				return addedFiles;
			} catch (SQLException ex) {
				if (null != localTrans) {
					localTrans.rollback();
				}
				throw new TskCoreException("Failed to add carved file to case database", ex);
			} finally {
				closeResultSet(rs);
				closeStatement(s);
				releaseExclusiveLock();
			}
		} else {
			return Collections.emptyList();
		}
	}

	/**
	 * Creates a new derived file object, adds it to database and returns it.
	 *
	 * TODO add support for adding derived method
	 *
	 * @param fileName file name the derived file
	 * @param localPath local path of the derived file, including the file name.
	 * The path is relative to the database path.
	 * @param size size of the derived file in bytes
	 * @param ctime
	 * @param crtime
	 * @param atime
	 * @param mtime
	 * @param isFile whether a file or directory, true if a file
	 * @param parentFile parent file object (derived or local file)
	 * @param rederiveDetails details needed to re-derive file (will be specific
	 * to the derivation method), currently unused
	 * @param toolName name of derivation method/tool, currently unused
	 * @param toolVersion version of derivation method/tool, currently unused
	 * @param otherDetails details of derivation method/tool, currently unused
	 * @return newly created derived file object
	 * @throws TskCoreException exception thrown if the object creation failed
	 * due to a critical system error
	 */
	public DerivedFile addDerivedFile(String fileName, String localPath,
			long size, long ctime, long crtime, long atime, long mtime,
			boolean isFile, AbstractFile parentFile,
			String rederiveDetails, String toolName, String toolVersion, String otherDetails) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireExclusiveLock();
		ResultSet rs = null;
		try {
			connection.beginTransaction();

			final long parentId = parentFile.getId();
			final String parentPath = parentFile.getParentPath() + parentFile.getName() + '/'; //NON-NLS

			// Insert a row for the derived file into the tsk_objects table.
			// INSERT INTO tsk_objects (par_obj_id, type) VALUES (?, ?)
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.INSERT_OBJECT);
			statement.clearParameters();
			statement.setLong(1, parentId);
			statement.setLong(2, TskData.ObjectType.ABSTRACTFILE.getObjectType());
			connection.executeUpdate(statement);
			rs = statement.getGeneratedKeys();
			long newObjId = rs.getLong(1);
			rs.close();
			rs = null;

			// Insert a row for the virtual directory into the tsk_files table.
			// INSERT INTO tsk_files (obj_id, fs_obj_id, name, type, has_path, dir_type, meta_type, 
			// dir_flags, meta_flags, size, ctime, crtime, atime, mtime, parent_path) 
			// VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)			
			statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.INSERT_FILE);
			statement.clearParameters();
			statement.setLong(1, newObjId);

			// If the parentFile is part of a file system, use its file system object ID.
			long fsObjId = this.getFileSystemId(parentId);
			if (fsObjId != -1) {
				statement.setLong(2, fsObjId);
			}
			statement.setString(3, fileName);

			//type, has_path
			statement.setShort(4, TskData.TSK_DB_FILES_TYPE_ENUM.DERIVED.getFileType());
			statement.setBoolean(5, true);

			//flags
			final TSK_FS_NAME_TYPE_ENUM dirType = isFile ? TSK_FS_NAME_TYPE_ENUM.REG : TSK_FS_NAME_TYPE_ENUM.DIR;
			statement.setShort(6, dirType.getValue());
			final TSK_FS_META_TYPE_ENUM metaType = isFile ? TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_REG : TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_DIR;
			statement.setShort(7, metaType.getValue());

			//note: using alloc under assumption that derived files derive from alloc files
			final TSK_FS_NAME_FLAG_ENUM dirFlag = TSK_FS_NAME_FLAG_ENUM.ALLOC;
			statement.setShort(8, dirFlag.getValue());
			final short metaFlags = (short) (TSK_FS_META_FLAG_ENUM.ALLOC.getValue()
					| TSK_FS_META_FLAG_ENUM.USED.getValue());
			statement.setShort(9, metaFlags);

			//size
			statement.setLong(10, size);

			//mactimes
			//long ctime, long crtime, long atime, long mtime,
			statement.setLong(11, ctime);
			statement.setLong(12, crtime);
			statement.setLong(13, atime);
			statement.setLong(14, mtime);

			//parent path
			statement.setString(15, parentPath);

			connection.executeUpdate(statement);

			//add localPath 
			addFilePath(connection, newObjId, localPath);

			connection.commitTransaction();

			//TODO add derived method to tsk_files_derived and tsk_files_derived_method 
			return new DerivedFile(this, newObjId, fileName, dirType, metaType, dirFlag, metaFlags,
					size, ctime, crtime, atime, mtime, null, null, parentPath, localPath, parentId);
		} catch (SQLException ex) {
			connection.rollbackTransaction();
			throw new TskCoreException("Failed to add derived file to case database", ex);
		} finally {
			closeResultSet(rs);
			releaseExclusiveLock();
		}
	}

	/**
	 *
	 * wraps the version of addLocalFile that takes a Transaction in a
	 * transaction local to this method.
	 *
	 * @param fileName
	 * @param localPath
	 * @param size
	 * @param ctime
	 * @param crtime
	 * @param atime
	 * @param mtime
	 * @param isFile
	 * @param parent
	 * @return
	 * @throws TskCoreException
	 */
	public LocalFile addLocalFile(String fileName, String localPath,
			long size, long ctime, long crtime, long atime, long mtime,
			boolean isFile, AbstractFile parent) throws TskCoreException {
		acquireExclusiveLock();
		CaseDbTransaction localTrans = beginTransaction();
		try {
			LocalFile created = addLocalFile(fileName, localPath, size, ctime, crtime, atime, mtime, isFile, parent, localTrans);
			localTrans.commit();
			return created;
		} catch (TskCoreException ex) {
			localTrans.rollback();
			throw ex;
		} finally {
			releaseExclusiveLock();
		}
	}

	/**
	 * Creates a new local file object, adds it to database and returns it.
	 *
	 *
	 * todo: at the moment we trust the transaction and don't do anything to
	 * check it is valid or in the correct state. we should.
	 *
	 *
	 * @param fileName file name the derived file
	 * @param localPath local absolute path of the local file, including the
	 * file name.
	 * @param size size of the derived file in bytes
	 * @param ctime
	 * @param crtime
	 * @param atime
	 * @param mtime
	 * @param isFile whether a file or directory, true if a file
	 * @param parent parent file object (such as virtual directory, another
	 * local file, or FsContent type of file)
	 * @param trans the transaction in the scope of which the operation is to be
	 * performed, managed by the caller
	 * @return newly created derived file object
	 * @throws TskCoreException exception thrown if the object creation failed
	 * due to a critical system error
	 */
	public LocalFile addLocalFile(String fileName, String localPath,
			long size, long ctime, long crtime, long atime, long mtime,
			boolean isFile, AbstractFile parent, CaseDbTransaction trans) throws TskCoreException {
		if (trans == null) {
			throw new TskCoreException("Passed null CaseDbTransaction");
		}

		acquireExclusiveLock();
		ResultSet resultSet = null;
		try {
			long parentId = -1;
			String parentPath;
			if (parent == null) {
				throw new TskCoreException(MessageFormat.format(bundle.getString("SleuthkitCase.addLocalFile.exception.msg1.text"), fileName));
			} else {
				parentId = parent.getId();
				parentPath = parent.getParentPath() + parent.getName() + "/"; //NON-NLS
				}

			// Insert a row for the local/logical file into the tsk_objects table.
			// INSERT INTO tsk_objects (par_obj_id, type) VALUES (?, ?)
			CaseDbConnection connection = connections.getConnection();
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.INSERT_OBJECT);
			statement.clearParameters();
			statement.setLong(1, parentId);
			statement.setLong(2, TskData.ObjectType.ABSTRACTFILE.getObjectType());
			connection.executeUpdate(statement);
			resultSet = statement.getGeneratedKeys();
			long newObjId = resultSet.getLong(1);
			resultSet.close();
			resultSet = null;

			// Insert a row for the local/logical file into the tsk_files table.
			// INSERT INTO tsk_files (obj_id, fs_obj_id, name, type, has_path, dir_type, meta_type, 
			// dir_flags, meta_flags, size, ctime, crtime, atime, mtime, parent_path) 
			// VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)			
			statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.INSERT_FILE);
			statement.clearParameters();
			statement.setLong(1, newObjId);

			// nothing to set for parameter 2, fs_obj_id since local files aren't part of file systems
			statement.setString(3, fileName);

			//type, has_path
			statement.setShort(4, TskData.TSK_DB_FILES_TYPE_ENUM.LOCAL.getFileType());
			statement.setBoolean(5, true);

			//flags
			final TSK_FS_NAME_TYPE_ENUM dirType = isFile ? TSK_FS_NAME_TYPE_ENUM.REG : TSK_FS_NAME_TYPE_ENUM.DIR;
			statement.setShort(6, dirType.getValue());
			final TSK_FS_META_TYPE_ENUM metaType = isFile ? TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_REG : TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_DIR;
			statement.setShort(7, metaType.getValue());

			//note: using alloc under assumption that derived files derive from alloc files
			final TSK_FS_NAME_FLAG_ENUM dirFlag = TSK_FS_NAME_FLAG_ENUM.ALLOC;
			statement.setShort(8, dirFlag.getValue());
			final short metaFlags = (short) (TSK_FS_META_FLAG_ENUM.ALLOC.getValue()
					| TSK_FS_META_FLAG_ENUM.USED.getValue());
			statement.setShort(9, metaFlags);

			//size
			statement.setLong(10, size);

			//mactimes
			//long ctime, long crtime, long atime, long mtime,
			statement.setLong(11, ctime);
			statement.setLong(12, crtime);
			statement.setLong(13, atime);
			statement.setLong(14, mtime);

			//parent path
			statement.setString(15, parentPath);

			connection.executeUpdate(statement);

			//add localPath 
			addFilePath(connection, newObjId, localPath);

			return new LocalFile(this, newObjId, fileName, dirType, metaType, dirFlag, metaFlags,
					size, ctime, crtime, atime, mtime, null, null, parentPath, localPath, parentId);
		} catch (SQLException e) {
			throw new TskCoreException("Error adding local file directory " + fileName + " with local path " + localPath, e);
		} finally {
			closeResultSet(resultSet);
			releaseExclusiveLock();
		}
	}

	/**
	 * Add a path (such as a local path) for a content object to tsk_file_paths
	 *
	 * @param objId object id of the file to add the path for
	 * @param path the path to add
	 * @throws SQLException exception thrown when database error occurred and
	 * path was not added
	 */
	private void addFilePath(CaseDbConnection connection, long objId, String path) throws SQLException {
		PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.INSERT_LOCAL_PATH);
		statement.clearParameters();
		statement.setLong(1, objId);
		statement.setString(2, path);
		connection.executeUpdate(statement);
	}

	/**
	 * Find all files in the data source, by name and parent
	 *
	 * @param dataSource the dataSource (Image, parent-less VirtualDirectory) to
	 * search for the given file name
	 * @param fileName Pattern of the name of the file or directory to match
	 * (case insensitive, used in LIKE SQL statement).
	 * @param parentFile Object for parent file/directory to find children in
	 * @return a list of AbstractFile for files/directories whose name matches
	 * fileName and that were inside a directory described by parentFile.
	 */
	public List<AbstractFile> findFiles(Content dataSource, String fileName, AbstractFile parentFile) throws TskCoreException {
		return findFiles(dataSource, fileName, parentFile.getName());
	}

	/**
	 * Count files matching the specific Where clause
	 *
	 * @param sqlWhereClause a SQL where clause appropriate for the desired
	 * files (do not begin the WHERE clause with the word WHERE!)
	 * @return count of files each of which satisfy the given WHERE clause
	 * @throws TskCoreException
	 */
	public long countFilesWhere(String sqlWhereClause) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT COUNT (*) FROM tsk_files WHERE " + sqlWhereClause); //NON-NLS
			return rs.getLong(1);
		} catch (SQLException e) {
			throw new TskCoreException("SQLException thrown when calling 'SleuthkitCase.findFilesWhere().", e);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseSharedLock();
		}
	}

	/**
	 * Find and return list of all (abstract) files matching the specific Where
	 * clause
	 *
	 * @param sqlWhereClause a SQL where clause appropriate for the desired
	 * files (do not begin the WHERE clause with the word WHERE!)
	 * @return a list of AbstractFile each of which satisfy the given WHERE
	 * clause
	 * @throws TskCoreException
	 */
	public List<AbstractFile> findAllFilesWhere(String sqlWhereClause) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT * FROM tsk_files WHERE " + sqlWhereClause); //NON-NLS
			return resultSetToAbstractFiles(rs);
		} catch (SQLException e) {
			throw new TskCoreException("SQLException thrown when calling 'SleuthkitCase.findAllFilesWhere(): " + sqlWhereClause, e);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseSharedLock();
		}
	}

	/**
	 * Find and return list of all (abstract) ids of files matching the specific
	 * Where clause
	 *
	 * @param sqlWhereClause a SQL where clause appropriate for the desired
	 * files (do not begin the WHERE clause with the word WHERE!)
	 * @return a list of file ids each of which satisfy the given WHERE clause
	 * @throws TskCoreException
	 */
	public List<Long> findAllFileIdsWhere(String sqlWhereClause) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT obj_id FROM tsk_files WHERE " + sqlWhereClause); //NON-NLS
			List<Long> ret = new ArrayList<Long>();
			while (rs.next()) {
				ret.add(rs.getLong(1));
			}
			return ret;
		} catch (SQLException e) {
			throw new TskCoreException("SQLException thrown when calling 'SleuthkitCase.findAllFileIdsWhere(): " + sqlWhereClause, e);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseSharedLock();
		}
	}

	/**
	 * Find and return list of files matching the specific Where clause. Use
	 * findAllFilesWhere instead. It returns a more generic data type
	 *
	 * @param sqlWhereClause a SQL where clause appropriate for the desired
	 * files (do not begin the WHERE clause with the word WHERE!)
	 * @return a list of FsContent each of which satisfy the given WHERE clause
	 * @throws TskCoreException
	 */
	@Deprecated	// use findAllFilesWhere instead
	public List<FsContent> findFilesWhere(String sqlWhereClause) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT * FROM tsk_files WHERE " + sqlWhereClause); //NON-NLS
			return resultSetToFsContents(rs);
		} catch (SQLException e) {
			throw new TskCoreException("SQLException thrown when calling 'SleuthkitCase.findFilesWhere().", e);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseSharedLock();
		}
	}

	/**
	 * @param dataSource the data source (Image, VirtualDirectory for file-sets,
	 * etc) to search for the given file name
	 * @param filePath The full path to the file(statement) of interest. This
	 * can optionally include the image and volume names. Treated in a case-
	 * insensitive manner.
	 * @return a list of AbstractFile that have the given file path.
	 */
	public List<AbstractFile> openFiles(Content dataSource, String filePath) throws TskCoreException {

		// get the non-unique path (strip of image and volume path segments, if
		// the exist.
		String path = AbstractFile.createNonUniquePath(filePath).toLowerCase();

		// split the file name from the parent path
		int lastSlash = path.lastIndexOf("/"); //NON-NLS

		// if the last slash is at the end, strip it off
		if (lastSlash == path.length()) {
			path = path.substring(0, lastSlash - 1);
			lastSlash = path.lastIndexOf("/"); //NON-NLS
		}

		String parentPath = path.substring(0, lastSlash);
		String fileName = path.substring(lastSlash);

		return findFiles(dataSource, fileName, parentPath);
	}

	/**
	 * Get file layout ranges from tsk_file_layout, for a file with specified id
	 *
	 * @param id of the file to get file layout ranges for
	 * @return list of populated file ranges
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 * core
	 */
	public List<TskFileRange> getFileRanges(long id) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "select * from tsk_file_layout where obj_id = " + id + " order by sequence");
			List<TskFileRange> ranges = new ArrayList<TskFileRange>();
			while (rs.next()) {
				ranges.add(rsHelper.tskFileRange(rs));
			}
			return ranges;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting TskFileLayoutRanges by id, id = " + id, ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseSharedLock();
		}
	}

	/**
	 * Get am image by the image object id
	 *
	 * @param id of the image object
	 * @return Image object populated
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 * core
	 */
	public Image getImageById(long id) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		Statement s1 = null;
		ResultSet rs1 = null;
		Statement s2 = null;
		ResultSet rs2 = null;
		try {
			s1 = connection.createStatement();
			rs1 = connection.executeQuery(s1, "SELECT * FROM tsk_image_info WHERE obj_id = " + id); //NON-NLS
			if (rs1.next()) {
				s2 = connection.createStatement();
				rs2 = connection.executeQuery(s2, "select * from tsk_image_names where obj_id = " + rs1.getLong("obj_id")); //NON-NLS
				List<String> imagePaths = new ArrayList<String>();
				while (rs2.next()) {
					imagePaths.add(rsHelper.imagePath(rs2));
				}
				return rsHelper.image(rs1, imagePaths.toArray(new String[imagePaths.size()]));
			} else {
				throw new TskCoreException("No image found for id: " + id);
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting Image by id, id = " + id, ex);
		} finally {
			closeResultSet(rs2);
			closeStatement(s2);
			closeResultSet(rs1);
			closeStatement(s1);
			releaseSharedLock();
		}
	}

	/**
	 * Get a volume system by the volume system object id
	 *
	 * @param id id of the volume system
	 * @param parent image containing the volume system
	 * @return populated VolumeSystem object
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 * core
	 */
	VolumeSystem getVolumeSystemById(long id, Image parent) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "select * from tsk_vs_info " //NON-NLS
					+ "where obj_id = " + id); //NON-NLS
			if (rs.next()) {
				return rsHelper.volumeSystem(rs, parent);
			} else {
				throw new TskCoreException("No volume system found for id:" + id);
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting Volume System by ID.", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseSharedLock();
		}
	}

	/**
	 * @param id ID of the desired VolumeSystem
	 * @param parentId ID of the VolumeSystem'statement parent
	 * @return the VolumeSystem with the given ID
	 * @throws TskCoreException
	 */
	VolumeSystem getVolumeSystemById(long id, long parentId) throws TskCoreException {
		VolumeSystem vs = getVolumeSystemById(id, null);
		vs.setParentId(parentId);
		return vs;
	}

	/**
	 * Get a file system by the object id
	 *
	 * @param id of the filesystem
	 * @param parent parent Image of the file system
	 * @return populated FileSystem object
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 * core
	 */
	FileSystem getFileSystemById(long id, Image parent) throws TskCoreException {
		return getFileSystemByIdHelper(id, parent);
	}

	/**
	 * @param id ID of the desired FileSystem
	 * @param parentId ID of the FileSystem'statement parent
	 * @return the desired FileSystem
	 * @throws TskCoreException
	 */
	FileSystem getFileSystemById(long id, long parentId) throws TskCoreException {
		Volume vol = null;
		FileSystem fs = getFileSystemById(id, vol);
		fs.setParentId(parentId);
		return fs;
	}

	/**
	 * Get a file system by the object id
	 *
	 * @param id of the filesystem
	 * @param parent parent Volume of the file system
	 * @return populated FileSystem object
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 * core
	 */
	FileSystem getFileSystemById(long id, Volume parent) throws TskCoreException {
		return getFileSystemByIdHelper(id, parent);
	}

	/**
	 * Get file system by id and Content parent
	 *
	 * @param id of the filesystem to get
	 * @param parent a direct parent Content object
	 * @return populated FileSystem object
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 * core
	 */
	private FileSystem getFileSystemByIdHelper(long id, Content parent) throws TskCoreException {
		// see if we already have it
		// @@@ NOTE: this is currently kind of bad in that we are ignoring the parent value,
		// but it should be the same...
		synchronized (fileSystemIdMap) {
			if (fileSystemIdMap.containsKey(id)) {
				return fileSystemIdMap.get(id);
			}
		}
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "select * from tsk_fs_info " //NON-NLS
					+ "where obj_id = " + id); //NON-NLS
			if (rs.next()) {
				FileSystem fs = rsHelper.fileSystem(rs, parent);
				// save it for the next call
				synchronized (fileSystemIdMap) {
					fileSystemIdMap.put(id, fs);
				}
				return fs;
			} else {
				throw new TskCoreException("No file system found for id:" + id);
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting File System by ID", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseSharedLock();
		}
	}

	/**
	 * Get volume by id
	 *
	 * @param id
	 * @param parent volume system
	 * @return populated Volume object
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 * core
	 */
	Volume getVolumeById(long id, VolumeSystem parent) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "select * from tsk_vs_parts " //NON-NLS
					+ "where obj_id = " + id); //NON-NLS
			if (rs.next()) {
				return rsHelper.volume(rs, parent);
			} else {
				throw new TskCoreException("No volume found for id:" + id);
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting Volume by ID", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseSharedLock();
		}
	}

	/**
	 * @param id ID of the desired Volume
	 * @param parentId ID of the Volume'statement parent
	 * @return the desired Volume
	 * @throws TskCoreException
	 */
	Volume getVolumeById(long id, long parentId) throws TskCoreException {
		Volume vol = getVolumeById(id, null);
		vol.setParentId(parentId);
		return vol;
	}

	/**
	 * Get a directory by id
	 *
	 * @param id of the directory object
	 * @param parentFs parent file system
	 * @return populated Directory object
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 * core
	 */
	Directory getDirectoryById(long id, FileSystem parentFs) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT * FROM tsk_files " //NON-NLS
					+ "WHERE obj_id = " + id);
			Directory temp = null; //NON-NLS
			if (rs.next()) {
				final short type = rs.getShort("type"); //NON-NLS
				if (type == TSK_DB_FILES_TYPE_ENUM.FS.getFileType()) {
					if (rs.getShort("meta_type") == TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_DIR.getValue()) { //NON-NLS
						temp = rsHelper.directory(rs, parentFs);
					}
				} else if (type == TSK_DB_FILES_TYPE_ENUM.VIRTUAL_DIR.getFileType()) {
					throw new TskCoreException("Expecting an FS-type directory, got virtual, id: " + id);
				}
			} else {
				throw new TskCoreException("No Directory found for id:" + id);
			}
			return temp;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting Directory by ID", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseSharedLock();
		}
	}

	/**
	 * Helper to return FileSystems in an Image
	 *
	 * @param image Image to lookup FileSystem for
	 * @return Collection of FileSystems in the image
	 */
	public Collection<FileSystem> getFileSystems(Image image) {
		List<FileSystem> fileSystems = new ArrayList<FileSystem>();
		CaseDbConnection connection;
		try {
			connection = connections.getConnection();
		} catch (TskCoreException ex) {
			logger.log(Level.SEVERE, "Error getting file systems for image " + image.getId(), ex); //NON-NLS			
			return fileSystems;
		}
		acquireSharedLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			s = connection.createStatement();

			// Get all the file systems.
			List<FileSystem> allFileSystems = new ArrayList<FileSystem>();
			try {
				rs = connection.executeQuery(s, "SELECT * FROM tsk_fs_info"); //NON-NLS
				while (rs.next()) {
					allFileSystems.add(rsHelper.fileSystem(rs, null));
				}
			} catch (SQLException ex) {
				logger.log(Level.SEVERE, "There was a problem while trying to obtain all file systems", ex); //NON-NLS
			} finally {
				closeResultSet(rs);
				rs = null;
			}

			// For each file system, find the image to which it belongs by iteratively
			// climbing the tsk_ojbects hierarchy only taking those file systems
			// that belong to this image.
			for (FileSystem fs : allFileSystems) {
				Long imageID = null;
				Long currentObjID = fs.getId();
				while (imageID == null) {
					try {
						rs = connection.executeQuery(s, "SELECT * FROM tsk_objects WHERE tsk_objects.obj_id = " + currentObjID); //NON-NLS
						currentObjID = rs.getLong("par_obj_id"); //NON-NLS
						if (rs.getInt("type") == TskData.ObjectType.IMG.getObjectType()) { //NON-NLS
							imageID = rs.getLong("obj_id"); //NON-NLS
						}
					} catch (SQLException ex) {
						logger.log(Level.SEVERE, "There was a problem while trying to obtain this image's file systems", ex); //NON-NLS
					} finally {
						closeResultSet(rs);
						rs = null;
					}
				}

				// see if imageID is this image'statement ID
				if (imageID == image.getId()) {
					fileSystems.add(fs);
				}
			}
		} catch (SQLException ex) {
			logger.log(Level.SEVERE, "Error getting case database connection", ex); //NON-NLS
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseSharedLock();
		}
		return fileSystems;
	}

	/**
	 * Returns the list of direct children for a given Image
	 *
	 * @param img image to get children for
	 * @return list of Contents (direct image children)
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 * core
	 */
	List<Content> getImageChildren(Image img) throws TskCoreException {
		Collection<ObjectInfo> childInfos = getChildrenInfo(img);
		List<Content> children = new ArrayList<Content>();
		for (ObjectInfo info : childInfos) {
			if (info.type == ObjectType.VS) {
				children.add(getVolumeSystemById(info.id, img));
			} else if (info.type == ObjectType.FS) {
				children.add(getFileSystemById(info.id, img));
			} else if (info.type == ObjectType.ABSTRACTFILE) {
				AbstractFile f = getAbstractFileById(info.id);
				if(f != null){
					children.add(f);
				}
			} else {
				throw new TskCoreException("Image has child of invalid type: " + info.type);
			}
		}
		return children;
	}

	/**
	 * Returns the list of direct children IDs for a given Image
	 *
	 * @param img image to get children for
	 * @return list of IDs (direct image children)
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 * core
	 */
	List<Long> getImageChildrenIds(Image img) throws TskCoreException {
		Collection<ObjectInfo> childInfos = getChildrenInfo(img);
		List<Long> children = new ArrayList<Long>();
		for (ObjectInfo info : childInfos) {
			if (info.type == ObjectType.VS
					|| info.type == ObjectType.FS
					|| info.type == ObjectType.ABSTRACTFILE) {
				children.add(info.id);
			} else {
				throw new TskCoreException("Image has child of invalid type: " + info.type);
			}
		}
		return children;
	}

	/**
	 * Returns the list of direct children for a given VolumeSystem
	 *
	 * @param vs volume system to get children for
	 * @return list of volume system children objects
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 * core
	 */
	List<Content> getVolumeSystemChildren(VolumeSystem vs) throws TskCoreException {
		Collection<ObjectInfo> childInfos = getChildrenInfo(vs);
		List<Content> children = new ArrayList<Content>();
		for (ObjectInfo info : childInfos) {
			if (info.type == ObjectType.VOL) {
				children.add(getVolumeById(info.id, vs));
			} else if (info.type == ObjectType.ABSTRACTFILE) {
				AbstractFile f = getAbstractFileById(info.id);
				if(f != null){
					children.add(f);
				}
			} else {
				throw new TskCoreException("VolumeSystem has child of invalid type: " + info.type);
			}
		}
		return children;
	}

	/**
	 * Returns the list of direct children IDs for a given VolumeSystem
	 *
	 * @param vs volume system to get children for
	 * @return list of volume system children IDs
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 * core
	 */
	List<Long> getVolumeSystemChildrenIds(VolumeSystem vs) throws TskCoreException {
		Collection<ObjectInfo> childInfos = getChildrenInfo(vs);
		List<Long> children = new ArrayList<Long>();
		for (ObjectInfo info : childInfos) {
			if (info.type == ObjectType.VOL || info.type == ObjectType.ABSTRACTFILE) {
				children.add(info.id);
			} else {
				throw new TskCoreException("VolumeSystem has child of invalid type: " + info.type);
			}
		}
		return children;
	}

	/**
	 * Returns a list of direct children for a given Volume
	 *
	 * @param vol volume to get children of
	 * @return list of Volume children
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 * core
	 */
	List<Content> getVolumeChildren(Volume vol) throws TskCoreException {
		Collection<ObjectInfo> childInfos = getChildrenInfo(vol);
		List<Content> children = new ArrayList<Content>();
		for (ObjectInfo info : childInfos) {
			if (info.type == ObjectType.FS) {
				children.add(getFileSystemById(info.id, vol));
			} else if (info.type == ObjectType.ABSTRACTFILE) {
				AbstractFile f = getAbstractFileById(info.id);
				if(f != null){
					children.add(f);
				}
			} else {
				throw new TskCoreException("Volume has child of invalid type: " + info.type);
			}
		}
		return children;
	}

	/**
	 * Returns a list of direct children IDs for a given Volume
	 *
	 * @param vol volume to get children of
	 * @return list of Volume children IDs
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 * core
	 */
	List<Long> getVolumeChildrenIds(Volume vol) throws TskCoreException {
		final Collection<ObjectInfo> childInfos = getChildrenInfo(vol);
		final List<Long> children = new ArrayList<Long>();
		for (ObjectInfo info : childInfos) {
			if (info.type == ObjectType.FS || info.type == ObjectType.ABSTRACTFILE) {
				children.add(info.id);
			} else {
				throw new TskCoreException("Volume has child of invalid type: " + info.type);
			}
		}
		return children;
	}

	/**
	 * Returns a map of image object IDs to a list of fully qualified file paths
	 * for that image
	 *
	 * @return map of image object IDs to file paths
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 * core
	 */
	public Map<Long, List<String>> getImagePaths() throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		Statement s1 = null;
		Statement s2 = null;
		ResultSet rs1 = null;
		ResultSet rs2 = null;
		try {
			s1 = connection.createStatement();
			rs1 = connection.executeQuery(s1, "select obj_id from tsk_image_info"); //NON-NLS
			s2 = connection.createStatement();
			Map<Long, List<String>> imgPaths = new LinkedHashMap<Long, List<String>>();
			while (rs1.next()) {
				long obj_id = rs1.getLong("obj_id"); //NON-NLS
				rs2 = connection.executeQuery(s2, "select * from tsk_image_names where obj_id = " + obj_id); //NON-NLS
				List<String> paths = new ArrayList<String>();
				while (rs2.next()) {
					paths.add(rsHelper.imagePath(rs2));
				}
				rs2.close();
				rs2 = null;
				imgPaths.put(obj_id, paths);
			}
			return imgPaths;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting image paths.", ex);
		} finally {
			closeResultSet(rs2);
			closeStatement(s2);
			closeResultSet(rs1);
			closeStatement(s1);
			releaseSharedLock();
		}
	}

	/**
	 * @return a collection of Images associated with this instance of
	 * SleuthkitCase
	 * @throws TskCoreException
	 */
	public List<Image> getImages() throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT obj_id FROM tsk_image_info"); //NON-NLS
			Collection<Long> imageIDs = new ArrayList<Long>();
			while (rs.next()) {
				imageIDs.add(rs.getLong("obj_id")); //NON-NLS
			}
			List<Image> images = new ArrayList<Image>();
			for (long id : imageIDs) {
				images.add(getImageById(id));
			}
			return images;
		} catch (SQLException ex) {
			throw new TskCoreException("Error retrieving images.", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseSharedLock();
		}
	}

	/**
	 * Get last (max) object id of content object in tsk_objects.
	 *
	 * @return currently max id
	 * @throws TskCoreException exception thrown when database error occurs and
	 * last object id could not be queried
	 */
	public long getLastObjectId() throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireExclusiveLock();
		ResultSet rs = null;
		try {
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.SELECT_MAX_OBJECT_ID);
			rs = connection.executeQuery(statement);
			long id = -1;
			if (rs.next()) {
				id = rs.getLong(1);
			}
			return id;
		} catch (SQLException e) {
			throw new TskCoreException("Error getting last object id", e);
		} finally {
			closeResultSet(rs);
			releaseExclusiveLock();
		}
	}

	/**
	 * Set the file paths for the image given by obj_id
	 *
	 * @param obj_id the ID of the image to update
	 * @param paths the fully qualified path to the files that make up the image
	 * @throws TskCoreException exception thrown when critical error occurs
	 * within tsk core and the update fails
	 */
	public void setImagePaths(long obj_id, List<String> paths) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireExclusiveLock();
		Statement statement = null;
		try {
			connection.beginTransaction();
			statement = connection.createStatement();
			connection.executeUpdate(statement, "DELETE FROM tsk_image_names WHERE obj_id = " + obj_id); //NON-NLS
			for (int i = 0; i < paths.size(); i++) {
				connection.executeUpdate(statement, "INSERT INTO tsk_image_names VALUES (" + obj_id + ", \"" + paths.get(i) + "\", " + i + ")"); //NON-NLS
			}
			connection.commitTransaction();
		} catch (SQLException ex) {
			connection.rollbackTransaction();
			throw new TskCoreException("Error updating image paths.", ex);
		} finally {
			closeStatement(statement);
			releaseExclusiveLock();
		}
	}

	/**
	 * Creates file object from a SQL query result set of rows from the
	 * tsk_files table. Assumes that the query was of the form "SELECT * FROM
	 * tsk_files WHERE XYZ".
	 *
	 * @param rs ResultSet to get content from. Caller is responsible for
	 * closing it.
	 * @return list of file objects from tsk_files table containing the results
	 * @throws SQLException if the query fails
	 */
	private List<AbstractFile> resultSetToAbstractFiles(ResultSet rs) throws SQLException {
		ArrayList<AbstractFile> results = new ArrayList<AbstractFile>();
		try {
			while (rs.next()) {
				final short type = rs.getShort("type"); //NON-NLS
				if (type == TSK_DB_FILES_TYPE_ENUM.FS.getFileType()) {
					FsContent result;
					if (rs.getShort("meta_type") == TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_DIR.getValue()) { //NON-NLS
						result = rsHelper.directory(rs, null);
					} else {
						result = rsHelper.file(rs, null);
					}
					results.add(result);
				} else if (type == TSK_DB_FILES_TYPE_ENUM.VIRTUAL_DIR.getFileType()) {
					final VirtualDirectory virtDir = rsHelper.virtualDirectory(rs);
					results.add(virtDir);
				} else if (type == TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS.getFileType()
						|| type == TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS.getFileType()
						|| type == TSK_DB_FILES_TYPE_ENUM.CARVED.getFileType()) {
					TSK_DB_FILES_TYPE_ENUM atype = TSK_DB_FILES_TYPE_ENUM.valueOf(type);
					String parentPath = rs.getString("parent_path"); //NON-NLS
					if (parentPath == null) {
						parentPath = "/"; //NON-NLS
					}
					LayoutFile lf = new LayoutFile(this, rs.getLong("obj_id"), //NON-NLS
							rs.getString("name"), //NON-NLS
							atype,
							TSK_FS_NAME_TYPE_ENUM.valueOf(rs.getShort("dir_type")), TSK_FS_META_TYPE_ENUM.valueOf(rs.getShort("meta_type")), //NON-NLS
							TSK_FS_NAME_FLAG_ENUM.valueOf(rs.getShort("dir_flags")), rs.getShort("meta_flags"), //NON-NLS
							rs.getLong("size"), //NON-NLS
							rs.getString("md5"), FileKnown.valueOf(rs.getByte("known")), parentPath); //NON-NLS
					results.add(lf);
				} else if (type == TSK_DB_FILES_TYPE_ENUM.DERIVED.getFileType()) {
					final DerivedFile df;
					df = rsHelper.derivedFile(rs, AbstractContent.UNKNOWN_ID);
					results.add(df);
				} else if (type == TSK_DB_FILES_TYPE_ENUM.LOCAL.getFileType()) {
					final LocalFile lf;
					lf = rsHelper.localFile(rs, AbstractContent.UNKNOWN_ID);
					results.add(lf);
				}

			} //end for each resultSet
		} catch (SQLException e) {
			logger.log(Level.SEVERE, "Error getting abstract files from result set", e); //NON-NLS
		}

		return results;
	}

	/**
	 * Creates FsContent objects from SQL query result set on tsk_files table
	 *
	 * @param rs the result set with the query results
	 * @return list of fscontent objects matching the query
	 * @throws SQLException if SQL query result getting failed
	 */
	private List<FsContent> resultSetToFsContents(ResultSet rs) throws SQLException {
		List<FsContent> results = new ArrayList<FsContent>();
		List<AbstractFile> temp = resultSetToAbstractFiles(rs);
		for (AbstractFile f : temp) {
			final TSK_DB_FILES_TYPE_ENUM type = f.getType();
			if (type.equals(TskData.TSK_DB_FILES_TYPE_ENUM.FS)) {
				results.add((FsContent) f);
			}
		}
		return results;
	}

	/**
	 * Process a read-only query on the tsk database, any table Can be used to
	 * e.g. to find files of a given criteria. resultSetToFsContents() will
	 * convert the results to useful objects. MUST CALL closeRunQuery() when
	 * done
	 *
	 * @param query the given string query to run
	 * @return	the resultSet from running the query. Caller MUST CALL
	 * closeRunQuery(resultSet) as soon as possible, when done with retrieving
	 * data from the resultSet
	 * @throws SQLException if error occurred during the query
	 * @deprecated use specific datamodel methods that encapsulate SQL layer
	 */
	@Deprecated
	public ResultSet runQuery(String query) throws SQLException {
		CaseDbConnection connection;
		try {
			connection = connections.getConnection();
		} catch (TskCoreException ex) {
			throw new SQLException("Error getting connection for ad hoc query", ex);
		}
		acquireSharedLock();
		try {
			return connection.executeQuery(connection.createStatement(), query);
		} finally {
			//TODO unlock should be done in closeRunQuery()
			//but currently not all code calls closeRunQuery - need to fix this
			releaseSharedLock();
		}
	}

	/**
	 * Closes ResultSet and its Statement previously retrieved from runQuery()
	 *
	 * @param resultSet with its Statement to close
	 * @throws SQLException of closing the query results failed
	 * @deprecated use specific datamodel methods that encapsulate SQL layer
	 */
	@Deprecated
	public void closeRunQuery(ResultSet resultSet) throws SQLException {
		final Statement statement = resultSet.getStatement();
		resultSet.close();
		if (statement != null) {
			statement.close();
		}
	}

	/**
	 * This method allows developers to run arbitrary SQL "SELECT"
	 * queries. The CaseDbQuery object will take care of acquiring
	 * the necessary database lock and when used in a try-with-resources
	 * block will automatically take care of releasing the lock.
	 * If you do not use a try-with-resources block you must call 
	 * CaseDbQuery.close() once you are done processing the results of
	 * the query.
	 * @param query The query string to execute.
	 * @return A CaseDbQuery instance.
	 * @throws TskCoreException 
	 */
	public CaseDbQuery executeQuery(String query) throws TskCoreException {
		return new CaseDbQuery(query);
	}
	
	@Override
	public void finalize() throws Throwable {
		try {
			close();
		} finally {
			super.finalize();
		}
	}

	/**
	 * Call to free resources when done with instance.
	 */
	public void close() {
		System.err.println(this.hashCode() + " closed"); //NON-NLS
		System.err.flush();
		acquireExclusiveLock();
		connections.close();
		fileSystemIdMap.clear();

		try {
			if (this.caseHandle != null) {
				this.caseHandle.free();
				this.caseHandle = null;

			}
		} catch (TskCoreException ex) {
			logger.log(Level.WARNING,
					"Error freeing case handle.", ex); //NON-NLS
		} finally {
			releaseExclusiveLock();
		}
	}

	/**
	 * Store the known status for the FsContent in the database Note: will not
	 * update status if content is already 'Known Bad'
	 *
	 * @param	file	The AbstractFile object
	 * @param	fileKnown	The object'statement known status
	 * @return	true if the known status was updated, false otherwise
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 * core
	 */
	public boolean setKnown(AbstractFile file, FileKnown fileKnown) throws TskCoreException {
		long id = file.getId();
		FileKnown currentKnown = file.getKnown();
		if (currentKnown.compareTo(fileKnown) > 0) {
			return false;
		}
		CaseDbConnection connection = connections.getConnection();
		acquireExclusiveLock();
		Statement statement = null;
		try {
			statement = connection.createStatement();
			connection.executeUpdate(statement, "UPDATE tsk_files " //NON-NLS
					+ "SET known='" + fileKnown.getFileKnownValue() + "' " //NON-NLS
					+ "WHERE obj_id=" + id); //NON-NLS
			file.setKnown(fileKnown);
		} catch (SQLException ex) {
			throw new TskCoreException("Error setting Known status.", ex);
		} finally {
			closeStatement(statement);
			releaseExclusiveLock();
		}
		return true;
	}

	/**
	 * Store the md5Hash for the file in the database
	 *
	 * @param	file	The file object
	 * @param	md5Hash	The object'statement md5Hash
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 * core
	 */
	void setMd5Hash(AbstractFile file, String md5Hash) throws TskCoreException {
		if(md5Hash == null){
			return;
		}
		long id = file.getId();
		CaseDbConnection connection = connections.getConnection();
		acquireExclusiveLock();
		try {
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.UPDATE_FILE_MD5);
			statement.clearParameters();
			statement.setString(1, md5Hash.toLowerCase());
			statement.setLong(2, id);
			connection.executeUpdate(statement);
			file.setMd5Hash(md5Hash.toLowerCase());
		} catch (SQLException ex) {
			throw new TskCoreException("Error setting MD5 hash", ex);
		} finally {
			releaseExclusiveLock();
		}
	}

	/**
	 * Return the number of objects in the database of a given file type.
	 *
	 * @param contentType Type of file to count
	 * @return Number of objects with that type.
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 * core
	 */
	public int countFsContentType(TskData.TSK_FS_META_TYPE_ENUM contentType) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			s = connection.createStatement();
			Short contentShort = contentType.getValue();
			rs = connection.executeQuery(s, "SELECT COUNT(*) FROM tsk_files WHERE meta_type = '" + contentShort.toString() + "'"); //NON-NLS
			int count = 0;
			if (rs.next()) {
				count = rs.getInt(1);
			}
			return count;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting number of objects.", ex);
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseSharedLock();
		}
	}

	/**
	 * Escape the single quotes in the given string so they can be added to the
	 * SQL caseDbConnection
	 *
	 * @param text
	 * @return text the escaped version
	 */
	private static String escapeForBlackboard(String text) {
		if (text != null) {
			text = text.replaceAll("'", "''");
		}
		return text;
	}

	/**
	 * Find all the files with the given MD5 hash.
	 *
	 * @param md5Hash hash value to match files with
	 * @return List of AbstractFile with the given hash
	 */
	public List<AbstractFile> findFilesByMd5(String md5Hash) {
		if(md5Hash == null){
			return Collections.<AbstractFile>emptyList();
		}
		CaseDbConnection connection;
		try {
			connection = connections.getConnection();
		} catch (TskCoreException ex) {
			logger.log(Level.SEVERE, "Error finding files by md5 hash " + md5Hash, ex); //NON-NLS			
			return Collections.<AbstractFile>emptyList();
		}
		acquireSharedLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT * FROM tsk_files WHERE " //NON-NLS
					+ " md5 = '" + md5Hash.toLowerCase() + "' " //NON-NLS
					+ "AND size > 0"); //NON-NLS
			return resultSetToAbstractFiles(rs);
		} catch (SQLException ex) {
			logger.log(Level.WARNING, "Error querying database.", ex); //NON-NLS
			return Collections.<AbstractFile>emptyList();
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseSharedLock();
		}
	}

	/**
	 * Query all the files to verify if they have an MD5 hash associated with
	 * them.
	 *
	 * @return true if all files have an MD5 hash
	 */
	public boolean allFilesMd5Hashed() {
		CaseDbConnection connection;
		try {
			connection = connections.getConnection();
		} catch (TskCoreException ex) {
			logger.log(Level.SEVERE, "Error checking md5 hashing status", ex); //NON-NLS			
			return false;
		}
		boolean allFilesAreHashed = false;
		acquireSharedLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT COUNT(*) FROM tsk_files " //NON-NLS
					+ "WHERE dir_type = '" + TskData.TSK_FS_NAME_TYPE_ENUM.REG.getValue() + "' " //NON-NLS
					+ "AND md5 IS NULL " //NON-NLS
					+ "AND size > '0'"); //NON-NLS
			if (rs.next() && rs.getInt(1) == 0) {
				allFilesAreHashed = true;
			}
		} catch (SQLException ex) {
			logger.log(Level.WARNING, "Failed to query whether all files have MD5 hashes", ex); //NON-NLS
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseSharedLock();
		}
		return allFilesAreHashed;
	}

	/**
	 * Query all the files and counts how many have an MD5 hash.
	 *
	 * @return the number of files with an MD5 hash
	 */
	public int countFilesMd5Hashed() {
		CaseDbConnection connection;
		try {
			connection = connections.getConnection();
		} catch (TskCoreException ex) {
			logger.log(Level.SEVERE, "Error getting database connection for hashed files count", ex); //NON-NLS			
			return 0;
		}
		int count = 0;
		acquireSharedLock();
		Statement s = null;
		ResultSet rs = null;
		try {
			s = connection.createStatement();
			rs = connection.executeQuery(s, "SELECT COUNT(*) FROM tsk_files " //NON-NLS
					+ "WHERE md5 IS NOT NULL " //NON-NLS
					+ "AND size > '0'"); //NON-NLS
			if (rs.next()) {
				count = rs.getInt(1);
			}
		} catch (SQLException ex) {
			logger.log(Level.WARNING, "Failed to query for all the files.", ex); //NON-NLS
		} finally {
			closeResultSet(rs);
			closeStatement(s);
			releaseSharedLock();
		}
		return count;
	}

	/**
	 * This is a temporary workaround to avoid an API change.
	 *
	 * @deprecated
	 */
	@Deprecated
	public interface ErrorObserver {

		void receiveError(String context, String errorMessage);
	}

	/**
	 * This is a temporary workaround to avoid an API change.
	 *
	 * @deprecated
	 * @param observer The observer to add.
	 */
	@Deprecated
	public void addErrorObserver(ErrorObserver observer) {
		errorObservers.add(observer);
	}

	/**
	 * This is a temporary workaround to avoid an API change.
	 *
	 * @deprecated
	 * @param observer The observer to remove.
	 */
	@Deprecated
	public void removerErrorObserver(ErrorObserver observer) {
		int i = errorObservers.indexOf(observer);
		if (i >= 0) {
			errorObservers.remove(i);
		}
	}

	/**
	 * This is a temporary workaround to avoid an API change.
	 *
	 * @deprecated
	 * @param context The context in which the error occurred.
	 * @param errorMessage A description of the error that occurred.
	 */
	@Deprecated
	public void submitError(String context, String errorMessage) {
		for (ErrorObserver observer : errorObservers) {
			observer.receiveError(context, errorMessage);
		}
	}

	/**
	 * Selects all of the rows from the tag_names table in the case database.
	 *
	 * @return A list, possibly empty, of TagName data transfer objects (DTOs)
	 * for the rows.
	 * @throws TskCoreException
	 */
	public List<TagName> getAllTagNames() throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		ResultSet resultSet = null;
		try {
			// SELECT * FROM tag_names
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.SELECT_TAG_NAMES);
			resultSet = connection.executeQuery(statement);
			ArrayList<TagName> tagNames = new ArrayList<TagName>();
			while (resultSet.next()) {
				tagNames.add(new TagName(resultSet.getLong("tag_name_id"), resultSet.getString("display_name"), resultSet.getString("description"), TagName.HTML_COLOR.getColorByName(resultSet.getString("color")))); //NON-NLS
			}
			return tagNames;
		} catch (SQLException ex) {
			throw new TskCoreException("Error selecting rows from tag_names table", ex);
		} finally {
			closeResultSet(resultSet);
			releaseSharedLock();
		}
	}

	/**
	 * Selects all of the rows from the tag_names table in the case database for
	 * which there is at least one matching row in the content_tags or
	 * blackboard_artifact_tags tables.
	 *
	 * @return A list, possibly empty, of TagName data transfer objects (DTOs)
	 * for the rows.
	 * @throws TskCoreException
	 */
	public List<TagName> getTagNamesInUse() throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		ResultSet resultSet = null;
		try {
			// SELECT * FROM tag_names WHERE tag_name_id IN (SELECT tag_name_id from content_tags UNION SELECT tag_name_id FROM blackboard_artifact_tags)
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.SELECT_TAG_NAMES_IN_USE);
			resultSet = connection.executeQuery(statement);
			ArrayList<TagName> tagNames = new ArrayList<TagName>();
			while (resultSet.next()) {
				tagNames.add(new TagName(resultSet.getLong("tag_name_id"), resultSet.getString("display_name"), resultSet.getString("description"), TagName.HTML_COLOR.getColorByName(resultSet.getString("color")))); //NON-NLS
			}
			return tagNames;
		} catch (SQLException ex) {
			throw new TskCoreException("Error selecting rows from tag_names table", ex);
		} finally {
			closeResultSet(resultSet);
			releaseSharedLock();
		}
	}

	/**
	 * Inserts row into the tags_names table in the case database.
	 *
	 * @param displayName The display name for the new tag name.
	 * @param description The description for the new tag name.
	 * @param color The HTML color to associate with the new tag name.
	 * @return A TagName data transfer object (DTO) for the new row.
	 * @throws TskCoreException
	 */
	public TagName addTagName(String displayName, String description, TagName.HTML_COLOR color) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireExclusiveLock();
		ResultSet resultSet = null;
		try {
			// INSERT INTO tag_names (display_name, description, color) VALUES (?, ?, ?)			
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.INSERT_TAG_NAME);
			statement.clearParameters();
			statement.setString(1, displayName);
			statement.setString(2, description);
			statement.setString(3, color.getName());
			connection.executeUpdate(statement);
			resultSet = statement.getGeneratedKeys();
			return new TagName(resultSet.getLong(1), displayName, description, color);
		} catch (SQLException ex) {
			throw new TskCoreException("Error adding row for " + displayName + " tag name to tag_names table", ex);
		} finally {
			closeResultSet(resultSet);
			releaseExclusiveLock();
		}
	}

	/**
	 * Inserts a row into the content_tags table in the case database.
	 *
	 * @param content The content to tag.
	 * @param tagName The name to use for the tag.
	 * @param comment A comment to store with the tag.
	 * @param beginByteOffset Designates the beginning of a tagged section.
	 * @param endByteOffset Designates the end of a tagged section.
	 * @return A ContentTag data transfer object (DTO) for the new row.
	 * @throws TskCoreException
	 */
	public ContentTag addContentTag(Content content, TagName tagName, String comment, long beginByteOffset, long endByteOffset) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireExclusiveLock();
		ResultSet resultSet = null;
		try {
			// INSERT INTO content_tags (obj_id, tag_name_id, comment, begin_byte_offset, end_byte_offset) VALUES (?, ?, ?, ?, ?)
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.INSERT_CONTENT_TAG);
			statement.clearParameters();
			statement.setLong(1, content.getId());
			statement.setLong(2, tagName.getId());
			statement.setString(3, comment);
			statement.setLong(4, beginByteOffset);
			statement.setLong(5, endByteOffset);
			connection.executeUpdate(statement);
			resultSet = statement.getGeneratedKeys();
			return new ContentTag(resultSet.getLong(1), content, tagName, comment, beginByteOffset, endByteOffset);
		} catch (SQLException ex) {
			throw new TskCoreException("Error adding row to content_tags table (obj_id = " + content.getId() + ", tag_name_id = " + tagName.getId() + ")", ex);
		} finally {
			closeResultSet(resultSet);
			releaseExclusiveLock();
		}
	}

	/*
	 * Deletes a row from the content_tags table in the case database.
	 * @param tag A ContentTag data transfer object (DTO) for the row to delete.
	 * @throws TskCoreException 
	 */
	public void deleteContentTag(ContentTag tag) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireExclusiveLock();
		try {
			// DELETE FROM content_tags WHERE tag_id = ?		
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.DELETE_CONTENT_TAG);
			statement.clearParameters();
			statement.setLong(1, tag.getId());
			connection.executeUpdate(statement);
		} catch (SQLException ex) {
			throw new TskCoreException("Error deleting row from content_tags table (id = " + tag.getId() + ")", ex);
		} finally {
			releaseExclusiveLock();
		}
	}

	/**
	 * Selects all of the rows from the content_tags table in the case database.
	 *
	 * @return A list, possibly empty, of ContentTag data transfer objects
	 * (DTOs) for the rows.
	 * @throws TskCoreException
	 */
	public List<ContentTag> getAllContentTags() throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		ResultSet resultSet = null;
		try {
			// SELECT * FROM content_tags INNER JOIN tag_names ON content_tags.tag_name_id = tag_names.tag_name_id
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.SELECT_CONTENT_TAGS);
			resultSet = connection.executeQuery(statement);
			ArrayList<ContentTag> tags = new ArrayList<ContentTag>();
			while (resultSet.next()) {
				TagName tagName = new TagName(resultSet.getLong(2), resultSet.getString("display_name"), resultSet.getString("description"), TagName.HTML_COLOR.getColorByName(resultSet.getString("color")));  //NON-NLS
				Content content = getContentById(resultSet.getLong("obj_id")); //NON-NLS
				tags.add(new ContentTag(resultSet.getLong("tag_id"), content, tagName, resultSet.getString("comment"), resultSet.getLong("begin_byte_offset"), resultSet.getLong("end_byte_offset")));  //NON-NLS
			}
			return tags;
		} catch (SQLException ex) {
			throw new TskCoreException("Error selecting rows from content_tags table", ex);
		} finally {
			closeResultSet(resultSet);
			releaseSharedLock();
		}
	}

	/**
	 * Gets a count of the rows in the content_tags table in the case database
	 * with a specified foreign key into the tag_names table.
	 *
	 * @param tagName A data transfer object (DTO) for the tag name to match.
	 * @return The count, possibly zero.
	 * @throws TskCoreException
	 */
	public long getContentTagsCountByTagName(TagName tagName) throws TskCoreException {
		if (tagName.getId() == Tag.ID_NOT_SET) {
			throw new TskCoreException("TagName object is invalid, id not set");
		}
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		ResultSet resultSet = null;
		try {
			// SELECT COUNT(*) FROM content_tags WHERE tag_name_id = ?
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.COUNT_CONTENT_TAGS_BY_TAG_NAME);
			statement.clearParameters();
			statement.setLong(1, tagName.getId());
			resultSet = connection.executeQuery(statement);
			if (resultSet.next()) {
				return resultSet.getLong(1);
			} else {
				throw new TskCoreException("Error getting content_tags row count for tag name (tag_name_id = " + tagName.getId() + ")");
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting content_tags row count for tag name (tag_name_id = " + tagName.getId() + ")", ex);
		} finally {
			closeResultSet(resultSet);
			releaseSharedLock();
		}
	}

	/**
	 * Selects the rows in the content_tags table in the case database with a
	 * specified foreign key into the tag_names table.
	 *
	 * @param tagName A data transfer object (DTO) for the tag name to match.
	 * @return A list, possibly empty, of ContentTag data transfer objects
	 * (DTOs) for the rows.
	 * @throws TskCoreException
	 */
	public List<ContentTag> getContentTagsByTagName(TagName tagName) throws TskCoreException {
		if (tagName.getId() == Tag.ID_NOT_SET) {
			throw new TskCoreException("TagName object is invalid, id not set");
		}
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		ResultSet resultSet = null;
		try {
			// SELECT * FROM content_tags WHERE tag_name_id = ?
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.SELECT_CONTENT_TAGS_BY_TAG_NAME);
			statement.clearParameters();
			statement.setLong(1, tagName.getId());
			resultSet = connection.executeQuery(statement);
			ArrayList<ContentTag> tags = new ArrayList<ContentTag>();
			while (resultSet.next()) {
				ContentTag tag = new ContentTag(resultSet.getLong("tag_id"), getContentById(resultSet.getLong("obj_id")), tagName, resultSet.getString("comment"), resultSet.getLong("begin_byte_offset"), resultSet.getLong("end_byte_offset"));  //NON-NLS
				tags.add(tag);
			}
			resultSet.close();
			return tags;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting content_tags rows (tag_name_id = " + tagName.getId() + ")", ex);
		} finally {
			closeResultSet(resultSet);
			releaseSharedLock();
		}
	}

	/**
	 * Selects the rows in the content_tags table in the case database with a
	 * specified foreign key into the tsk_objects table.
	 *
	 * @param content A data transfer object (DTO) for the content to match.
	 * @return A list, possibly empty, of ContentTag data transfer objects
	 * (DTOs) for the rows.
	 * @throws TskCoreException
	 */
	public List<ContentTag> getContentTagsByContent(Content content) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		ResultSet resultSet = null;
		try {
			// SELECT * FROM content_tags INNER JOIN tag_names ON content_tags.tag_name_id = tag_names.tag_name_id WHERE content_tags.obj_id = ?
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.SELECT_CONTENT_TAGS_BY_CONTENT);
			statement.clearParameters();
			statement.setLong(1, content.getId());
			resultSet = connection.executeQuery(statement);
			ArrayList<ContentTag> tags = new ArrayList<ContentTag>();
			while (resultSet.next()) {
				TagName tagName = new TagName(resultSet.getLong(2), resultSet.getString("display_name"), resultSet.getString("description"), TagName.HTML_COLOR.getColorByName(resultSet.getString("color")));  //NON-NLS
				ContentTag tag = new ContentTag(resultSet.getLong("tag_id"), content, tagName, resultSet.getString("comment"), resultSet.getLong("begin_byte_offset"), resultSet.getLong("end_byte_offset"));  //NON-NLS
				tags.add(tag);
			}
			return tags;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting content tags data for content (obj_id = " + content.getId() + ")", ex);
		} finally {
			closeResultSet(resultSet);
			releaseSharedLock();
		}
	}

	/**
	 * Inserts a row into the blackboard_artifact_tags table in the case
	 * database.
	 *
	 * @param artifact The blackboard artifact to tag.
	 * @param tagName The name to use for the tag.
	 * @param comment A comment to store with the tag.
	 * @return A BlackboardArtifactTag data transfer object (DTO) for the new
	 * row.
	 * @throws TskCoreException
	 */
	public BlackboardArtifactTag addBlackboardArtifactTag(BlackboardArtifact artifact, TagName tagName, String comment) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireExclusiveLock();
		ResultSet resultSet = null;
		try {
			// INSERT INTO blackboard_artifact_tags (artifact_id, tag_name_id, comment, begin_byte_offset, end_byte_offset) VALUES (?, ?, ?, ?, ?)			
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.INSERT_ARTIFACT_TAG);
			statement.clearParameters();
			statement.setLong(1, artifact.getArtifactID());
			statement.setLong(2, tagName.getId());
			statement.setString(3, comment);
			connection.executeUpdate(statement);
			resultSet = statement.getGeneratedKeys();
			return new BlackboardArtifactTag(resultSet.getLong(1), artifact, getContentById(artifact.getObjectID()), tagName, comment);
		} catch (SQLException ex) {
			throw new TskCoreException("Error adding row to blackboard_artifact_tags table (obj_id = " + artifact.getArtifactID() + ", tag_name_id = " + tagName.getId() + ")", ex);
		} finally {
			closeResultSet(resultSet);
			releaseExclusiveLock();
		}
	}

	/*
	 * Deletes a row from the blackboard_artifact_tags table in the case database.
	 * @param tag A BlackboardArtifactTag data transfer object (DTO) representing the row to delete.
	 * @throws TskCoreException 
	 */
	public void deleteBlackboardArtifactTag(BlackboardArtifactTag tag) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireExclusiveLock();
		try {
			// DELETE FROM blackboard_artifact_tags WHERE tag_id = ?
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.DELETE_ARTIFACT_TAG);
			statement.clearParameters();
			statement.setLong(1, tag.getId());
			connection.executeUpdate(statement);
		} catch (SQLException ex) {
			throw new TskCoreException("Error deleting row from blackboard_artifact_tags table (id = " + tag.getId() + ")", ex);
		} finally {
			releaseExclusiveLock();
		}
	}

	/**
	 * Selects all of the rows from the blackboard_artifacts_tags table in the
	 * case database.
	 *
	 * @return A list, possibly empty, of BlackboardArtifactTag data transfer
	 * objects (DTOs) for the rows.
	 * @throws TskCoreException
	 */
	public List<BlackboardArtifactTag> getAllBlackboardArtifactTags() throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		ResultSet resultSet = null;
		try {
			// SELECT * FROM blackboard_artifact_tags INNER JOIN tag_names ON blackboard_artifact_tags.tag_name_id = tag_names.tag_name_id
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.SELECT_ARTIFACT_TAGS);
			resultSet = connection.executeQuery(statement);
			ArrayList<BlackboardArtifactTag> tags = new ArrayList<BlackboardArtifactTag>();
			while (resultSet.next()) {
				TagName tagName = new TagName(resultSet.getLong(2), resultSet.getString("display_name"), resultSet.getString("description"), TagName.HTML_COLOR.getColorByName(resultSet.getString("color")));  //NON-NLS
				BlackboardArtifact artifact = getBlackboardArtifact(resultSet.getLong("artifact_id")); //NON-NLS
				Content content = getContentById(artifact.getObjectID());
				BlackboardArtifactTag tag = new BlackboardArtifactTag(resultSet.getLong("tag_id"), artifact, content, tagName, resultSet.getString("comment"));  //NON-NLS
				tags.add(tag);
			}
			return tags;
		} catch (SQLException ex) {
			throw new TskCoreException("Error selecting rows from blackboard_artifact_tags table", ex);
		} finally {
			closeResultSet(resultSet);
			releaseSharedLock();
		}
	}

	/**
	 * Gets a count of the rows in the blackboard_artifact_tags table in the
	 * case database with a specified foreign key into the tag_names table.
	 *
	 * @param tagName A data transfer object (DTO) for the tag name to match.
	 * @return The count, possibly zero.
	 * @throws TskCoreException
	 */
	public long getBlackboardArtifactTagsCountByTagName(TagName tagName) throws TskCoreException {
		if (tagName.getId() == Tag.ID_NOT_SET) {
			throw new TskCoreException("TagName object is invalid, id not set");
		}
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		ResultSet resultSet = null;
		try {
			// SELECT COUNT(*) FROM blackboard_artifact_tags WHERE tag_name_id = ?
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.COUNT_ARTIFACTS_BY_TAG_NAME);
			statement.clearParameters();
			statement.setLong(1, tagName.getId());
			resultSet = connection.executeQuery(statement);
			if (resultSet.next()) {
				return resultSet.getLong(1);
			} else {
				throw new TskCoreException("Error getting blackboard_artifact_tags row count for tag name (tag_name_id = " + tagName.getId() + ")");
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting blackboard artifact_content_tags row count for tag name (tag_name_id = " + tagName.getId() + ")", ex);
		} finally {
			closeResultSet(resultSet);
			releaseSharedLock();
		}
	}

	/**
	 * Selects the rows in the blackboard_artifacts_tags table in the case
	 * database with a specified foreign key into the tag_names table.
	 *
	 * @param tagName A data transfer object (DTO) for the tag name to match.
	 * @return A list, possibly empty, of BlackboardArtifactTag data transfer
	 * objects (DTOs) for the rows.
	 * @throws TskCoreException
	 */
	public List<BlackboardArtifactTag> getBlackboardArtifactTagsByTagName(TagName tagName) throws TskCoreException {
		if (tagName.getId() == Tag.ID_NOT_SET) {
			throw new TskCoreException("TagName object is invalid, id not set");
		}
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		ResultSet resultSet = null;
		try {
			// SELECT * FROM blackboard_artifact_tags WHERE tag_name_id = ?
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.SELECT_ARTIFACT_TAGS_BY_TAG_NAME);
			statement.clearParameters();
			statement.setLong(1, tagName.getId());
			resultSet = connection.executeQuery(statement);
			ArrayList<BlackboardArtifactTag> tags = new ArrayList<BlackboardArtifactTag>();
			while (resultSet.next()) {
				BlackboardArtifact artifact = getBlackboardArtifact(resultSet.getLong("artifact_id")); //NON-NLS
				Content content = getContentById(artifact.getObjectID());
				BlackboardArtifactTag tag = new BlackboardArtifactTag(resultSet.getLong("tag_id"), artifact, content, tagName, resultSet.getString("comment"));  //NON-NLS
				tags.add(tag);
			}
			return tags;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting blackboard artifact tags data (tag_name_id = " + tagName.getId() + ")", ex);
		} finally {
			closeResultSet(resultSet);
			releaseSharedLock();
		}
	}

	/**
	 * Selects the rows in the blackboard_artifacts_tags table in the case
	 * database with a specified foreign key into the blackboard_artifacts
	 * table.
	 *
	 * @param artifact A data transfer object (DTO) for the artifact to match.
	 * @return A list, possibly empty, of BlackboardArtifactTag data transfer
	 * objects (DTOs) for the rows.
	 * @throws TskCoreException
	 */
	public List<BlackboardArtifactTag> getBlackboardArtifactTagsByArtifact(BlackboardArtifact artifact) throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		ResultSet resultSet = null;
		try {
			// SELECT * FROM blackboard_artifact_tags INNER JOIN tag_names ON blackboard_artifact_tags.tag_name_id = tag_names.tag_name_id WHERE blackboard_artifact_tags.artifact_id = ?			
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.SELECT_ARTIFACT_TAGS_BY_ARTIFACT);
			statement.clearParameters();
			statement.setLong(1, artifact.getArtifactID());
			resultSet = connection.executeQuery(statement);
			ArrayList<BlackboardArtifactTag> tags = new ArrayList<BlackboardArtifactTag>();
			while (resultSet.next()) {
				TagName tagName = new TagName(resultSet.getLong(2), resultSet.getString("display_name"), resultSet.getString("description"), TagName.HTML_COLOR.getColorByName(resultSet.getString("color")));  //NON-NLS
				Content content = getContentById(artifact.getObjectID());
				BlackboardArtifactTag tag = new BlackboardArtifactTag(resultSet.getLong("tag_id"), artifact, content, tagName, resultSet.getString("comment"));  //NON-NLS
				tags.add(tag);
			}
			return tags;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting blackboard artifact tags data (artifact_id = " + artifact.getArtifactID() + ")", ex);
		} finally {
			closeResultSet(resultSet);
			releaseSharedLock();
		}
	}

	/**
	 * Inserts a row into the reports table in the case database.
	 *
	 * @param localPath The path of the report file, must be in the database
	 * directory (case directory in Autopsy) or one of its subdirectories.
	 * @param sourceModuleName The name of the module that created the report.
	 * @param reportName The report name, may be empty.
	 * @return A Report data transfer object (DTO) for the new row.
	 * @throws TskCoreException
	 */
	public Report addReport(String localPath, String sourceModuleName, String reportName) throws TskCoreException {
		// Make sure the local path of the report is in the database directory
		// or one of its subdirectories.
		String relativePath = ""; //NON-NLS
		try {
			relativePath = new File(getDbDirPath()).toURI().relativize(new File(localPath).toURI()).getPath();
		} catch (IllegalArgumentException ex) {
			String errorMessage = String.format("Local path %s not in the database directory or one of its subdirectories", localPath);
			throw new TskCoreException(errorMessage, ex);
		}

		// Figure out the create time of the report.
		long createTime = 0;
		try {
			java.io.File tempFile = new java.io.File(localPath);
			// Convert to UNIX epoch (seconds, not milliseconds).
			createTime = tempFile.lastModified() / 1000;
		} catch (Exception ex) {
			throw new TskCoreException("Could not get create time for report at " + localPath, ex);
		}

		// Write the report data to the database.
		CaseDbConnection connection = connections.getConnection();
		acquireExclusiveLock();
		ResultSet resultSet = null;
		try {
			// INSERT INTO reports (path, crtime, src_module_name, display_name) VALUES (?, ?, ?, ?)			
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.INSERT_REPORT);
			statement.clearParameters();
			statement.setString(1, relativePath);
			statement.setLong(2, createTime);
			statement.setString(3, sourceModuleName);
			statement.setString(4, reportName);
			connection.executeUpdate(statement);
			resultSet = statement.getGeneratedKeys();
			return new Report(resultSet.getLong(1), localPath, createTime, sourceModuleName, reportName);
		} catch (SQLException ex) {
			throw new TskCoreException("Error adding report " + localPath + " to reports table", ex);
		} finally {
			closeResultSet(resultSet);
			releaseExclusiveLock();
		}
	}

	/**
	 * Selects all of the rows from the reports table in the case database.
	 *
	 * @return A list, possibly empty, of Report data transfer objects (DTOs)
	 * for the rows.
	 * @throws TskCoreException
	 */
	public List<Report> getAllReports() throws TskCoreException {
		CaseDbConnection connection = connections.getConnection();
		acquireSharedLock();
		ResultSet resultSet = null;
		try {
			PreparedStatement statement = connection.getPreparedStatement(CaseDbConnection.PREPARED_STATEMENT.SELECT_REPORTS);
			resultSet = connection.executeQuery(statement);
			ArrayList<Report> reports = new ArrayList<Report>();
			while (resultSet.next()) {
				reports.add(new Report(resultSet.getLong("report_id"), //NON-NLS
						getDbDirPath() + java.io.File.separator + resultSet.getString("path"), //NON-NLS
						resultSet.getLong("crtime"), //NON-NLS
						resultSet.getString("src_module_name"), //NON-NLS
						resultSet.getString("report_name")));  //NON-NLS
			}
			return reports;
		} catch (SQLException ex) {
			throw new TskCoreException("Error querying reports table", ex);
		} finally {
			closeResultSet(resultSet);
			releaseSharedLock();
		}
	}

	private static void closeResultSet(ResultSet resultSet) {
		if (resultSet != null) {
			try {
				resultSet.close();
			} catch (SQLException ex) {
				logger.log(Level.SEVERE, "Error closing ResultSet", ex); //NON-NLS
			}
		}
	}

	private static void closeStatement(Statement statement) {
		if (statement != null) {
			try {
				statement.close();
			} catch (SQLException ex) {
				logger.log(Level.SEVERE, "Error closing Statement", ex); //NON-NLS
			}
		}
	}

	private final class ConnectionPerThreadDispenser extends ThreadLocal<CaseDbConnection> {
		
		private final HashSet<CaseDbConnection> databaseConnections = new HashSet<CaseDbConnection>();
		private boolean isClosed = false;

		synchronized CaseDbConnection getConnection() throws TskCoreException {
			if(isClosed){
				throw new TskCoreException("Error getting case database connection - case is closed");
			}
			
			CaseDbConnection connection = get();
			if (!connection.isOpen()) {
				throw new TskCoreException("Case database connection for current thread is not open");
			}
			databaseConnections.add(connection);
			return connection;
		}

		/**
		 * ****************
		 * Close the CaseDbConnection, which in turn releases the file handle to
		 * the database
		 */
		public synchronized void close() {
			for (CaseDbConnection entry : databaseConnections) {
				entry.close();
			}
			databaseConnections.clear();
			isClosed = true;
		}

		@Override
		public CaseDbConnection initialValue() {
			return new CaseDbConnection(dbPath);
		}
	}

	/**
	 * Encapsulates a connection to the underlying SQLite case database and a
	 * set of prepared statements.
	 */
	private static final class CaseDbConnection {

		enum PREPARED_STATEMENT {

			SELECT_ATTRIBUTES_OF_ARTIFACT("SELECT artifact_id, source, context, attribute_type_id, value_type, " //NON-NLS
					+ "value_byte, value_text, value_int32, value_int64, value_double " //NON-NLS
					+ "FROM blackboard_attributes WHERE artifact_id = ?"), //NON-NLS
			SELECT_ARTIFACT_BY_ID("SELECT obj_id, artifact_type_id FROM blackboard_artifacts WHERE artifact_id = ?"), //NON-NLS
			SELECT_ARTIFACTS_BY_TYPE("SELECT artifact_id, obj_id FROM blackboard_artifacts " //NON-NLS
					+ "WHERE artifact_type_id = ?"), //NON-NLS
			COUNT_ARTIFACTS_OF_TYPE("SELECT COUNT(*) FROM blackboard_artifacts WHERE artifact_type_id = ?"), //NON-NLS
			COUNT_ARTIFACTS_FROM_SOURCE("SELECT COUNT(*) FROM blackboard_artifacts WHERE obj_id = ?"), //NON-NLS
			SELECT_ARTIFACTS_BY_SOURCE_AND_TYPE("SELECT artifact_id FROM blackboard_artifacts WHERE obj_id = ? AND artifact_type_id = ?"), //NON-NLS
			COUNT_ARTIFACTS_BY_SOURCE_AND_TYPE("SELECT COUNT(*) FROM blackboard_artifacts WHERE obj_id = ? AND artifact_type_id = ?"), //NON-NLS
			SELECT_FILES_BY_PARENT("SELECT tsk_files.* " //NON-NLS
					+ "FROM tsk_objects INNER JOIN tsk_files " //NON-NLS
					+ "ON tsk_objects.obj_id=tsk_files.obj_id " //NON-NLS
					+ "WHERE (tsk_objects.par_obj_id = ? ) " //NON-NLS
					+ "ORDER BY tsk_files.dir_type, tsk_files.name COLLATE NOCASE"), //NON-NLS
			SELECT_FILES_BY_PARENT_AND_TYPE("SELECT tsk_files.* " //NON-NLS
					+ "FROM tsk_objects INNER JOIN tsk_files " //NON-NLS
					+ "ON tsk_objects.obj_id=tsk_files.obj_id " //NON-NLS
					+ "WHERE (tsk_objects.par_obj_id = ? AND tsk_files.type = ? ) " //NON-NLS
					+ "ORDER BY tsk_files.dir_type, tsk_files.name COLLATE NOCASE"), //NON-NLS
			SELECT_FILE_IDS_BY_PARENT("SELECT tsk_files.obj_id FROM tsk_objects INNER JOIN tsk_files " //NON-NLS
					+ "ON tsk_objects.obj_id=tsk_files.obj_id WHERE (tsk_objects.par_obj_id = ?)"), //NON-NLS
			SELECT_FILE_IDS_BY_PARENT_AND_TYPE("SELECT tsk_files.obj_id " //NON-NLS
					+ "FROM tsk_objects INNER JOIN tsk_files " //NON-NLS
					+ "ON tsk_objects.obj_id=tsk_files.obj_id " //NON-NLS
					+ "WHERE (tsk_objects.par_obj_id = ? " //NON-NLS
					+ "AND tsk_files.type = ? )"), //NON-NLS
			SELECT_FILE_BY_ID("SELECT * FROM tsk_files WHERE obj_id = ? LIMIT 1"), //NON-NLS
			INSERT_ARTIFACT("INSERT INTO blackboard_artifacts (artifact_id, obj_id, artifact_type_id) " //NON-NLS
					+ "VALUES (?, ?, ?)"), //NON-NLS
			INSERT_STRING_ATTRIBUTE("INSERT INTO blackboard_attributes (artifact_id, artifact_type_id, source, context, attribute_type_id, value_type, value_text) " //NON-NLS
					+ "VALUES (?,?,?,?,?,?,?)"), //NON-NLS
			INSERT_BYTE_ATTRIBUTE("INSERT INTO blackboard_attributes (artifact_id, artifact_type_id, source, context, attribute_type_id, value_type, value_byte) " //NON-NLS
					+ "VALUES (?,?,?,?,?,?,?)"), //NON-NLS
			INSERT_INT_ATTRIBUTE("INSERT INTO blackboard_attributes (artifact_id, artifact_type_id, source, context, attribute_type_id, value_type, value_int32) " //NON-NLS
					+ "VALUES (?,?,?,?,?,?,?)"), //NON-NLS
			INSERT_LONG_ATTRIBUTE("INSERT INTO blackboard_attributes (artifact_id, artifact_type_id, source, context, attribute_type_id, value_type, value_int64) " //NON-NLS
					+ "VALUES (?,?,?,?,?,?,?)"), //NON-NLS
			INSERT_DOUBLE_ATTRIBUTE("INSERT INTO blackboard_attributes (artifact_id, artifact_type_id, source, context, attribute_type_id, value_type, value_double) " //NON-NLS
					+ "VALUES (?,?,?,?,?,?,?)"), //NON-NLS
			SELECT_FILES_BY_FILE_SYSTEM_AND_NAME("SELECT * FROM tsk_files WHERE LOWER(name) LIKE ? and LOWER(name) NOT LIKE '%journal%' AND fs_obj_id = ?"), //NON-NLS
			SELECT_FILES_BY_FILE_SYSTEM_AND_PATH("SELECT * FROM tsk_files WHERE LOWER(name) LIKE ? AND LOWER(name) NOT LIKE '%journal%' AND LOWER(parent_path) LIKE ? AND fs_obj_id = ?"), //NON-NLS
			UPDATE_FILE_MD5("UPDATE tsk_files SET md5 = ? WHERE obj_id = ?"), //NON-NLS
			SELECT_LOCAL_PATH_FOR_FILE("SELECT path FROM tsk_files_path WHERE obj_id = ?"), //NON-NLS
			SELECT_PATH_FOR_FILE("SELECT parent_path FROM tsk_files WHERE obj_id = ?"), //NON-NLS
			SELECT_FILE_NAME("SELECT name FROM tsk_files WHERE obj_id = ?"), //NON-NLS
			SELECT_DERIVED_FILE("SELECT derived_id, rederive FROM tsk_files_derived WHERE obj_id = ?"), //NON-NLS
			SELECT_FILE_DERIVATION_METHOD("SELECT tool_name, tool_version, other FROM tsk_files_derived_method WHERE derived_id = ?"), //NON-NLS
			SELECT_MAX_OBJECT_ID("SELECT MAX(obj_id) from tsk_objects"), //NON-NLS
			INSERT_OBJECT("INSERT INTO tsk_objects (par_obj_id, type) VALUES (?, ?)"), //NON-NLS
			INSERT_FILE("INSERT INTO tsk_files (obj_id, fs_obj_id, name, type, has_path, dir_type, meta_type, dir_flags, meta_flags, size, ctime, crtime, atime, mtime, parent_path) " //NON-NLS
					+ "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"), //NON-NLS
			INSERT_LAYOUT_FILE("INSERT INTO tsk_file_layout (obj_id, byte_start, byte_len, sequence) " //NON-NLS
					+ "VALUES (?, ?, ?, ?)"), //NON-NLS
			INSERT_LOCAL_PATH("INSERT INTO tsk_files_path (obj_id, path) VALUES (?, ?)"), //NON-NLS
			COUNT_CHILD_OBJECTS_BY_PARENT("SELECT COUNT(obj_id) FROM tsk_objects WHERE par_obj_id = ?"), //NON-NLS
			SELECT_FILE_SYSTEM_BY_OBJECT("SELECT fs_obj_id from tsk_files WHERE obj_id=?"), //NON-NLS
			SELECT_TAG_NAMES("SELECT * FROM tag_names"), //NON-NLS
			SELECT_TAG_NAMES_IN_USE("SELECT * FROM tag_names " //NON-NLS
					+ "WHERE tag_name_id IN " //NON-NLS
					+ "(SELECT tag_name_id from content_tags UNION SELECT tag_name_id FROM blackboard_artifact_tags)"), //NON-NLS
			INSERT_TAG_NAME("INSERT INTO tag_names (display_name, description, color) VALUES (?, ?, ?)"), //NON-NLS
			INSERT_CONTENT_TAG("INSERT INTO content_tags (obj_id, tag_name_id, comment, begin_byte_offset, end_byte_offset) VALUES (?, ?, ?, ?, ?)"), //NON-NLS
			DELETE_CONTENT_TAG("DELETE FROM content_tags WHERE tag_id = ?"), //NON-NLS
			COUNT_CONTENT_TAGS_BY_TAG_NAME("SELECT COUNT(*) FROM content_tags WHERE tag_name_id = ?"), //NON-NLS
			SELECT_CONTENT_TAGS("SELECT * FROM content_tags INNER JOIN tag_names ON content_tags.tag_name_id = tag_names.tag_name_id"), //NON-NLS
			SELECT_CONTENT_TAGS_BY_TAG_NAME("SELECT * FROM content_tags WHERE tag_name_id = ?"), //NON-NLS
			SELECT_CONTENT_TAGS_BY_CONTENT("SELECT * FROM content_tags INNER JOIN tag_names ON content_tags.tag_name_id = tag_names.tag_name_id WHERE content_tags.obj_id = ?"), //NON-NLS
			INSERT_ARTIFACT_TAG("INSERT INTO blackboard_artifact_tags (artifact_id, tag_name_id, comment) VALUES (?, ?, ?)"), //NON-NLS
			DELETE_ARTIFACT_TAG("DELETE FROM blackboard_artifact_tags WHERE tag_id = ?"), //NON-NLS
			SELECT_ARTIFACT_TAGS("SELECT * FROM blackboard_artifact_tags INNER JOIN tag_names ON blackboard_artifact_tags.tag_name_id = tag_names.tag_name_id"), //NON-NLS
			COUNT_ARTIFACTS_BY_TAG_NAME("SELECT COUNT(*) FROM blackboard_artifact_tags WHERE tag_name_id = ?"), //NON-NLS
			SELECT_ARTIFACT_TAGS_BY_TAG_NAME("SELECT * FROM blackboard_artifact_tags WHERE tag_name_id = ?"), //NON-NLS
			SELECT_ARTIFACT_TAGS_BY_ARTIFACT("SELECT * FROM blackboard_artifact_tags INNER JOIN tag_names ON blackboard_artifact_tags.tag_name_id = tag_names.tag_name_id WHERE blackboard_artifact_tags.artifact_id = ?"), //NON-NLS
			SELECT_REPORTS("SELECT * FROM reports"), //NON-NLS
			INSERT_REPORT("INSERT INTO reports (path, crtime, src_module_name, report_name) VALUES (?, ?, ?, ?)");	 //NON-NLS

			private final String sql;

			private PREPARED_STATEMENT(String sql) {
				this.sql = sql;
			}

			String getSQL() {
				return sql;
			}
		}
		private final Map<PREPARED_STATEMENT, PreparedStatement> preparedStatements;
		private Connection connection;

		CaseDbConnection(String dbPath) {
			this.preparedStatements = new EnumMap<PREPARED_STATEMENT, PreparedStatement>(PREPARED_STATEMENT.class);
			Statement statement = null;
			try {
				SQLiteConfig config = new SQLiteConfig();
				
				// Reduce I/O operations, we have no OS crash recovery anyway.
				config.setSynchronous(SQLiteConfig.SynchronousMode.OFF);
				
				// The original comment for "read_uncommited" indicating that it
				// was being set to "allow query while in transaction". I don't fully
				// understand why this is needed since all it does it expose dirty writes
				// within one transaction to other queries. There was also the suggestion
				// that it may have helped to increase performance.
				config.setReadUncommited(true);
				
				// Enforce foreign key constraints.
				config.enforceForeignKeys(true);
				
				this.connection = DriverManager.getConnection("jdbc:sqlite:" + dbPath, config.toProperties()); //NON-NLS
			} catch (SQLException ex) {
				// The exception is caught and logged here because this 
				// constructor will be called by an override of 
				// ThreadLocal<T>.initialValue() which cannot throw. Calls to 
				// ConnectionPerThreadDispenser.getConnection() will detect
				// the error state via isOpen() and throw an appropriate 
				// exception.
				SleuthkitCase.logger.log(Level.SEVERE, "Error setting up case database connection for thread", ex); //NON-NLS
				if (this.connection != null) {
					try {
						this.connection.close();
					} catch (SQLException e) {
						SleuthkitCase.logger.log(Level.SEVERE, "Failed to close connection", e);
					}
					this.connection = null;
				}
			}
		}

		boolean isOpen() {
			return this.connection != null;
		}

		PreparedStatement getPreparedStatement(PREPARED_STATEMENT statementKey) throws SQLException {
			// Lazy statement preparation.
			PreparedStatement statement;
			if (this.preparedStatements.containsKey(statementKey)) {
				statement = this.preparedStatements.get(statementKey);
			} else {
				statement = prepareStatement(statementKey.getSQL());
				this.preparedStatements.put(statementKey, statement);
			}
			return statement;
		}

		private PreparedStatement prepareStatement(String sqlStatement) throws SQLException {
			PreparedStatement statement = null;
			boolean locked = true;
			while (locked) {
				try {
					statement = this.connection.prepareStatement(sqlStatement);
					locked = false;
				} catch (SQLException ex) {
					if (ex.getErrorCode() != SQLITE_BUSY_ERROR && ex.getErrorCode() != DATABASE_LOCKED_ERROR) {
						throw ex;
					}
				}
			}
			return statement;
		}

		Statement createStatement() throws SQLException {
			Statement statement = null;
			boolean locked = true;
			while (locked) {
				try {
					statement = this.connection.createStatement();
					locked = false;
				} catch (SQLException ex) {
					if (ex.getErrorCode() != SQLITE_BUSY_ERROR && ex.getErrorCode() != DATABASE_LOCKED_ERROR) {
						throw ex;
					}
				}
			}
			return statement;
		}

		void beginTransaction() throws SQLException {
			boolean locked = true;
			while (locked) {
				try {
					connection.setAutoCommit(false);
					locked = false;
				} catch (SQLException ex) {
					if (ex.getErrorCode() != SQLITE_BUSY_ERROR && ex.getErrorCode() != DATABASE_LOCKED_ERROR) {
						throw ex;
					}
				}
			}
		}

		void commitTransaction() throws SQLException {
			boolean locked = true;

			// Exceptions can be thrown on a call to commit so we will retry
			// until it succeeds.
			while (locked) {
				try {
					connection.commit();
					locked = false;
				} catch (SQLException ex) {
					logger.log(Level.SEVERE, String.format("Exception commiting transaction: Error code: %d SQLState: %s", ex.getErrorCode(), ex.getSQLState()), ex);
				}
			}

			// You must turn auto commit back on when done with the transaction.
			try {
				connection.setAutoCommit(true);
			}
			catch (SQLException ex) {
				logger.log(Level.SEVERE, String.format("Exception resetting auto commit: Error code: %d SQLState: %s", ex.getErrorCode(), ex.getSQLState()), ex);
			}
		}

		/**
		 * A rollback that logs exceptions and does not throw, intended for
		 * "internal" use in SleuthkitCase methods where the exception that
		 * motivated the rollback is the exception to report to the client.
		 */
		void rollbackTransaction() {
			try {
				connection.rollback();
			} catch (SQLException e) {
				logger.log(Level.SEVERE, "Error rolling back transaction", e);
			}
			try {
				connection.setAutoCommit(true);
			} catch (SQLException e) {
				logger.log(Level.SEVERE, "Error restoring auto-commit", e);
			}
		}

		/**
		 * A rollback that throws, intended for use by the CaseDbTransaction
		 * class where client code is managing the transaction and the client
		 * may wish to know that the rollback failed.
		 *
		 * @throws SQLException
		 */
		void rollbackTransactionWithThrow() throws SQLException {
			try {
				connection.rollback();
			} finally {
				connection.setAutoCommit(true);
			}
		}

		private ResultSet executeQuery(Statement statement, String query) throws SQLException {
			ResultSet resultSet = null;
			boolean locked = true;
			while (locked) {
				try {
					resultSet = statement.executeQuery(query);
					locked = false;
				} catch (SQLException ex) {
					if (ex.getErrorCode() != SQLITE_BUSY_ERROR && ex.getErrorCode() != DATABASE_LOCKED_ERROR) {
						throw ex;
					}
				}
			}
			return resultSet;
		}

		private ResultSet executeQuery(PreparedStatement statement) throws SQLException {
			ResultSet resultSet = null;
			boolean locked = true;
			while (locked) {
				try {
					resultSet = statement.executeQuery();
					locked = false;
				} catch (SQLException ex) {
					if (ex.getErrorCode() != SQLITE_BUSY_ERROR && ex.getErrorCode() != DATABASE_LOCKED_ERROR) {
						throw ex;
					}
				}
			}
			return resultSet;
		}

		void executeUpdate(Statement statement, String update) throws SQLException {
			boolean locked = true;
			while (locked) {
				try {
					statement.executeUpdate(update);
					locked = false;
				} catch (SQLException ex) {
					if (ex.getErrorCode() != SQLITE_BUSY_ERROR && ex.getErrorCode() != DATABASE_LOCKED_ERROR) {
						throw ex;
					}
				}
			}
		}

		void executeUpdate(PreparedStatement statement) throws SQLException {
			boolean locked = true;
			while (locked) {
				try {
					statement.executeUpdate();
					locked = false;
				} catch (SQLException ex) {
					if (ex.getErrorCode() != SQLITE_BUSY_ERROR && ex.getErrorCode() != DATABASE_LOCKED_ERROR) {
						throw ex;
					}
				}
			}
		}

		/**
		 * ****************
		 * Close the connection to the database, thereby releasing the file
		 * handle
		 */
		private void close() {
			try { // close all file handles to the autopsy.db database.
				connection.close();
			} catch (SQLException ex) {
				logger.log(Level.SEVERE, "Unable to close handle to autopsy.db", ex);
			}
		}
	}

	/**
	 * Wraps the transactional capabilities of a CaseDbConnection object to
	 * support use cases where control of a transaction is given to a
	 * SleuthkitCase client. Note that this class does not implement the
	 * Transaction interface because that sort of flexibility and its associated
	 * complexity is not needed. Also, TskCoreExceptions are thrown to be
	 * consistent with the outer SleuthkitCase class.
	 */
	public static final class CaseDbTransaction {

		private final CaseDbConnection connection;

		private CaseDbTransaction(CaseDbConnection connection) throws TskCoreException {
			this.connection = connection;
			try {
				this.connection.beginTransaction();
			} catch (SQLException ex) {
				throw new TskCoreException("Failed to create transaction on case database", ex);
			}
		}

		/**
		 * The implementations of the public APIs that take a CaseDbTransaction
		 * object need access to the underlying CaseDbConnection.
		 *
		 * @return The CaseDbConnection instance for this instance of
		 * CaseDbTransaction.
		 */
		private CaseDbConnection getConnection() {
			return this.connection;
		}

		/**
		 * Commits the transaction on the case database that was begun when this
		 * object was constructed.
		 *
		 * @throws TskCoreException
		 */
		public void commit() throws TskCoreException {
			try {
				this.connection.commitTransaction();
			} catch (SQLException ex) {
				throw new TskCoreException("Failed to commit transaction on case database", ex);
			}
		}

		/**
		 * Rolls back the transaction on the case database that was begun when
		 * this object was constructed.
		 *
		 * @throws TskCoreException
		 */
		public void rollback() throws TskCoreException {
			try {
				this.connection.rollbackTransactionWithThrow();
			} catch (SQLException ex) {
				throw new TskCoreException("Case database transaction rollback failed", ex);
			}
		}
	}
	
	/**
	 * The CaseDbQuery supports the use case where developers have a 
	 * need for data that is not exposed through the SleuthkitCase API.
	 * A CaseDbQuery instance gets created through the SleuthkitCase
	 * executeDbQuery() method. It wraps the ResultSet and takes care
	 * of acquiring and releasing the appropriate database lock.
	 * It implements AutoCloseable so that it can be used in a try-with
	 * -resources block freeing developers from having to remember to
	 * close the result set and releasing the lock.
	 * 
	 */
	public final class CaseDbQuery implements AutoCloseable {
		private ResultSet resultSet;
		
		private CaseDbQuery(String query) throws TskCoreException {
			if (!query.regionMatches(true, 0, "SELECT", 0, "SELECT".length())) {
				throw new TskCoreException("Unsupported query: Only SELECT queries are supported.");
			}
			
			CaseDbConnection connection;
			
			try {
				connection = connections.getConnection();
			} catch (TskCoreException ex) {
				throw new TskCoreException("Error getting connection for query: ", ex);
			}

			try {
				SleuthkitCase.this.acquireSharedLock();		
				resultSet = connection.executeQuery(connection.createStatement(), query);
			}
			catch (SQLException ex)
			{
				SleuthkitCase.this.releaseSharedLock();
				throw new TskCoreException("Error executing query: ", ex);				
			}
		}
		
		/**
		 * Get the result set for this query.
		 * @return The result set.
		 */
		public ResultSet getResultSet() {
			return resultSet;
		}
		
		@Override
		public void close() throws TskCoreException {
			try {
				if (resultSet != null) {
					final Statement statement = resultSet.getStatement();
					if (statement != null) {
						statement.close();
					}
					resultSet.close();
				}

				SleuthkitCase.this.releaseSharedLock();				
			}
			catch (SQLException ex) {
				throw new TskCoreException("Error closing query: ", ex);
			}
		}	
	}
}
