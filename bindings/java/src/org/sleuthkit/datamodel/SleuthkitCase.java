/*
 * Sleuth Kit Data Model
 *
 * Copyright 2012 Basis Technology Corp.
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
import java.util.*;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.logging.Level;
import org.sleuthkit.datamodel.TskData.ObjectType;
import java.util.logging.Logger;
import org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE;
import org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE;
import org.sleuthkit.datamodel.SleuthkitJNI.CaseDbHandle.AddImageProcess;
import org.sleuthkit.datamodel.TskData.FileKnown;
import org.sleuthkit.datamodel.TskData.TSK_DB_FILES_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_META_FLAG_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_META_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_FLAG_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_TYPE_ENUM;
import org.sqlite.SQLiteJDBCLoader;

/**
 * Represents the case database and abstracts out the most commonly used
 * database operations.
 *
 * Also provides case database-level lock that protect access to the database
 * resource. The lock is available outside of the class to synchronize certain
 * actions (such as addition of an image) with concurrent database writes, for
 * database implementations (such as SQLite) that might need it.
 */
public class SleuthkitCase {

	private String dbPath;
	private String dbDirPath;
	private volatile SleuthkitJNI.CaseDbHandle caseHandle;
	private volatile Connection con;
	private ResultSetHelper rsHelper = new ResultSetHelper(this);
	private int artifactIDcounter = 1001;
	private int attributeIDcounter = 1001;
	//database lock
	private static final ReentrantReadWriteLock rwLock = new ReentrantReadWriteLock(true); //use fairness policy
	private static final Lock caseDbLock = rwLock.writeLock(); //using exclusing lock for all db ops for now
	//private static final Lock caseDbWriteLock = rwLock.writeLock();
	//private static final Lock caseDbReadLock = rwLock.readLock();
	//prepared statements
	private PreparedStatement getBlackboardAttributesSt;
	private PreparedStatement getBlackboardArtifactSt;
	private PreparedStatement getBlackboardArtifactsSt;
	private PreparedStatement getBlackboardArtifactsTypeCountSt;
	private PreparedStatement getBlackboardArtifactsContentCountSt;
	private PreparedStatement getArtifactsHelper1St;
	private PreparedStatement getArtifactsHelper2St;
	private PreparedStatement getArtifactsCountHelperSt;
	private PreparedStatement getAbstractFileChildren;
	private PreparedStatement getAbstractFileChildrenIds;
	private PreparedStatement getAbstractFileById;
	private PreparedStatement addArtifactSt1;
	private PreparedStatement addArtifactSt2;
	private PreparedStatement getLastArtifactId;
	private PreparedStatement addBlackboardAttributeStringSt;
	private PreparedStatement addBlackboardAttributeByteSt;
	private PreparedStatement addBlackboardAttributeIntegerSt;
	private PreparedStatement addBlackboardAttributeLongSt;
	private PreparedStatement addBlackboardAttributeDoubleSt;
	private PreparedStatement getFileSt;
	private PreparedStatement getFileWithParentSt;
	private PreparedStatement updateMd5St;
	private PreparedStatement getPathSt;
	private PreparedStatement getDerivedInfoSt;
	private PreparedStatement getDerivedMethodSt;
	private PreparedStatement addObjectSt;
	private PreparedStatement addLocalFileSt;
	private PreparedStatement addPathSt;
	private PreparedStatement hasChildrenSt;
	private PreparedStatement getLastContentIdSt;
	private static final Logger logger = Logger.getLogger(SleuthkitCase.class.getName());

	/**
	 * constructor (private) - client uses openCase() and newCase() instead
	 *
	 * @param dbPath path to the database file
	 * @param caseHandle handle to the case database API
	 * @throws SQLException thrown if SQL error occurred
	 * @throws ClassNotFoundException thrown if database driver could not be
	 * loaded
	 * @throws TskCoreException thrown if critical error occurred within TSK
	 * case
	 */
	private SleuthkitCase(String dbPath, SleuthkitJNI.CaseDbHandle caseHandle) throws SQLException, ClassNotFoundException, TskCoreException {
		Class.forName("org.sqlite.JDBC");
		this.dbPath = dbPath;
		this.dbDirPath = new java.io.File(dbPath).getParentFile().getAbsolutePath();
		this.caseHandle = caseHandle;
		con = DriverManager.getConnection("jdbc:sqlite:" + dbPath);
		configureDB();
		initBlackboardTypes();
		initStatements();
	}

	/**
	 * Get location of the database directory
	 *
	 * @return absolute database directory path
	 */
	public String getDbDirPath() {
		return dbDirPath;
	}

	private void initStatements() throws SQLException {
		getBlackboardAttributesSt = con.prepareStatement(
				"SELECT artifact_id, source, context, attribute_type_id, value_type, "
				+ "value_byte, value_text, value_int32, value_int64, value_double "
				+ "FROM blackboard_attributes WHERE artifact_id = ?");

		getBlackboardArtifactSt = con.prepareStatement(
				"SELECT obj_id, artifact_type_id FROM blackboard_artifacts WHERE artifact_id = ?");

		getBlackboardArtifactsSt = con.prepareStatement(
				"SELECT artifact_id, obj_id FROM blackboard_artifacts "
				+ "WHERE artifact_type_id = ?");

		getBlackboardArtifactsTypeCountSt = con.prepareStatement(
				"SELECT COUNT(*) FROM blackboard_artifacts WHERE artifact_type_id = ?");

		getBlackboardArtifactsContentCountSt = con.prepareStatement(
				"SELECT COUNT(*) FROM blackboard_artifacts WHERE obj_id = ?");

		getArtifactsHelper1St = con.prepareStatement(
				"SELECT artifact_id FROM blackboard_artifacts WHERE obj_id = ? AND artifact_type_id = ?");

		getArtifactsHelper2St = con.prepareStatement(
				"SELECT artifact_id, obj_id FROM blackboard_artifacts WHERE artifact_type_id = ?");

		getArtifactsCountHelperSt = con.prepareStatement(
				"SELECT COUNT(*) FROM blackboard_artifacts WHERE obj_id = ? AND artifact_type_id = ?");

		getAbstractFileChildren = con.prepareStatement(
				"SELECT tsk_files.* "
				+ "FROM tsk_objects JOIN tsk_files "
				+ "ON tsk_objects.obj_id=tsk_files.obj_id "
				+ "WHERE (tsk_objects.par_obj_id = ? "
				+ "AND tsk_files.type = ? )");

		getAbstractFileChildrenIds = con.prepareStatement(
				"SELECT tsk_files.obj_id "
				+ "FROM tsk_objects JOIN tsk_files "
				+ "ON tsk_objects.obj_id=tsk_files.obj_id "
				+ "WHERE (tsk_objects.par_obj_id = ? "
				+ "AND tsk_files.type = ? )");

		getAbstractFileById = con.prepareStatement("SELECT * FROM tsk_files WHERE obj_id = ? LIMIT 1");

		addArtifactSt1 = con.prepareStatement(
				"INSERT INTO blackboard_artifacts (artifact_id, obj_id, artifact_type_id) "
				+ "VALUES (NULL, ?, ?)");


		getLastArtifactId = con.prepareStatement(
				"SELECT MAX(artifact_id) from blackboard_artifacts "
				+ "WHERE obj_id = ? AND + artifact_type_id = ?");


		addBlackboardAttributeStringSt = con.prepareStatement(
				"INSERT INTO blackboard_attributes (artifact_id, source, context, attribute_type_id, value_type, value_text) "
				+ "VALUES (?,?,?,?,?,?)");

		addBlackboardAttributeByteSt = con.prepareStatement(
				"INSERT INTO blackboard_attributes (artifact_id, source, context, attribute_type_id, value_type, value_byte) "
				+ "VALUES (?,?,?,?,?,?)");

		addBlackboardAttributeIntegerSt = con.prepareStatement(
				"INSERT INTO blackboard_attributes (artifact_id, source, context, attribute_type_id, value_type, value_int32) "
				+ "VALUES (?,?,?,?,?,?)");

		addBlackboardAttributeLongSt = con.prepareStatement(
				"INSERT INTO blackboard_attributes (artifact_id, source, context, attribute_type_id, value_type, value_int64) "
				+ "VALUES (?,?,?,?,?,?)");

		addBlackboardAttributeDoubleSt = con.prepareStatement(
				"INSERT INTO blackboard_attributes (artifact_id, source, context, attribute_type_id, value_type, value_double) "
				+ "VALUES (?,?,?,?,?,?)");

		getFileSt = con.prepareStatement("SELECT * FROM tsk_files WHERE LOWER(name) LIKE ? and LOWER(name) NOT LIKE '%journal%' AND fs_obj_id = ?");

		getFileWithParentSt = con.prepareStatement("SELECT * FROM tsk_files WHERE LOWER(name) LIKE ? AND LOWER(name) NOT LIKE '%journal%' AND LOWER(parent_path) LIKE ? AND fs_obj_id = ?");

		updateMd5St = con.prepareStatement("UPDATE tsk_files SET md5 = ? WHERE obj_id = ?");

		getPathSt = con.prepareStatement("SELECT path FROM tsk_files_path WHERE obj_id = ?");

		getDerivedInfoSt = con.prepareStatement("SELECT derived_id, rederive FROM tsk_files_derived WHERE obj_id = ?");

		getDerivedMethodSt = con.prepareStatement("SELECT tool_name, tool_version, other FROM tsk_files_derived_method WHERE derived_id = ?");

		getLastContentIdSt = con.prepareStatement(
				"SELECT MAX(obj_id) from tsk_objects");

		addObjectSt = con.prepareStatement(
				"INSERT INTO tsk_objects (obj_id, par_obj_id, type) VALUES (?, ?, ?)");

		addLocalFileSt = con.prepareStatement(
				"INSERT INTO tsk_files (obj_id, name, type, has_path, dir_type, meta_type, dir_flags, meta_flags, size, ctime, crtime, atime, mtime, parent_path) "
				+ "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

		addPathSt = con.prepareStatement(
				"INSERT INTO tsk_files_path (obj_id, path) VALUES (?, ?)");

		hasChildrenSt = con.prepareStatement(
				"SELECT COUNT(obj_id) FROM tsk_objects WHERE par_obj_id = ?");

	}

	private void closeStatements() {
		try {
			if (getBlackboardAttributesSt != null) {
				getBlackboardAttributesSt.close();
				getBlackboardAttributesSt = null;
			}
			if (getBlackboardArtifactSt != null) {
				getBlackboardArtifactSt.close();
				getBlackboardArtifactSt = null;
			}
			if (getBlackboardArtifactsSt != null) {
				getBlackboardArtifactsSt.close();
				getBlackboardArtifactsSt = null;
			}
			if (getBlackboardArtifactsTypeCountSt != null) {
				getBlackboardArtifactsTypeCountSt.close();
				getBlackboardArtifactsTypeCountSt = null;
			}
			if (getBlackboardArtifactsContentCountSt != null) {
				getBlackboardArtifactsContentCountSt.close();
				getBlackboardArtifactsContentCountSt = null;
			}
			if (getArtifactsHelper1St != null) {
				getArtifactsHelper1St.close();
				getArtifactsHelper1St = null;
			}
			if (getArtifactsHelper2St != null) {
				getArtifactsHelper2St.close();
				getArtifactsHelper2St = null;
			}
			if (getArtifactsCountHelperSt != null) {
				getArtifactsCountHelperSt.close();
				getArtifactsCountHelperSt = null;
			}

			if (getAbstractFileChildren != null) {
				getAbstractFileChildren.close();
				getAbstractFileChildren = null;
			}
			if (getAbstractFileChildrenIds != null) {
				getAbstractFileChildrenIds.close();
				getAbstractFileChildrenIds = null;
			}
			if (getAbstractFileById != null) {
				getAbstractFileById.close();
				getAbstractFileById = null;
			}
			if (addArtifactSt1 != null) {
				addArtifactSt1.close();
				addArtifactSt1 = null;
			}
			if (addArtifactSt2 != null) {
				addArtifactSt2.close();
				addArtifactSt2 = null;
			}
			if (getLastArtifactId != null) {
				getLastArtifactId.close();
				getLastArtifactId = null;
			}

			if (addBlackboardAttributeStringSt != null) {
				addBlackboardAttributeStringSt.close();
				addBlackboardAttributeStringSt = null;
			}

			if (addBlackboardAttributeByteSt != null) {
				addBlackboardAttributeByteSt.close();
				addBlackboardAttributeByteSt = null;
			}

			if (addBlackboardAttributeIntegerSt != null) {
				addBlackboardAttributeIntegerSt.close();
				addBlackboardAttributeIntegerSt = null;
			}

			if (addBlackboardAttributeLongSt != null) {
				addBlackboardAttributeLongSt.close();
				addBlackboardAttributeLongSt = null;
			}

			if (addBlackboardAttributeDoubleSt != null) {
				addBlackboardAttributeDoubleSt.close();
				addBlackboardAttributeDoubleSt = null;
			}

			if (getFileSt != null) {
				getFileSt.close();
				getFileSt = null;
			}

			if (getFileWithParentSt != null) {
				getFileWithParentSt.close();
				getFileWithParentSt = null;
			}

			if (updateMd5St != null) {
				updateMd5St.close();
				updateMd5St = null;
			}
			
			if (getLastContentIdSt != null) {
				getLastContentIdSt.close();
				getLastContentIdSt = null;
			}

			if (getPathSt != null) {
				getPathSt.close();
				getPathSt = null;
			}

			if (getDerivedInfoSt != null) {
				getDerivedInfoSt.close();
				getDerivedInfoSt = null;
			}

			if (getDerivedMethodSt != null) {
				getDerivedMethodSt.close();
				getDerivedMethodSt = null;
			}


			if (addObjectSt != null) {
				addObjectSt.close();
				addObjectSt = null;
			}

			if (addLocalFileSt != null) {
				addLocalFileSt.close();
				addLocalFileSt = null;
			}

			if (addPathSt != null) {
				addPathSt.close();
				addPathSt = null;
			}

			if (hasChildrenSt != null) {
				hasChildrenSt.close();
				hasChildrenSt = null;
			}
			

		} catch (SQLException e) {
			logger.log(Level.WARNING,
					"Error closing prepared statements", e);
		}
	}

	private void configureDB() throws TskCoreException {
		try {
			//this should match SleuthkitJNI db setup
			final Statement statement = con.createStatement();
			//reduce i/o operations, we have no OS crash recovery anyway
			statement.execute("PRAGMA synchronous = OFF;");
			//allow to query while in transaction - no need read locks
			statement.execute("PRAGMA read_uncommitted = True;");
			statement.close();

			logger.log(Level.INFO, String.format("sqlite-jdbc version %s loaded in %s mode",
					SQLiteJDBCLoader.getVersion(), SQLiteJDBCLoader.isNativeMode()
					? "native" : "pure-java"));

		} catch (SQLException e) {
			throw new TskCoreException("Couldn't configure the database connection", e);
		}
	}

	/**
	 * Lock to protect against concurrent write accesses to case database and to
	 * block readers while database is in write transaction. Should be utilized
	 * by all db code where underlying storage supports max. 1 concurrent writer
	 * MUST always call dbWriteUnLock() as early as possible, in the same thread
	 * where dbWriteLock() was called
	 */
	public static void dbWriteLock() {
		//Logger.getLogger("LOCK").log(Level.INFO, "Locking " + rwLock.toString());
		caseDbLock.lock();
	}

	/**
	 * Release previously acquired write lock acquired in this thread using
	 * dbWriteLock(). Call in "finally" block to ensure the lock is always
	 * released.
	 */
	public static void dbWriteUnlock() {
		//Logger.getLogger("LOCK").log(Level.INFO, "UNLocking " + rwLock.toString());
		caseDbLock.unlock();
	}

	/**
	 * Lock to protect against read while it is in a write transaction state.
	 * Supports multiple concurrent readers if there is no writer. MUST always
	 * call dbReadUnLock() as early as possible, in the same thread where
	 * dbReadLock() was called.
	 */
	static void dbReadLock() {
		caseDbLock.lock();
	}

	/**
	 * Release previously acquired read lock acquired in this thread using
	 * dbReadLock(). Call in "finally" block to ensure the lock is always
	 * released.
	 */
	static void dbReadUnlock() {
		caseDbLock.unlock();
	}

	/**
	 * Open an existing case
	 *
	 * @param dbPath Path to SQLite database.
	 * @return Case object
	 */
	public static SleuthkitCase openCase(String dbPath) throws TskCoreException {
		SleuthkitCase.dbWriteLock();
		SleuthkitJNI.CaseDbHandle caseHandle = SleuthkitJNI.openCaseDb(dbPath);
		try {
			return new SleuthkitCase(dbPath, caseHandle);
		} catch (SQLException ex) {
			throw new TskCoreException("Couldn't open case at " + dbPath, ex);
		} catch (ClassNotFoundException ex) {
			throw new TskCoreException("Couldn't open case at " + dbPath, ex);
		} finally {
			SleuthkitCase.dbWriteUnlock();
		}
	}

	/**
	 * Create a new case
	 *
	 * @param dbPath Path to where SQlite database should be created.
	 * @return Case object
	 */
	public static SleuthkitCase newCase(String dbPath) throws TskCoreException {
		SleuthkitCase.dbWriteLock();
		SleuthkitJNI.CaseDbHandle caseHandle = SleuthkitJNI.newCaseDb(dbPath);
		try {
			return new SleuthkitCase(dbPath, caseHandle);
		} catch (SQLException ex) {
			throw new TskCoreException("Couldn't open case at " + dbPath, ex);
		} catch (ClassNotFoundException ex) {
			throw new TskCoreException("Couldn't open case at " + dbPath, ex);
		} finally {
			SleuthkitCase.dbWriteUnlock();
		}

	}

	private void initBlackboardTypes() throws SQLException, TskCoreException {
		dbReadLock();
		try {
			Statement s = con.createStatement();
			for (ARTIFACT_TYPE type : ARTIFACT_TYPE.values()) {
				ResultSet rs = s.executeQuery("SELECT * from blackboard_artifact_types WHERE artifact_type_id = '" + type.getTypeID() + "'");
				if (!rs.next()) {
					this.addBuiltInArtifactType(type);
				}
				rs.close();
			}
			for (ATTRIBUTE_TYPE type : ATTRIBUTE_TYPE.values()) {
				ResultSet rs = s.executeQuery("SELECT * from blackboard_attribute_types WHERE attribute_type_id = '" + type.getTypeID() + "'");
				if (!rs.next()) {
					this.addBuiltInAttrType(type);
				}
				rs.close();
			}
			s.close();
		} finally {
			dbReadUnlock();
		}
	}

	/**
	 * Start process of adding an image to the case. Adding an image is a
	 * multi-step process and this returns an object that allows it to happen.
	 *
	 * @param timezone TZ timezone string to use for ingest of image.
	 * @param processUnallocSpace set to true if to process unallocated space on
	 * the image
	 * @param noFatFsOrphans true if to skip processing orphans on FAT
	 * filesystems
	 * @return object to start ingest
	 */
	public AddImageProcess makeAddImageProcess(String timezone, boolean processUnallocSpace, boolean noFatFsOrphans) {
		return this.caseHandle.initAddImageProcess(timezone, processUnallocSpace, noFatFsOrphans);
	}

	/**
	 * Set the NSRL database
	 *
	 * @param path The path to the database
	 * @return a handle for that database
	 */
	public int setNSRLDatabase(String path) throws TskCoreException {
		return this.caseHandle.setNSRLDatabase(path);
	}

	/**
	 * Add the known bad database
	 *
	 * @param path The path to the database
	 * @return a handle for that database
	 */
	public int addKnownBadDatabase(String path) throws TskCoreException {
		return this.caseHandle.addKnownBadDatabase(path);
	}

	/**
	 * Reset currently used lookup databases on that case object
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within tsk core
	 */
	public void clearLookupDatabases() throws TskCoreException {
		this.caseHandle.clearLookupDatabases();
	}

	/**
	 * Get the list of root objects, meaning image files or local files.
	 *
	 * @return list of content objects.
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within tsk core
	 */
	public List<Content> getRootObjects() throws TskCoreException {
		Collection<ObjectInfo> infos = new ArrayList<ObjectInfo>();
		dbReadLock();
		try {

			Statement s = con.createStatement();
			ResultSet rs = s.executeQuery("select obj_id, type from tsk_objects "
					+ "where par_obj_id is NULL");

			while (rs.next()) {
				infos.add(new ObjectInfo(rs.getLong("obj_id"), ObjectType.valueOf(rs.getShort("type"))));
			}
			rs.close();
			s.close();


			List<Content> rootObjs = new ArrayList<Content>();

			for (ObjectInfo i : infos) {
				if (i.type == ObjectType.IMG) {
					rootObjs.add(getImageById(i.id));
				} else {
					throw new TskCoreException("Parentless object has wrong type to be a root: " + i.type);
				}
			}

			return rootObjs;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting root objects.", ex);
		} finally {
			dbReadUnlock();
		}
	}

	/**
	 * Get all blackboard artifacts of a given type
	 *
	 * @param artifactTypeID artifact type id (must exist in database)
	 * @return list of blackboard artifacts
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within tsk core
	 */
	public ArrayList<BlackboardArtifact> getBlackboardArtifacts(int artifactTypeID) throws TskCoreException {
		String artifactTypeName = this.getArtifactTypeString(artifactTypeID);
		dbReadLock();
		try {
			ArrayList<BlackboardArtifact> artifacts = new ArrayList<BlackboardArtifact>();

			getBlackboardArtifactsSt.setInt(1, artifactTypeID);

			final ResultSet rs = getBlackboardArtifactsSt.executeQuery();

			while (rs.next()) {
				artifacts.add(new BlackboardArtifact(this, rs.getLong(1), rs.getLong(2),
						artifactTypeID, artifactTypeName, ARTIFACT_TYPE.fromID(artifactTypeID).getDisplayName()));
			}
			rs.close();
			return artifacts;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting or creating a blackboard artifact. " + ex.getMessage(), ex);
		} finally {
			dbReadUnlock();
		}

	}

	/**
	 * Get count of blackboard artifacts for a given content
	 *
	 * @param objId associated object
	 * @return count of artifacts
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within tsk core
	 */
	public long getBlackboardArtifactsCount(long objId) throws TskCoreException {
		ResultSet rs = null;
		dbReadLock();
		try {
			long count = 0;
			getBlackboardArtifactsContentCountSt.setLong(1, objId);
			rs = getBlackboardArtifactsContentCountSt.executeQuery();

			if (rs.next()) {
				count = rs.getLong(1);
			} else {
				throw new TskCoreException("Error getting count of artifacts by content. ");
			}

			return count;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting number of blackboard artifacts by content. " + ex.getMessage(), ex);
		} finally {
			if (rs != null) {
				try {
					rs.close();
				} catch (SQLException ex) {
					logger.log(Level.WARNING, "Could not close the result set, ", ex);
				}
			}

			dbReadUnlock();
		}

	}

	/**
	 * Get count of blackboard artifacts of a given type
	 *
	 * @param artifactTypeID artifact type id (must exist in database)
	 * @return count of artifacts
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within tsk core
	 */
	public long getBlackboardArtifactsTypeCount(int artifactTypeID) throws TskCoreException {
		ResultSet rs = null;
		dbReadLock();
		try {
			long count = 0;
			getBlackboardArtifactsTypeCountSt.setInt(1, artifactTypeID);
			rs = getBlackboardArtifactsTypeCountSt.executeQuery();

			if (rs.next()) {
				count = rs.getLong(1);
			} else {
				throw new TskCoreException("Error getting count of artifacts by type. ");
			}

			return count;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting number of blackboard artifacts by type. " + ex.getMessage(), ex);
		} finally {
			if (rs != null) {
				try {
					rs.close();
				} catch (SQLException ex) {
					logger.log(Level.WARNING, "Coud not close the result set, ", ex);
				}
			}

			dbReadUnlock();
		}

	}

	/**
	 * Helper to iterate over blackboard artifacts result set containing all
	 * columns and return a list of artifacts in the set. Must be enclosed in
	 * dbReadLock. Result set and statement must be freed by the caller.
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
		dbReadLock();
		try {
			Statement s = con.createStatement();
			ResultSet rs = s.executeQuery("SELECT DISTINCT blackboard_artifacts.artifact_id, "
					+ "blackboard_artifacts.obj_id, blackboard_artifacts.artifact_type_id "
					+ "FROM blackboard_artifacts, blackboard_attributes "
					+ "WHERE blackboard_artifacts.artifact_id = blackboard_attributes.artifact_id "
					+ "AND blackboard_attributes.attribute_type_id IS " + attrType.getTypeID()
					+ " AND blackboard_attributes.value_text IS '" + value + "'");

			List<BlackboardArtifact> artifacts = getArtifactsHelper(rs);

			rs.close();
			s.close();
			return artifacts;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting blackboard artifacts by attribute. " + ex.getMessage(), ex);
		} finally {
			dbReadUnlock();
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

		subString = "%" + subString;
		if (startsWith == false) {
			subString = subString + "%";
		}

		dbReadLock();
		try {
			Statement s = con.createStatement();
			ResultSet rs = s.executeQuery("SELECT DISTINCT blackboard_artifacts.artifact_id, "
					+ "blackboard_artifacts.obj_id, blackboard_artifacts.artifact_type_id "
					+ "FROM blackboard_artifacts, blackboard_attributes "
					+ "WHERE blackboard_artifacts.artifact_id = blackboard_attributes.artifact_id "
					+ "AND blackboard_attributes.attribute_type_id IS " + attrType.getTypeID()
					+ " AND blackboard_attributes.value_text LIKE '" + subString + "'");

			List<BlackboardArtifact> artifacts = getArtifactsHelper(rs);

			rs.close();
			s.close();
			return artifacts;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting blackboard artifacts by attribute. " + ex.getMessage(), ex);
		} finally {
			dbReadUnlock();
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
		dbReadLock();
		try {
			Statement s = con.createStatement();
			ResultSet rs = s.executeQuery("SELECT DISTINCT blackboard_artifacts.artifact_id, "
					+ "blackboard_artifacts.obj_id, blackboard_artifacts.artifact_type_id "
					+ "FROM blackboard_artifacts, blackboard_attributes "
					+ "WHERE blackboard_artifacts.artifact_id = blackboard_attributes.artifact_id "
					+ "AND blackboard_attributes.attribute_type_id IS " + attrType.getTypeID()
					+ " AND blackboard_attributes.value_int32 IS " + value);

			List<BlackboardArtifact> artifacts = getArtifactsHelper(rs);

			rs.close();
			s.close();
			return artifacts;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting blackboard artifacts by attribute. " + ex.getMessage(), ex);
		} finally {
			dbReadUnlock();
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
		dbReadLock();
		try {
			Statement s = con.createStatement();
			ResultSet rs = s.executeQuery("SELECT DISTINCT blackboard_artifacts.artifact_id, "
					+ "blackboard_artifacts.obj_id, blackboard_artifacts.artifact_type_id "
					+ "FROM blackboard_artifacts, blackboard_attributes "
					+ "WHERE blackboard_artifacts.artifact_id = blackboard_attributes.artifact_id "
					+ "AND blackboard_attributes.attribute_type_id IS " + attrType.getTypeID()
					+ " AND blackboard_attributes.value_int64 IS " + value);

			List<BlackboardArtifact> artifacts = getArtifactsHelper(rs);

			rs.close();
			s.close();
			return artifacts;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting blackboard artifacts by attribute. " + ex.getMessage(), ex);
		} finally {
			dbReadUnlock();
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
		dbReadLock();
		try {
			Statement s = con.createStatement();
			ResultSet rs = s.executeQuery("SELECT DISTINCT blackboard_artifacts.artifact_id, "
					+ "blackboard_artifacts.obj_id, blackboard_artifacts.artifact_type_id "
					+ "FROM blackboard_artifacts, blackboard_attributes "
					+ "WHERE blackboard_artifacts.artifact_id = blackboard_attributes.artifact_id "
					+ "AND blackboard_attributes.attribute_type_id IS " + attrType.getTypeID()
					+ " AND blackboard_attributes.value_double IS " + value);

			List<BlackboardArtifact> artifacts = getArtifactsHelper(rs);

			rs.close();
			s.close();
			return artifacts;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting blackboard artifacts by attribute. " + ex.getMessage(), ex);
		} finally {
			dbReadUnlock();
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
		dbReadLock();
		try {
			Statement s = con.createStatement();
			ResultSet rs = s.executeQuery("SELECT DISTINCT blackboard_artifacts.artifact_id, "
					+ "blackboard_artifacts.obj_id, blackboard_artifacts.artifact_type_id "
					+ "FROM blackboard_artifacts, blackboard_attributes "
					+ "WHERE blackboard_artifacts.artifact_id = blackboard_attributes.artifact_id "
					+ "AND blackboard_attributes.attribute_type_id IS " + attrType.getTypeID()
					+ " AND blackboard_attributes.value_byte IS " + value);

			List<BlackboardArtifact> artifacts = getArtifactsHelper(rs);

			rs.close();
			s.close();
			return artifacts;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting blackboard artifacts by attribute. " + ex.getMessage(), ex);
		} finally {
			dbReadUnlock();
		}
	}

	/**
	 * Get all blackboard artifact types
	 *
	 * @return list of blackboard artifact types
	 * @throws TskCoreException exception thrown if a critical error occurred
	 * within tsk core
	 */
	public ArrayList<BlackboardArtifact.ARTIFACT_TYPE> getBlackboardArtifactTypes() throws TskCoreException {
		dbReadLock();
		try {
			ArrayList<BlackboardArtifact.ARTIFACT_TYPE> artifact_types = new ArrayList<BlackboardArtifact.ARTIFACT_TYPE>();
			Statement s = con.createStatement();
			ResultSet rs = s.executeQuery("SELECT artifact_type_id FROM blackboard_artifact_types");

			while (rs.next()) {
				artifact_types.add(BlackboardArtifact.ARTIFACT_TYPE.fromID(rs.getInt(1)));
			}
			rs.close();
			s.close();
			return artifact_types;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting artifact types. " + ex.getMessage(), ex);
		} finally {
			dbReadUnlock();
		}

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
		dbReadLock();
		try {
			ArrayList<BlackboardAttribute.ATTRIBUTE_TYPE> attribute_types = new ArrayList<BlackboardAttribute.ATTRIBUTE_TYPE>();
			Statement s = con.createStatement();
			ResultSet rs = s.executeQuery("SELECT type_name FROM blackboard_attribute_types");

			while (rs.next()) {
				attribute_types.add(BlackboardAttribute.ATTRIBUTE_TYPE.fromLabel(rs.getString(1)));
			}
			rs.close();
			s.close();
			return attribute_types;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting attribute types. " + ex.getMessage(), ex);
		} finally {
			dbReadUnlock();
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
	 * within tsk core
	 */
	public int getBlackboardAttributeTypesCount() throws TskCoreException {
		ResultSet rs = null;
		Statement s = null;
		dbReadLock();
		try {
			int count = 0;
			s = con.createStatement();
			rs = s.executeQuery("SELECT COUNT(*) FROM blackboard_attribute_types");

			if (rs.next()) {
				count = rs.getInt(1);
			} else {
				throw new TskCoreException("Error getting count of attribute types. ");
			}

			return count;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting number of blackboard artifacts by type. " + ex.getMessage(), ex);
		} finally {
			if (rs != null) {
				try {
					rs.close();
				} catch (SQLException ex) {
					logger.log(Level.WARNING, "Coud not close the result set, ", ex);
				}
			}
			if (s != null) {
				try {
					s.close();
				} catch (SQLException ex) {
					logger.log(Level.WARNING, "Coud not close the statement, ", ex);
				}
			}

			dbReadUnlock();
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
	 * within tsk core
	 */
	private ArrayList<BlackboardArtifact> getArtifactsHelper(int artifactTypeID, String artifactTypeName, long obj_id) throws TskCoreException {
		dbReadLock();
		try {
			ArrayList<BlackboardArtifact> artifacts = new ArrayList<BlackboardArtifact>();

			getArtifactsHelper1St.setLong(1, obj_id);
			getArtifactsHelper1St.setInt(1, artifactTypeID);
			ResultSet rs = getArtifactsHelper1St.executeQuery();

			while (rs.next()) {
				artifacts.add(new BlackboardArtifact(this, rs.getLong(1), obj_id, artifactTypeID, artifactTypeName, this.getArtifactTypeDisplayName(artifactTypeID)));
			}
			rs.close();

			return artifacts;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting or creating a blackboard artifact. " + ex.getMessage(), ex);
		} finally {
			dbReadUnlock();
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
	 * within tsk core
	 */
	private long getArtifactsCountHelper(int artifactTypeID, long obj_id) throws TskCoreException {
		ResultSet rs = null;
		dbReadLock();
		try {
			long count = 0;

			getArtifactsCountHelperSt.setLong(1, obj_id);
			getArtifactsCountHelperSt.setInt(1, artifactTypeID);
			rs = getArtifactsCountHelperSt.executeQuery();

			if (rs.next()) {
				count = rs.getLong(1);
			} else {
				throw new TskCoreException("Error getting blackboard artifact count, no rows returned");
			}

			return count;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting blackboard artifact count, " + ex.getMessage(), ex);
		} finally {
			if (rs != null) {
				try {
					rs.close();
				} catch (SQLException ex) {
					logger.log(Level.SEVERE, "Could not close the result set. ", ex);
				}
			}
			dbReadUnlock();
		}
	}

	/**
	 * helper method to get all artifacts matching the type id name
	 *
	 * @param artifactTypeID artifact type id
	 * @param artifactTypeName artifact type name
	 * @return list of blackboard artifacts
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within tsk core
	 */
	private ArrayList<BlackboardArtifact> getArtifactsHelper(int artifactTypeID, String artifactTypeName) throws TskCoreException {
		dbReadLock();
		try {
			ArrayList<BlackboardArtifact> artifacts = new ArrayList<BlackboardArtifact>();

			getArtifactsHelper2St.setInt(1, artifactTypeID);
			ResultSet rs = getArtifactsHelper2St.executeQuery();

			while (rs.next()) {
				artifacts.add(new BlackboardArtifact(this, rs.getLong(1), rs.getLong(2), artifactTypeID, artifactTypeName, this.getArtifactTypeDisplayName(artifactTypeID)));
			}
			rs.close();

			return artifacts;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting or creating a blackboard artifact. " + ex.getMessage(), ex);
		} finally {
			dbReadUnlock();
		}
	}

	/**
	 * Get all blackboard artifacts of a given type for the given object id
	 *
	 * @param artifactTypeName artifact type name
	 * @param obj_id object id
	 * @return list of blackboard artifacts
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within tsk core
	 */
	public ArrayList<BlackboardArtifact> getBlackboardArtifacts(String artifactTypeName, long obj_id) throws TskCoreException {
		int artifactTypeID = this.getArtifactTypeID(artifactTypeName);
		return getArtifactsHelper(artifactTypeID, artifactTypeName, obj_id);
	}

	/**
	 * Get all blackboard artifacts of a given type for the given object id
	 *
	 * @param artifactTypeID artifact type id (must exist in database)
	 * @param obj_id object id
	 * @return list of blackboard artifacts
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within tsk core
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
	 * within tsk core
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
	 * within tsk core
	 */
	public long getBlackboardArtifactsCount(String artifactTypeName, long obj_id) throws TskCoreException {
		int artifactTypeID = this.getArtifactTypeID(artifactTypeName);
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
	 * within tsk core
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
	 * within tsk core
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
	 * within tsk core
	 */
	public ArrayList<BlackboardArtifact> getBlackboardArtifacts(String artifactTypeName) throws TskCoreException {
		int artifactTypeID = this.getArtifactTypeID(artifactTypeName);
		return getArtifactsHelper(artifactTypeID, artifactTypeName);
	}

	/**
	 * Get all blackboard artifacts of a given type
	 *
	 * @param artifactType artifact type enum
	 * @return list of blackboard artifacts
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within tsk core
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
	 * within tsk core
	 */
	public List<BlackboardArtifact> getBlackboardArtifacts(ARTIFACT_TYPE artifactType, BlackboardAttribute.ATTRIBUTE_TYPE attrType, String value) throws TskCoreException {
		dbReadLock();
		try {
			Statement s = con.createStatement();
			ResultSet rs = s.executeQuery("SELECT DISTINCT blackboard_artifacts.artifact_id, "
					+ "blackboard_artifacts.obj_id, blackboard_artifacts.artifact_type_id "
					+ "FROM blackboard_artifacts, blackboard_attributes "
					+ "WHERE blackboard_artifacts.artifact_id = blackboard_attributes.artifact_id "
					+ "AND blackboard_attributes.attribute_type_id IS " + attrType.getTypeID()
					+ " AND blackboard_artifacts.artifact_type_id = " + artifactType.getTypeID()
					+ " AND blackboard_attributes.value_text IS '" + value + "'");

			List<BlackboardArtifact> artifacts = getArtifactsHelper(rs);

			rs.close();
			s.close();
			return artifacts;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting blackboard artifacts by artifact type and attribute. " + ex.getMessage(), ex);
		} finally {
			dbReadUnlock();
		}
	}

	/**
	 * Get the blackboard artifact with the given artifact id
	 *
	 * @param artifactID artifact ID
	 * @return blackboard artifact
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within tsk core
	 */
	public BlackboardArtifact getBlackboardArtifact(long artifactID) throws TskCoreException {
		dbReadLock();
		try {
			getBlackboardArtifactSt.setLong(1, artifactID);
			ResultSet rs = getBlackboardArtifactSt.executeQuery();
			long obj_id = rs.getLong(1);
			int artifact_type_id = rs.getInt(2);
			rs.close();
			return new BlackboardArtifact(this, artifactID, obj_id, artifact_type_id, this.getArtifactTypeString(artifact_type_id), this.getArtifactTypeDisplayName(artifact_type_id));

		} catch (SQLException ex) {
			throw new TskCoreException("Error getting a blackboard artifact. " + ex.getMessage(), ex);
		} finally {
			dbReadUnlock();
		}
	}

	/**
	 * Add a blackboard attribute. All information for the attribute should be
	 * in the given attribute
	 *
	 * @param attr a blackboard attribute. All necessary information should be
	 * filled in.
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within tsk core
	 */
	public void addBlackboardAttribute(BlackboardAttribute attr) throws TskCoreException {
		dbWriteLock();
		try {
			PreparedStatement ps = null;
			switch (attr.getValueType()) {
				case STRING:
					addBlackboardAttributeStringSt.setString(6, escapeForBlackboard(attr.getValueString()));
					ps = addBlackboardAttributeStringSt;
					break;
				case BYTE:
					addBlackboardAttributeByteSt.setBytes(6, attr.getValueBytes());
					ps = addBlackboardAttributeByteSt;
					break;
				case INTEGER:
					addBlackboardAttributeIntegerSt.setInt(6, attr.getValueInt());
					ps = addBlackboardAttributeIntegerSt;
					break;
				case LONG:
					addBlackboardAttributeLongSt.setLong(6, attr.getValueLong());
					ps = addBlackboardAttributeLongSt;
					break;
				case DOUBLE:
					addBlackboardAttributeDoubleSt.setDouble(6, attr.getValueDouble());
					ps = addBlackboardAttributeDoubleSt;
					break;
			} // end switch

			//set common fields
			ps.setLong(1, attr.getArtifactID());
			ps.setString(2, attr.getModuleName());
			ps.setString(3, attr.getContext());
			ps.setInt(4, attr.getAttributeTypeID());
			ps.setLong(5, attr.getValueType().getType());
			ps.executeUpdate();
			ps.clearParameters();
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting or creating a blackboard artifact.", ex);
		} finally {
			dbWriteUnlock();
		}
	}

	/**
	 * Add a blackboard attributes in bulk. All information for the attribute
	 * should be in the given attribute
	 *
	 * @param attributes collection of blackboard attributes. All necessary
	 * information should be filled in.
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within tsk core
	 */
	public void addBlackboardAttributes(Collection<BlackboardAttribute> attributes) throws TskCoreException {
		dbWriteLock();
		try {
			con.setAutoCommit(false);
		} catch (SQLException ex) {
			dbWriteUnlock();
			throw new TskCoreException("Error creating transaction, no attributes created.", ex);
		}

		for (final BlackboardAttribute attr : attributes) {
			PreparedStatement ps = null;
			try {
				switch (attr.getValueType()) {
					case STRING:
						addBlackboardAttributeStringSt.setString(6, escapeForBlackboard(attr.getValueString()));
						ps = addBlackboardAttributeStringSt;
						break;
					case BYTE:
						addBlackboardAttributeByteSt.setBytes(6, attr.getValueBytes());
						ps = addBlackboardAttributeByteSt;
						break;
					case INTEGER:
						addBlackboardAttributeIntegerSt.setInt(6, attr.getValueInt());
						ps = addBlackboardAttributeIntegerSt;
						break;
					case LONG:
						addBlackboardAttributeLongSt.setLong(6, attr.getValueLong());
						ps = addBlackboardAttributeLongSt;
						break;
					case DOUBLE:
						addBlackboardAttributeDoubleSt.setDouble(6, attr.getValueDouble());
						ps = addBlackboardAttributeDoubleSt;
						break;
				}

				//set commmon fields and exec. update
				ps.setLong(1, attr.getArtifactID());
				ps.setString(2, attr.getModuleName());
				ps.setString(3, attr.getContext());
				ps.setInt(4, attr.getAttributeTypeID());
				ps.setLong(5, attr.getValueType().getType());
				ps.executeUpdate();
				ps.clearParameters();

			} catch (SQLException ex) {
				logger.log(Level.WARNING, "Error adding attribute: " + attr.toString(), ex);
				//try to add more attributes 
			}
		} //end for every attribute

		//commit transaction
		try {
			con.commit();
		} catch (SQLException ex) {
			throw new TskCoreException("Error committing transaction, no attributes created.", ex);
		} finally {
			try {
				con.setAutoCommit(true);
			} catch (SQLException ex) {
				throw new TskCoreException("Error setting autocommit and closing the transaction!", ex);
			} finally {
				dbWriteUnlock();
			}
		}

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
		addAttrType(attrTypeString, displayName, attributeIDcounter);
		int retval = attributeIDcounter;
		attributeIDcounter++;
		return retval;

	}

	/**
	 * helper method. add an attribute type with the given name and id
	 *
	 * @param attrTypeString type name
	 * @param displayName the (non-unique) display name of the attribute type
	 * @param typeID type id
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within tsk core
	 */
	private void addAttrType(String attrTypeString, String displayName, int typeID) throws TskCoreException {
		dbWriteLock();
		try {
			Statement s = con.createStatement();
			ResultSet rs = s.executeQuery("SELECT * from blackboard_attribute_types WHERE type_name = '" + attrTypeString + "'");
			if (!rs.next()) {
				s.executeUpdate("INSERT INTO blackboard_attribute_types (attribute_type_id, type_name, display_name) VALUES (" + typeID + ", '" + attrTypeString + "', '" + displayName + "')");
				rs.close();
				s.close();
			} else {
				rs.close();
				s.close();
				throw new TskCoreException("Attribute with that name already exists");
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting attribute type id.", ex);
		} finally {
			dbWriteUnlock();
		}
	}

	/**
	 * Get the attribute id that corresponds to the given string. If that string
	 * does not exist it will be added to the table.
	 *
	 * @param attrTypeString attribute type string
	 * @return attribute id
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within tsk core
	 */
	public int getAttrTypeID(String attrTypeString) throws TskCoreException {
		dbReadLock();
		try {
			Statement s = con.createStatement();
			ResultSet rs;

			rs = s.executeQuery("SELECT attribute_type_id FROM blackboard_attribute_types WHERE type_name = '" + attrTypeString + "'");
			if (rs.next()) {
				int type = rs.getInt(1);
				rs.close();
				s.close();
				return type;
			} else {
				rs.close();
				s.close();
				throw new TskCoreException("No id with that name");
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting attribute type id.", ex);
		} finally {
			dbReadUnlock();
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
		dbReadLock();
		try {
			Statement s = con.createStatement();
			ResultSet rs;

			rs = s.executeQuery("SELECT type_name FROM blackboard_attribute_types WHERE attribute_type_id = " + attrTypeID);
			if (rs.next()) {
				String type = rs.getString(1);
				rs.close();
				s.close();
				return type;
			} else {
				rs.close();
				s.close();
				throw new TskCoreException("No type with that id.");
			}

		} catch (SQLException ex) {
			throw new TskCoreException("Error getting or creating a attribute type name.", ex);
		} finally {
			dbReadUnlock();
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
		dbReadLock();
		try {
			Statement s = con.createStatement();
			ResultSet rs;

			rs = s.executeQuery("SELECT display_name FROM blackboard_attribute_types WHERE attribute_type_id = " + attrTypeID);
			if (rs.next()) {
				String type = rs.getString(1);
				rs.close();
				s.close();
				return type;
			} else {
				rs.close();
				s.close();
				throw new TskCoreException("No type with that id.");
			}

		} catch (SQLException ex) {
			throw new TskCoreException("Error getting or creating a attribute type name.", ex);
		} finally {
			dbReadUnlock();
		}
	}

	/**
	 * Get artifact type id for the given string. Will throw an error if one
	 * with that name does not exist.
	 *
	 * @param artifactTypeString name for an artifact type
	 * @return artifact type
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within tsk core
	 */
	int getArtifactTypeID(String artifactTypeString) throws TskCoreException {
		dbReadLock();
		try {
			Statement s = con.createStatement();
			ResultSet rs;

			rs = s.executeQuery("SELECT artifact_type_id FROM blackboard_artifact_types WHERE type_name = '" + artifactTypeString + "'");
			if (rs.next()) {
				int type = rs.getInt(1);
				rs.close();
				s.close();
				return type;
			} else {
				rs.close();
				s.close();
				throw new TskCoreException("No artifact with that name exists");
			}

		} catch (SQLException ex) {
			throw new TskCoreException("Error getting artifact type id." + ex.getMessage(), ex);
		} finally {
			dbReadUnlock();
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
		dbReadLock();
		try {
			Statement s = con.createStatement();
			ResultSet rs;

			rs = s.executeQuery("SELECT type_name FROM blackboard_artifact_types WHERE artifact_type_id = " + artifactTypeID);
			if (rs.next()) {
				String type = rs.getString(1);
				rs.close();
				s.close();
				return type;
			} else {
				rs.close();
				s.close();
				throw new TskCoreException("Error: no artifact with that name in database");
			}

		} catch (SQLException ex) {
			throw new TskCoreException("Error getting artifact type id.", ex);
		} finally {
			dbReadUnlock();
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
		dbReadLock();
		try {
			Statement s = con.createStatement();
			ResultSet rs;

			rs = s.executeQuery("SELECT display_name FROM blackboard_artifact_types WHERE artifact_type_id = " + artifactTypeID);
			if (rs.next()) {
				String type = rs.getString(1);
				rs.close();
				s.close();
				return type;
			} else {
				rs.close();
				s.close();
				throw new TskCoreException("Error: no artifact with that name in database");
			}

		} catch (SQLException ex) {
			throw new TskCoreException("Error getting artifact type id.", ex);
		} finally {
			dbReadUnlock();
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
		addArtifactType(artifactTypeName, displayName, artifactIDcounter);
		int retval = artifactIDcounter;
		artifactIDcounter++;
		return retval;
	}

	/**
	 * helper method. add an artifact with the given type and id
	 *
	 * @param artifactTypeName type name
	 * @param displayName Display (non-unique) name of artifact
	 * @param typeID type id
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within tsk core
	 */
	private void addArtifactType(String artifactTypeName, String displayName, int typeID) throws TskCoreException {
		dbWriteLock();
		try {
			Statement s = con.createStatement();
			ResultSet rs = s.executeQuery("SELECT * FROM blackboard_artifact_types WHERE type_name = '" + artifactTypeName + "'");
			if (!rs.next()) {
				s.executeUpdate("INSERT INTO blackboard_artifact_types (artifact_type_id, type_name, display_name) VALUES (" + typeID + " , '" + artifactTypeName + "', '" + displayName + "')");
				rs.close();
				s.close();
			} else {
				rs.close();
				s.close();
				throw new TskCoreException("Artifact with that name already exists");
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error adding artifact type.", ex);
		} finally {
			dbWriteUnlock();
		}

	}

	public ArrayList<BlackboardAttribute> getBlackboardAttributes(final BlackboardArtifact artifact) throws TskCoreException {
		final ArrayList<BlackboardAttribute> attributes = new ArrayList<BlackboardAttribute>();
		ResultSet rs = null;
		dbReadLock();
		try {
			getBlackboardAttributesSt.setLong(1, artifact.getArtifactID());
			rs = getBlackboardAttributesSt.executeQuery();
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
			rs.close();

			return attributes;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting attributes for artifact: " + artifact.getArtifactID(), ex);
		} finally {
			dbReadUnlock();
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
		ArrayList<BlackboardAttribute> matches = new ArrayList<BlackboardAttribute>();
		dbReadLock();
		try {
			Statement s;

			s = con.createStatement();

			ResultSet rs = s.executeQuery("Select artifact_id, source, context, attribute_type_id, value_type, "
					+ "value_byte, value_text, value_int32, value_int64, value_double FROM blackboard_attributes " + whereClause);

			while (rs.next()) {
				BlackboardAttribute attr = new BlackboardAttribute(rs.getLong("artifact_id"), rs.getInt("attribute_type_id"), rs.getString("source"), rs.getString("context"),
						BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.fromType(rs.getInt("value_type")), rs.getInt("value_int32"), rs.getLong("value_int64"), rs.getDouble("value_double"),
						rs.getString("value_text"), rs.getBytes("value_byte"), this);
				matches.add(attr);
			}
			rs.close();
			s.close();

			return matches;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting attributes. using this where clause: " + whereClause, ex);
		} finally {
			dbReadUnlock();
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
		ArrayList<BlackboardArtifact> matches = new ArrayList<BlackboardArtifact>();
		dbReadLock();
		try {
			Statement s;
			s = con.createStatement();

			ResultSet rs = s.executeQuery("Select artifact_id, obj_id, artifact_type_id FROM blackboard_artifacts " + whereClause);

			while (rs.next()) {
				BlackboardArtifact artifact = new BlackboardArtifact(this, rs.getLong(1), rs.getLong(2), rs.getInt(3), this.getArtifactTypeString(rs.getInt(3)), this.getArtifactTypeDisplayName(rs.getInt(3)));
				matches.add(artifact);
			}
			rs.close();
			s.close();
			return matches;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting attributes. using this where clause: " + whereClause, ex);
		} finally {
			dbReadUnlock();
		}
	}

	/**
	 * Add a new blackboard artifact with the given type. If that artifact type
	 * does not exist an error will be thrown. The artifact typename can be
	 * looked up in the returned blackboard artifact
	 *
	 * @param artifactTypeID the type the given artifact should have
	 * @param obj_id the content object id associated with this artifact
	 * @return a new blackboard artifact
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within tsk core
	 */
	public BlackboardArtifact newBlackboardArtifact(int artifactTypeID, long obj_id) throws TskCoreException {
		dbWriteLock();
		try {
			String artifactTypeName = this.getArtifactTypeString(artifactTypeID);
			String artifactDisplayName = this.getArtifactTypeDisplayName(artifactTypeID);

			long artifactID = -1;
			addArtifactSt1.setLong(1, obj_id);
			addArtifactSt1.setInt(2, artifactTypeID);
			addArtifactSt1.executeUpdate();

			getLastArtifactId.setLong(1, obj_id);
			getLastArtifactId.setInt(2, artifactTypeID);

			final ResultSet rs = getLastArtifactId.executeQuery();
			artifactID = rs.getLong(1);
			rs.close();

			addArtifactSt1.clearParameters();
			getLastArtifactId.clearParameters();

			return new BlackboardArtifact(this, artifactID, obj_id, artifactTypeID,
					artifactTypeName, artifactDisplayName);

		} catch (SQLException ex) {
			throw new TskCoreException("Error getting or creating a blackboard artifact. " + ex.getMessage(), ex);
		} finally {
			dbWriteUnlock();
		}
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
		dbWriteLock();
		try {
			final int type = artifactType.getTypeID();

			long artifactID = -1;
			addArtifactSt1.setLong(1, obj_id);
			addArtifactSt1.setInt(2, type);
			addArtifactSt1.executeUpdate();

			getLastArtifactId.setLong(1, obj_id);
			getLastArtifactId.setInt(2, type);
			final ResultSet rs = getLastArtifactId.executeQuery();
			if (rs.next()) {
				artifactID = rs.getLong(1);
			}

			rs.close();

			addArtifactSt1.clearParameters();
			getLastArtifactId.clearParameters();

			return new BlackboardArtifact(this, artifactID, obj_id, type,
					artifactType.getLabel(), artifactType.getDisplayName());

		} catch (SQLException ex) {
			throw new TskCoreException("Error getting or creating a blackboard artifact. " + ex.getMessage(), ex);
		} finally {
			dbWriteUnlock();
		}
	}

	/**
	 * Add one of the built in artifact types
	 *
	 * @param type type enum
	 * @throws TskException
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within tsk core
	 */
	private void addBuiltInArtifactType(ARTIFACT_TYPE type) throws TskCoreException {
		addArtifactType(type.getLabel(), type.getDisplayName(), type.getTypeID());
	}

	/**
	 * Add one of the built in attribute types
	 *
	 * @param type type enum
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within tsk core
	 */
	private void addBuiltInAttrType(ATTRIBUTE_TYPE type) throws TskCoreException {
		addAttrType(type.getLabel(), type.getDisplayName(), type.getTypeID());
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
		boolean hasChildren = false;

		ResultSet rs = null;
		dbReadLock();
		try {
			hasChildrenSt.setLong(1, content.getId());
			rs = hasChildrenSt.executeQuery();
			if (rs.next()) {
				hasChildren = rs.getInt(1) > 0;
			}

		} catch (SQLException e) {
			logger.log(Level.SEVERE, "Error checking for children of parent: " + content, e);
		} finally {
			if (rs != null) {
				try {
					rs.close();
				} catch (SQLException ex) {
					logger.log(Level.SEVERE, "Error closing a result set after checking for children.", ex);
				}
			}
			dbReadUnlock();

		}
		return hasChildren;

	}
	
	/**
	 * Counts if the content object  children. Note: this is generally more
	 * efficient then preloading all children and counting,
	 * and facilities lazy loading.
	 *
	 * @param content content object to check for children count
	 * @return children count
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within tsk core
	 */
	int getContentChildrenCount(Content content) throws TskCoreException {
		int countChildren = -1;

		ResultSet rs = null;
		dbReadLock();
		try {
			hasChildrenSt.setLong(1, content.getId());
			rs = hasChildrenSt.executeQuery();
			if (rs.next()) {
				countChildren = rs.getInt(1);
			}

		} catch (SQLException e) {
			logger.log(Level.SEVERE, "Error checking for children of parent: " + content, e);
		} finally {
			if (rs != null) {
				try {
					rs.close();
				} catch (SQLException ex) {
					logger.log(Level.SEVERE, "Error closing a result set after checking for children.", ex);
				}
			}
			dbReadUnlock();

		}
		return countChildren;

	}

	/**
	 * Returns the list of AbstractFile Children for a given AbstractFileParent
	 *
	 * @param parent the content parent to get abstract file children for
	 * @param type children type to look for, defined in TSK_DB_FILES_TYPE_ENUM
	 * @throws TskCoreException exception thrown if a critical error occurs
	 * within tsk core
	 */
	List<Content> getAbstractFileChildren(Content parent, TSK_DB_FILES_TYPE_ENUM type) throws TskCoreException {

		List<Content> children = new ArrayList<Content>();

		dbReadLock();
		try {

			long parentId = parent.getId();

			getAbstractFileChildren.setLong(1, parentId);
			getAbstractFileChildren.setShort(2, type.getFileType());

			final ResultSet rs = getAbstractFileChildren.executeQuery();

			while (rs.next()) {
				if (type == TSK_DB_FILES_TYPE_ENUM.FS) {
					FsContent result;
					if (rs.getShort("meta_type") == TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_DIR.getValue()) {
						result = rsHelper.directory(rs, null);
					} else {
						result = rsHelper.file(rs, null);
					}
					children.add(result);
				} else if (type == TSK_DB_FILES_TYPE_ENUM.VIRTUAL_DIR) {
					String parentPath = rs.getString("parent_path");
					if (parentPath == null) {
						parentPath = "";
					}
					VirtualDirectory virtDir = new VirtualDirectory(this, rs.getLong("obj_id"),
							rs.getString("name"),
							TSK_FS_NAME_TYPE_ENUM.valueOf(rs.getShort("dir_type")), 
							TSK_FS_META_TYPE_ENUM.ValueOf(rs.getShort("meta_type")),
							TSK_FS_NAME_FLAG_ENUM.valueOf(rs.getShort("dir_flags")), rs.getShort("meta_flags"),
							rs.getLong("size"), rs.getString("md5"), 
							FileKnown.valueOf(rs.getByte("known")), parentPath);
					children.add(virtDir);
				} else if (type == TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS) {
					String parentPath = rs.getString("parent_path");
					if (parentPath == null) {
						parentPath = "";
					}
					final LayoutFile lf =
							new LayoutFile(this, rs.getLong("obj_id"), rs.getString("name"),
							TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS,
							TSK_FS_NAME_TYPE_ENUM.valueOf(rs.getShort("dir_type")), 
							TSK_FS_META_TYPE_ENUM.ValueOf(rs.getShort("meta_type")),
							TSK_FS_NAME_FLAG_ENUM.valueOf(rs.getShort("dir_flags")), 
							rs.getShort("meta_flags"),
							rs.getLong("size"),
							rs.getString("md5"), FileKnown.valueOf(rs.getByte("known")), parentPath);
					children.add(lf);
				} else if (type == TSK_DB_FILES_TYPE_ENUM.DERIVED) {
					final DerivedFile df = rsHelper.derivedFile(rs, parentId);
					children.add(df);
				} else if (type == TSK_DB_FILES_TYPE_ENUM.LOCAL) {
					//TODO
				}
			}
			rs.close();
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting AbstractFile children for Content.", ex);
		} finally {
			dbReadUnlock();
		}
		return children;
	}

	List<Long> getAbstractFileChildrenIds(Content parent, TSK_DB_FILES_TYPE_ENUM type) throws TskCoreException {
		final List<Long> children = new ArrayList<Long>();

		dbReadLock();
		try {

			getAbstractFileChildrenIds.setLong(1, parent.getId());
			getAbstractFileChildrenIds.setShort(2, type.getFileType());

			ResultSet rs = getAbstractFileChildrenIds.executeQuery();

			while (rs.next()) {
				children.add(rs.getLong(1));
			}
			rs.close();
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting AbstractFile children for Content.", ex);
		} finally {
			dbReadUnlock();
		}
		return children;
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
		dbReadLock();
		try {
			Statement s = con.createStatement();
			String query = "SELECT tsk_objects.obj_id, tsk_objects.type ";
			query += "FROM tsk_objects left join tsk_files ";
			query += "ON tsk_objects.obj_id=tsk_files.obj_id ";
			query += "WHERE tsk_objects.par_obj_id = " + c.getId() + " ";
			ResultSet rs = s.executeQuery(query);

			Collection<ObjectInfo> infos = new ArrayList<ObjectInfo>();

			while (rs.next()) {
				infos.add(new ObjectInfo(rs.getLong("obj_id"), ObjectType.valueOf(rs.getShort("type"))));
			}
			rs.close();
			s.close();
			return infos;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting Children Info for Content.", ex);
		} finally {
			dbReadUnlock();
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
		dbReadLock();
		try {
			Statement s = con.createStatement();
			ResultSet rs = s.executeQuery("SELECT parent.obj_id, parent.type "
					+ "FROM tsk_objects AS parent JOIN tsk_objects AS child "
					+ "ON child.par_obj_id = parent.obj_id "
					+ "WHERE child.obj_id = " + c.getId());

			ObjectInfo info;

			if (rs.next()) {
				info = new ObjectInfo(rs.getLong(1), ObjectType.valueOf(rs.getShort(2)));
				rs.close();
				s.close();
				return info;
			} else {
				rs.close();
				s.close();
				throw new TskCoreException("Given content (id: " + c.getId() + ") has no parent.");
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting Parent Info for Content.", ex);
		} finally {
			dbReadUnlock();
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
		dbReadLock();
		try {
			Statement s = con.createStatement();
			ResultSet rs = s.executeQuery("SELECT parent.obj_id, parent.type "
					+ "FROM tsk_objects AS parent JOIN tsk_objects AS child "
					+ "ON child.par_obj_id = parent.obj_id "
					+ "WHERE child.obj_id = " + contentId);

			ObjectInfo info;

			if (rs.next()) {
				info = new ObjectInfo(rs.getLong(1), ObjectType.valueOf(rs.getShort(2)));
				rs.close();
				s.close();
				return info;
			} else {
				rs.close();
				s.close();
				throw new TskCoreException("Given content (id: " + contentId + ") has no parent.");
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting Parent Info for Content: " + contentId, ex);
		} finally {
			dbReadUnlock();
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
		dbReadLock();
		Statement s = null;
		ResultSet contentRs = null;
		try {
			s = con.createStatement();
			contentRs = s.executeQuery("SELECT * FROM tsk_objects WHERE obj_id = " + id + " LIMIT  1");
			if (!contentRs.next()) {
				contentRs.close();
				s.close();
				return null;
			}

			AbstractContent content = null;
			long parentId = contentRs.getLong("par_obj_id");
			final TskData.ObjectType type = TskData.ObjectType.valueOf(contentRs.getShort("type"));
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
			try {
				if (contentRs != null) {
					contentRs.close();
				}
				if (s != null) {
					s.close();
				}
			} catch (SQLException ex) {
				throw new TskCoreException("Error closing statement when getting Content by ID.", ex);
			}
			dbReadUnlock();
		}
	}

	/**
	 * /internal Get a path of a file in tsk_files_path table or null if there
	 * is none
	 *
	 * @param id id of the file to get path for
	 * @return file path of null
	 * @throws SQLException file path could not be queried due to user error
	 */
	String getFilePath(long id) throws SQLException {

		String filePath = null;
		ResultSet rs = null;
		dbReadLock();
		try {
			getPathSt.setLong(1, id);
			rs = getPathSt.executeQuery();
			if (rs.next()) {
				filePath = rs.getString(1);
			}
		} catch (SQLException ex) {
			logger.log(Level.SEVERE, "Error getting file path for file: " + id, ex);
		} finally {
			if (rs != null) {
				try {
					rs.close();
				} catch (SQLException ex) {
					logger.log(Level.SEVERE, "Error closing result set after getting file path by id.", ex);
				}
			}
			dbReadUnlock();
		}

		return filePath;
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
		DerivedFile.DerivedMethod method = null;

		ResultSet rs1 = null;
		ResultSet rs2 = null;
		dbReadLock();
		try {
			getDerivedInfoSt.setLong(1, id);
			rs1 = getDerivedInfoSt.executeQuery();
			if (rs1.next()) {
				int method_id = rs1.getInt(1);
				String rederive = rs1.getString(1);

				method = new DerivedFile.DerivedMethod(method_id, rederive);

				getDerivedMethodSt.setInt(1, method_id);
				rs2 = getDerivedMethodSt.executeQuery();
				if (rs2.next()) {
					method.setToolName(rs2.getString(1));
					method.setToolVersion(rs2.getString(2));
					method.setOther(rs2.getString(3));
				}
			}
		} catch (SQLException e) {
			logger.log(Level.SEVERE, "Error getting derived method for file: " + id, e);
		} finally {
			if (rs1 != null) {
				try {
					rs1.close();
				} catch (SQLException ex) {
					logger.log(Level.SEVERE, "Error closing result set after getting derived file method", ex);
				}
			}
			if (rs2 != null) {
				try {
					rs2.close();
				} catch (SQLException ex) {
					logger.log(Level.SEVERE, "Error closing result set after getting derived file method", ex);
				}
			}

			dbReadUnlock();
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
		ResultSet rs = null;
		dbReadLock();
		try {
			getAbstractFileById.setLong(1, id);
			rs = getAbstractFileById.executeQuery();

			List<AbstractFile> results;
			if ((results = resultSetToAbstractFiles(rs)).size() > 0) {
				return results.get(0);
			} else {
				return null;
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting FsContent by ID.", ex);
		} finally {
			if (rs != null) {
				try {
					rs.close();
				} catch (SQLException ex) {
					logger.log(Level.SEVERE, "Error closing result set after getting file by id.", ex);
				}
			}
			dbReadUnlock();
		}

	}

	/**
	 * @param image the image to search for the given file name
	 * @param fileName the name of the file or directory to match (case
	 * insensitive)
	 * @return a list of FsContent for files/directories whose name matches the
	 * given fileName
	 */
	public List<FsContent> findFiles(Image image, String fileName) throws TskCoreException {
		dbReadLock();

		// set the file name in the PS
		List<FsContent> fsContents = new ArrayList<FsContent>();
		try {
			for (FileSystem fileSystem : getFileSystems(image)) {
				getFileSt.setString(1, fileName.toLowerCase());
				getFileSt.setLong(2, fileSystem.getId());

				// get the result set
				ResultSet rs = getFileSt.executeQuery();

				// convert to FsConents
				fsContents.addAll(resultSetToFsContents(rs));

				// close the ResultSet
				rs.close();
			}
		} catch (Exception e) {
			throw new TskCoreException(e.getMessage());
		} finally {
			dbReadUnlock();
		}

		return fsContents;
	}

	/**
	 * @param image the image to search for the given file name
	 * @param fileName the name of the file or directory to match (case
	 * insensitive)
	 * @param dirName the name of a parent directory of fileName (case
	 * insensitive)
	 * @return a list of FsContent for files/directories whose name matches
	 * fileName and whose parent directory contains dirName.
	 */
	public List<FsContent> findFiles(Image image, String fileName, String dirName) throws TskCoreException {
		dbReadLock();

		ResultSet rs = null;
		List<FsContent> fsContents = new ArrayList<FsContent>();
		try {
			for (FileSystem fileSystem : getFileSystems(image)) {
				getFileWithParentSt.setString(1, fileName.toLowerCase());

				// set the parent directory name
				getFileWithParentSt.setString(2, "%" + dirName.toLowerCase() + "%");

				// set the image ID
				getFileWithParentSt.setLong(3, fileSystem.getId());

				// get the result set
				rs = getFileWithParentSt.executeQuery();

				// convert to FsConents
				fsContents.addAll(resultSetToFsContents(rs));

				// close the ResultSet
				rs.close();
			}
		} catch (Exception e) {
			throw new TskCoreException(e.getMessage());
		} finally {
			dbReadUnlock();
		}

		return fsContents;
	}

	
	/**
	 * Add a path (such as a local path) for a content object to tsk_file_paths
	 *
	 * @param objId object id of the file to add the path for
	 * @param path the path to add
	 * @throws SQLException exception thrown when database error occurred and
	 * path was not added
	 */
	private void addFilePath(long objId, String path) throws SQLException {
		try {
			addPathSt.setLong(1, objId);
			addPathSt.setString(2, path);
			addPathSt.executeUpdate();
		}
		finally {
			addPathSt.clearParameters();
		}
	}

	/**
	 * Creates a new derived file object, adds it to database and returns it.
	 *
	 * TODO add support for adding derived method and re-factor common code with
	 * LocalFiles
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
		
		final long parentId = parentFile.getId();
		final String parentPath = parentFile.getParentPath() + parentFile.getName() + '/';

		DerivedFile ret = null;

		long newObjId = -1;

		dbWriteLock();

		//all in one write lock and transaction
		//get last object id
		//create tsk_objects object with new id
		//create tsk_files object with the new id
		try {

			con.setAutoCommit(false);

			newObjId = getLastObjectId() + 1;
			if (newObjId < 1) {
				String msg = "Error creating a derived file, cannot get new id of the object, file name: " + fileName;
				throw new TskCoreException(msg);
			}

			//tsk_objects
			addObjectSt.setLong(1, newObjId);
			addObjectSt.setLong(2, parentId);
			addObjectSt.setLong(3, TskData.ObjectType.ABSTRACTFILE.getObjectType());
			addObjectSt.executeUpdate();

			//tsk_files
			//obj_id, fs_obj_id, name, type, has_path, dir_type, meta_type, dir_flags, meta_flags, size, parent_path

			//obj_id, fs_obj_id, name
			addLocalFileSt.setLong(1, newObjId);
			addLocalFileSt.setString(2, fileName);

			//type, has_path
			addLocalFileSt.setShort(3, TskData.TSK_DB_FILES_TYPE_ENUM.DERIVED.getFileType());
			addLocalFileSt.setBoolean(4, true);

			//flags
			final TSK_FS_NAME_TYPE_ENUM dirType = isFile ? TSK_FS_NAME_TYPE_ENUM.REG : TSK_FS_NAME_TYPE_ENUM.DIR;
			addLocalFileSt.setShort(5, dirType.getValue());
			final TSK_FS_META_TYPE_ENUM metaType = isFile ? TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_REG : TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_DIR;
			addLocalFileSt.setShort(6, metaType.getValue());

			//note: using alloc under assumption that derived files derive from alloc files
			final TSK_FS_NAME_FLAG_ENUM dirFlag = TSK_FS_NAME_FLAG_ENUM.ALLOC;
			addLocalFileSt.setShort(7, dirFlag.getValue());
			final short metaFlags = (short) (TSK_FS_META_FLAG_ENUM.ALLOC.getValue()
					| TSK_FS_META_FLAG_ENUM.USED.getValue());
			addLocalFileSt.setShort(8, metaFlags);

			//size
			addLocalFileSt.setLong(9, size);
			//mactimes
			//long ctime, long crtime, long atime, long mtime,
			addLocalFileSt.setLong(10, ctime);
			addLocalFileSt.setLong(11, crtime);
			addLocalFileSt.setLong(12, atime);
			addLocalFileSt.setLong(13, mtime);
			//parent path
			addLocalFileSt.setString(14, parentPath);

			addLocalFileSt.executeUpdate();
			
			//add localPath 
			addFilePath(newObjId, localPath);

			ret = new DerivedFile(this, newObjId, fileName, dirType, metaType, dirFlag, metaFlags,
					size, ctime, crtime, atime, mtime, null, null, parentPath, localPath, parentId);

			//TODO add derived method to tsk_files_derived and tsk_files_derived_method 

		} catch (SQLException e) {
			String msg = "Error creating a derived file, file name: " + fileName;
			throw new TskCoreException(msg, e);
		} finally {
			try {
				addObjectSt.clearParameters();
				addLocalFileSt.clearParameters();
			} catch (SQLException ex) {
				logger.log(Level.SEVERE, "Error clearing parameters after adding derived file", ex);
			}
			
			try {
				con.commit();
			} catch (SQLException ex) {
				logger.log(Level.SEVERE, "Error committing after adding derived file", ex);
			} finally {
				try {
					con.setAutoCommit(true);
				} catch (SQLException ex) {
					logger.log(Level.SEVERE, "Error setting auto-commit after adding derived file", ex);
				} finally {
					dbWriteUnlock();
				}
			}
		}


		return ret;
	}

	/**
	 * @param image the image to search for the given file name
	 * @param fileName the name of the file or directory to match (case
	 * insensitive)
	 * @param parentFsContent
	 * @return a list of FsContent for files/directories whose name matches
	 * fileName and that were inside a directory described by parentFsContent.
	 */
	public List<FsContent> findFiles(Image image, String fileName, FsContent parentFsContent) throws TskCoreException {
		return findFiles(image, fileName, parentFsContent.getName());
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
		Statement statement = null;
		ResultSet rs = null;
		dbReadLock();
		try {
			statement = con.createStatement();
			rs = statement.executeQuery("SELECT COUNT (*) FROM tsk_files WHERE " + sqlWhereClause);
			return rs.getLong(1);
		} catch (SQLException e) {
			throw new TskCoreException("SQLException thrown when calling 'SleuthkitCase.findFilesWhere().", e);
		} finally {
			if (rs != null) {
				try {
					rs.close();
				} catch (SQLException ex) {
					logger.log(Level.SEVERE, "Error closing result set after executing  countFilesWhere", ex);
				}
			}
			if (statement != null) {
				try {
					statement.close();
				} catch (SQLException ex) {
					logger.log(Level.SEVERE, "Error closing statement after executing  countFilesWhere", ex);
				}
			}
			dbReadUnlock();
		}
	}

	
	/**
	 * Find and return list of files matching the specific Where clause
	 * 
	 * @param sqlWhereClause a SQL where clause appropriate for the desired
	 * files (do not begin the WHERE clause with the word WHERE!)
	 * @return a list of FsContent each of which satisfy the given WHERE clause
	 * @throws TskCoreException
	 */
	public List<FsContent> findFilesWhere(String sqlWhereClause) throws TskCoreException {
		Statement statement = null;
		ResultSet rs = null;
		dbReadLock();
		try {
			statement = con.createStatement();
			rs = statement.executeQuery("SELECT * FROM tsk_files WHERE " + sqlWhereClause);
			return resultSetToFsContents(rs);
		} catch (SQLException e) {
			throw new TskCoreException("SQLException thrown when calling 'SleuthkitCase.findFilesWhere().", e);
		} finally {
			if (rs != null) {
				try {
					rs.close();
				} catch (SQLException ex) {
					logger.log(Level.SEVERE, "Error closing result set after executing  findFilesWhere", ex);
				}
			}
			if (statement != null) {
				try {
					statement.close();
				} catch (SQLException ex) {
					logger.log(Level.SEVERE, "Error closing statement after executing  findFilesWhere", ex);
				}
			}
			dbReadUnlock();
		}
	}

	
	
	/**
	 * @param image the image to search for the given file name
	 * @param filePath The full path to the file(s) of interest. This can
	 * optionally include the image and volume names. Treated in a case-
	 * insensitive manner.
	 * @return a list of FsContent that have the given file path.
	 */
	public List<FsContent> openFiles(Image image, String filePath) throws TskCoreException {

		// get the non-unique path (strip of image and volume path segments, if
		// the exist.
		String path = AbstractFile.createNonUniquePath(filePath).toLowerCase();

		// split the file name from the parent path
		int lastSlash = path.lastIndexOf("/");

		// if the last slash is at the end, strip it off
		if (lastSlash == path.length()) {
			path = path.substring(0, lastSlash - 1);
			lastSlash = path.lastIndexOf("/");
		}

		String parentPath = path.substring(0, lastSlash);
		String fileName = path.substring(lastSlash);

		return findFiles(image, fileName, parentPath);
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
		List<TskFileRange> ranges = new ArrayList<TskFileRange>();
		dbReadLock();
		try {
			Statement s1 = con.createStatement();

			ResultSet rs1 = s1.executeQuery("select * from tsk_file_layout where obj_id = " + id + " order by sequence");

			while (rs1.next()) {
				ranges.add(rsHelper.tskFileRange(rs1));
			}
			rs1.close();
			s1.close();
			return ranges;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting TskFileLayoutRanges by ID.", ex);
		} finally {
			dbReadUnlock();
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
		dbReadLock();
		try {
			Statement s1 = con.createStatement();

			ResultSet rs1 = s1.executeQuery("select * from tsk_image_info where obj_id = " + id);

			Image temp;
			if (rs1.next()) {
				long obj_id = rs1.getLong("obj_id");
				Statement s2 = con.createStatement();
				ResultSet rs2 = s2.executeQuery("select * from tsk_image_names where obj_id = " + obj_id);
				List<String> imagePaths = new ArrayList<String>();
				while (rs2.next()) {
					imagePaths.add(rsHelper.imagePath(rs2));
				}

				String path1 = imagePaths.get(0);
				String name = (new java.io.File(path1)).getName();

				temp = rsHelper.image(rs1, name, imagePaths.toArray(new String[imagePaths.size()]));
				rs2.close();
				s2.close();
			} else {
				rs1.close();
				s1.close();
				throw new TskCoreException("No image found for id: " + id);
			}
			rs1.close();
			s1.close();
			return temp;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting Image by ID.", ex);
		} finally {
			dbReadUnlock();
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
		dbReadLock();
		try {
			Statement s = con.createStatement();

			ResultSet rs = s.executeQuery("select * from tsk_vs_info "
					+ "where obj_id = " + id);
			VolumeSystem temp;

			if (rs.next()) {
				temp = rsHelper.volumeSystem(rs, parent);
			} else {
				rs.close();
				s.close();
				throw new TskCoreException("No volume system found for id:" + id);
			}
			rs.close();
			s.close();
			return temp;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting Volume System by ID.", ex);
		} finally {
			dbReadUnlock();
		}
	}

	/**
	 * @param id ID of the desired VolumeSystem
	 * @param parentId ID of the VolumeSystem's parent
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
	 * @param parentId ID of the FileSystem's parent
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
		dbReadLock();
		try {
			Statement s = con.createStatement();
			FileSystem temp;

			ResultSet rs = s.executeQuery("select * from tsk_fs_info "
					+ "where obj_id = " + id);

			if (rs.next()) {
				temp = rsHelper.fileSystem(rs, parent);
			} else {
				rs.close();
				s.close();
				throw new TskCoreException("No file system found for id:" + id);
			}
			rs.close();
			s.close();

			return temp;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting File System by ID.", ex);
		} finally {
			dbReadUnlock();
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
		dbReadLock();
		try {
			Statement s = con.createStatement();
			Volume temp;

			ResultSet rs = s.executeQuery("select * from tsk_vs_parts "
					+ "where obj_id = " + id);

			if (rs.next()) {
				temp = rsHelper.volume(rs, parent);
			} else {
				rs.close();
				s.close();
				throw new TskCoreException("No volume found for id:" + id);
			}
			rs.close();
			s.close();
			return temp;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting Volume by ID.", ex);
		} finally {
			dbReadUnlock();
		}
	}

	/**
	 * @param id ID of the desired Volume
	 * @param parentId ID of the Volume's parent
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
		dbReadLock();
		try {
			Statement s = con.createStatement();
			Directory temp = null;

			ResultSet rs = s.executeQuery("SELECT * FROM tsk_files "
					+ "WHERE obj_id = " + id);

			if (rs.next()) {
				final short type = rs.getShort("type");
				if (type == TSK_DB_FILES_TYPE_ENUM.FS.getFileType()) {
					if (rs.getShort("meta_type") == TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_DIR.getValue()) {
						temp = rsHelper.directory(rs, parentFs);
					}
				} else if (type == TSK_DB_FILES_TYPE_ENUM.VIRTUAL_DIR.getFileType()) {
					rs.close();
					s.close();
					throw new TskCoreException("Expecting an FS-type directory, got virtual, id: " + id);
				}
			} else {
				rs.close();
				s.close();
				throw new TskCoreException("No Directory found for id:" + id);
			}
			rs.close();
			s.close();
			return temp;
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting Directory by ID.", ex);
		} finally {
			dbReadUnlock();
		}
	}

	/**
	 * Helper to return FileSystems in an Image
	 *
	 * @param image Image to lookup FileSystem for
	 * @return Collection of FileSystems in the image
	 */
	public Collection<FileSystem> getFileSystems(Image image) {

		// create a query to get all file system objects
		String allFsObjects = "SELECT * FROM tsk_fs_info";

		// perform the query and create a list of FileSystem objects
		List<FileSystem> allFileSystems = new ArrayList<FileSystem>();

		dbReadLock();
		Statement statement = null;
		ResultSet rs = null;
		try {
			statement = con.createStatement();
			rs = statement.executeQuery(allFsObjects);
			while (rs.next()) {
				allFileSystems.add(rsHelper.fileSystem(rs, null));
			}
		} catch (SQLException ex) {
			logger.log(Level.SEVERE, "There was a problem while trying to obtain this image's file systems.", ex);
		} finally {
			if (rs != null) {
				try {
					rs.close();
				} catch (SQLException ex) {
					logger.log(Level.SEVERE, "Cannot close result set after query of all fs objects", ex);
				}
			}
			if (statement != null) {
				try {
					statement.close();
				} catch (SQLException ex) {
					logger.log(Level.SEVERE, "Cannot close statement after query of all fs objects", ex);
				}
			}
			dbReadUnlock();
		}

		// for each file system, find the image to which it belongs by iteratively
		// climbing the tsk_ojbects hierarchy only taking those file systems
		// that belong to this image.
		List<FileSystem> fileSystems = new ArrayList<FileSystem>();
		for (FileSystem fs : allFileSystems) {
			Long imageID = null;
			Long currentObjID = fs.getId();
			while (imageID == null) {
				dbReadLock();
				try {
					statement = con.createStatement();
					rs = statement.executeQuery("SELECT * FROM tsk_objects WHERE tsk_objects.obj_id = " + currentObjID);
					currentObjID = rs.getLong("par_obj_id");
					if (rs.getInt("type") == TskData.ObjectType.IMG.getObjectType()) {
						imageID = rs.getLong("obj_id");
					}
				} catch (SQLException ex) {
					logger.log(Level.SEVERE, "There was a problem while trying to obtain this image's file systems.", ex);
				} finally {
					if (rs != null) {
						try {
							rs.close();
						} catch (SQLException ex) {
							logger.log(Level.SEVERE, "Cannot close result set after query of all fs objects for fs", ex);
						}
					}
					if (statement != null) {
						try {
							statement.close();
						} catch (SQLException ex) {
							logger.log(Level.SEVERE, "Cannot close statement after query of all fs objects for fs", ex);
						}
					}
					dbReadUnlock();
				}
			}

			// see if imageID is this image's ID
			if (imageID == image.getId()) {
				fileSystems.add(fs);
			}
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
				children.add(getAbstractFileById(info.id));
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
				children.add(getAbstractFileById(info.id));
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
				children.add(getAbstractFileById(info.id));
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
	 * Returns a list of direct children for a given file system
	 *
	 * @param fs file system to get the list of children for
	 * @return the list of direct files children of the filesystem
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 * core
	 */
	List<Content> getFileSystemChildren(FileSystem fs) throws TskCoreException {
		List<Content> ret = new ArrayList<Content>();
		for (TskData.TSK_DB_FILES_TYPE_ENUM type : TskData.TSK_DB_FILES_TYPE_ENUM.values()) {
			ret.addAll(getAbstractFileChildren(fs, type));
		}
		return ret;
	}

	/**
	 * Returns a list of direct children IDs for a given file system
	 *
	 * @param fs file system to get the list of children for
	 * @return the list of direct files children IDs of the filesystem
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 * core
	 */
	List<Long> getFileSystemChildrenIds(FileSystem fs) throws TskCoreException {
		List<Long> ret = new ArrayList<Long>();
		for (TskData.TSK_DB_FILES_TYPE_ENUM type : TskData.TSK_DB_FILES_TYPE_ENUM.values()) {
			ret.addAll(getAbstractFileChildrenIds(fs, type));
		}
		return ret;
	}

	/**
	 * Returns a list of direct children for a given directory
	 *
	 * @param dir directory to get the list of direct children for
	 * @return list of direct children (files) for a given directory
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 * core
	 */
	List<Content> getDirectoryChildren(Directory dir) throws TskCoreException {
		List<Content> ret = new ArrayList<Content>();
		for (TskData.TSK_DB_FILES_TYPE_ENUM type : TskData.TSK_DB_FILES_TYPE_ENUM.values()) {
			ret.addAll(getAbstractFileChildren(dir, type));
		}
		return ret;
	}

	/**
	 * Returns a list of direct children IDs for a given directory
	 *
	 * @param dir directory to get the list of direct children for
	 * @return list of direct children (files) IDs for a given directory
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 * core
	 */
	List<Long> getDirectoryChildrenIds(Directory dir) throws TskCoreException {
		List<Long> ret = new ArrayList<Long>();
		for (TskData.TSK_DB_FILES_TYPE_ENUM type : TskData.TSK_DB_FILES_TYPE_ENUM.values()) {
			ret.addAll(getAbstractFileChildrenIds(dir, type));
		}
		return ret;
	}

	/**
	 * Returns a list of direct children for a given layout directory
	 *
	 * @param ldir layout directory to get the list of direct children for
	 * @return list of direct children (layout files or layout directories) for
	 * a given layout directory
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 * core
	 */
	List<Content> getLayoutDirectoryChildren(VirtualDirectory ldir) throws TskCoreException {
		List<Content> ret = new ArrayList<Content>();
		for (TskData.TSK_DB_FILES_TYPE_ENUM type : TskData.TSK_DB_FILES_TYPE_ENUM.values()) {
			ret.addAll(getAbstractFileChildren(ldir, type));
		}
		return ret;
	}

	/**
	 * Returns a list of direct children IDs for a given layout directory
	 *
	 * @param ldir layout directory to get the list of direct children for
	 * @return list of direct children IDs (layout files or layout directories)
	 * for a given layout directory
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 * core
	 */
	List<Long> getLayoutDirectoryChildrenIds(VirtualDirectory ldir) throws TskCoreException {
		List<Long> ret = new ArrayList<Long>();
		for (TskData.TSK_DB_FILES_TYPE_ENUM type : TskData.TSK_DB_FILES_TYPE_ENUM.values()) {
			ret.addAll(getAbstractFileChildrenIds(ldir, type));
		}
		return ret;
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
		Map<Long, List<String>> imgPaths = new LinkedHashMap<Long, List<String>>();

		dbReadLock();
		try {
			Statement s1 = con.createStatement();

			ResultSet rs1 = s1.executeQuery("select * from tsk_image_info");

			while (rs1.next()) {
				long obj_id = rs1.getLong("obj_id");
				Statement s2 = con.createStatement();
				ResultSet rs2 = s2.executeQuery("select * from tsk_image_names where obj_id = " + obj_id);
				List<String> paths = new ArrayList<String>();
				while (rs2.next()) {
					paths.add(rsHelper.imagePath(rs2));
				}
				rs2.close();
				s2.close();
				imgPaths.put(obj_id, paths);
			}

			rs1.close();
			s1.close();
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting image paths.", ex);
		} finally {
			dbReadUnlock();
		}


		return imgPaths;
	}

	/**
	 * @return a collection of Images associated with this instance of
	 * SleuthkitCase
	 * @throws TskCoreException
	 */
	public List<Image> getImages() throws TskCoreException {
		dbReadLock();
		Collection<Long> imageIDs = new ArrayList<Long>();
		try {
			ResultSet rs = con.createStatement().executeQuery("select * from tsk_image_info");
			while (rs.next()) {
				imageIDs.add(rs.getLong("obj_id"));
			}
			rs.close();
		} catch (SQLException ex) {
			throw new TskCoreException("Error retrieving images.", ex);
		} finally {
			dbReadUnlock();
		}

		List<Image> images = new ArrayList<Image>();
		for (long id : imageIDs) {
			images.add(getImageById(id));
		}

		return images;
	}
	
	
	/**
	 * Get last (max) object id of content object in tsk_objects.
	 * 
	 * Note, if you
	 * are using this id to create a new object, make sure you are getting and
	 * using it in the same write lock/transaction to avoid potential
	 * concurrency issues with other writes
	 *
	 * @return currently max id
	 * @throws TskCoreException exception thrown when database error occurs and last object id could not be queried
	 */
	public long getLastObjectId() throws TskCoreException {
		long id = -1;
		ResultSet rs = null;
		dbReadLock();
		try {
			rs = getLastContentIdSt.executeQuery();
			if (rs.next()) {
				id = rs.getLong(1);
			}
		} catch (SQLException e) {
			final String msg = "Error closing result set after getting last object id.";
			logger.log(Level.SEVERE, msg, e);
			throw new TskCoreException(msg, e);
		} finally {
			if (rs != null) {
				try {
					rs.close();
				} catch (SQLException ex) {
					logger.log(Level.SEVERE, "Error closing result set after getting last object id.", ex);
				}
			}
			dbReadUnlock();
		}

		return id;
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

		dbWriteLock();
		try {
			Statement s1 = con.createStatement();

			s1.executeUpdate("DELETE FROM tsk_image_names WHERE obj_id = " + obj_id);
			for (int i = 0; i < paths.size(); i++) {
				s1.executeUpdate("INSERT INTO tsk_image_names VALUES (" + obj_id + ", \"" + paths.get(i) + "\", " + i + ")");
			}

			s1.close();
		} catch (SQLException ex) {
			throw new TskCoreException("Error updating image paths.", ex);
		} finally {
			dbWriteUnlock();
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
		dbReadLock();
		try {
			while (rs.next()) {
				final short type = rs.getShort("type");
				if (type == TSK_DB_FILES_TYPE_ENUM.FS.getFileType()) {
					FsContent result;
					if (rs.getShort("meta_type") == TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_DIR.getValue()) {
						result = rsHelper.directory(rs, null);
					} else {
						result = rsHelper.file(rs, null);
					}
					results.add(result);
				} else if (type == TSK_DB_FILES_TYPE_ENUM.VIRTUAL_DIR.getFileType()) {
					String parentPath = rs.getString("parent_path");
					if (parentPath == null) {
						parentPath = "";
					}
					final VirtualDirectory virtDir = new VirtualDirectory(this, rs.getLong("obj_id"),
							rs.getString("name"),
							TSK_FS_NAME_TYPE_ENUM.valueOf(rs.getShort("dir_type")), 
							TSK_FS_META_TYPE_ENUM.ValueOf(rs.getShort("meta_type")),
							TSK_FS_NAME_FLAG_ENUM.valueOf(rs.getShort("dir_flags")), 
							rs.getShort("meta_flags"),
							rs.getLong("size"), rs.getString("md5"), 
							FileKnown.valueOf(rs.getByte("known")), parentPath);
					results.add(virtDir);
				} else if (type == TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS.getFileType()) {
					String parentPath = rs.getString("parent_path");
					if (parentPath == null) {
						parentPath = "";
					}
					LayoutFile lf = new LayoutFile(this, rs.getLong("obj_id"),
							rs.getString("name"),
							TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS,
							TSK_FS_NAME_TYPE_ENUM.valueOf(rs.getShort("dir_type")), TSK_FS_META_TYPE_ENUM.ValueOf(rs.getShort("meta_type")),
							TSK_FS_NAME_FLAG_ENUM.valueOf(rs.getShort("dir_flags")), rs.getShort("meta_flags"),
							rs.getLong("size"),
							rs.getString("md5"), FileKnown.valueOf(rs.getByte("known")), parentPath);
					results.add(lf);
				} else if (type == TSK_DB_FILES_TYPE_ENUM.DERIVED.getFileType()) {
					final DerivedFile df;
					df = rsHelper.derivedFile(rs, AbstractContent.UNKNOWN_ID);
					results.add(df);
				} else if (type == TSK_DB_FILES_TYPE_ENUM.LOCAL.getFileType()) {
					//TODO
				}

			} //end for each rs
		} catch (SQLException e) {
			logger.log(Level.SEVERE, "Error getting abstract file from result set.", e);
		} finally {
			dbReadUnlock();
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
	public List<FsContent> resultSetToFsContents(ResultSet rs) throws SQLException {
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
		Statement statement;
		dbReadLock();
		try {
			statement = con.createStatement();
			ResultSet rs = statement.executeQuery(query);
			return rs;
		} finally {
			//TODO unlock should be done in closeRunQuery()
			//but currently not all code calls closeRunQuery - need to fix this
			dbReadUnlock();
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

	@Override
	public void finalize() throws Throwable {
		try {
			close();
		} finally {
			super.finalize();
		}
	}

	/**
	 * Closes the database connection of this instance.
	 */
	private void closeConnection() {
		SleuthkitCase.dbWriteLock();
		try {
			if (con != null) {
				con.close();
				con = null;
			}
			closeStatements();

		} catch (SQLException e) {
			// connection close failed.
			logger.log(Level.WARNING,
					"Error closing connection.", e);
		} finally {
			SleuthkitCase.dbWriteUnlock();
		}
	}

	/**
	 * Call to free resources when done with instance.
	 */
	public void close() {
		System.err.println(this.hashCode() + " closed");
		System.err.flush();
		SleuthkitCase.dbWriteLock();
		this.closeConnection();
		try {
			if (this.caseHandle != null) {
				this.caseHandle.free();
				this.caseHandle = null;


			}

		} catch (TskCoreException ex) {
			logger.log(Level.WARNING,
					"Error freeing case handle.", ex);
		} finally {
			SleuthkitCase.dbWriteUnlock();
		}
	}

	/**
	 * Make a duplicate / backup copy of the current case database Makes a new
	 * copy only, and continues to use the current db
	 *
	 * @param newDBPath path to the copy to be created. File will be overwritten
	 * if it exists
	 * @throws IOException if copying fails
	 */
	public void copyCaseDB(String newDBPath) throws IOException {
		InputStream in = null;
		OutputStream out = null;
		SleuthkitCase.dbReadLock();
		try {
			InputStream inFile = new FileInputStream(this.dbPath);
			in = new BufferedInputStream(inFile);
			OutputStream outFile = new FileOutputStream(newDBPath);
			out = new BufferedOutputStream(outFile);
			int readBytes = 0;
			while ((readBytes = in.read()) != -1) {
				out.write(readBytes);
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
				logger.log(Level.WARNING, "Could not close streams after db copy", e);
			}
			SleuthkitCase.dbReadUnlock();
		}
	}

	/**
	 * Store the known status for the FsContent in the database Note: will not
	 * update status if content is already 'Known Bad'
	 *
	 * @param	file	The AbstractFile object
	 * @param	fileKnown	The object's known status
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
		SleuthkitCase.dbWriteLock();
		try {
			Statement s = con.createStatement();
			s.executeUpdate("UPDATE tsk_files "
					+ "SET known='" + fileKnown.getFileKnownValue() + "' "
					+ "WHERE obj_id=" + id);
			s.close();
			//update the object itself
			file.setKnown(fileKnown);
		} catch (SQLException ex) {
			throw new TskCoreException("Error setting Known status.", ex);
		} finally {
			SleuthkitCase.dbWriteUnlock();
		}
		return true;
	}

	/**
	 * Store the md5Hash for the file in the database
	 *
	 * @param	file	The file object
	 * @param	md5Hash	The object's md5Hash
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 * core
	 */
	void setMd5Hash(AbstractFile file, String md5Hash) throws TskCoreException {
		long id = file.getId();
		SleuthkitCase.dbWriteLock();
		try {
			updateMd5St.setString(1, md5Hash);
			updateMd5St.setLong(2, id);
			updateMd5St.executeUpdate();
			//update the object itself
			file.setMd5Hash(md5Hash);
		} catch (SQLException ex) {
			throw new TskCoreException("Error setting MD5 hash.", ex);
		} finally {
			SleuthkitCase.dbWriteUnlock();
		}
	}

	/**
	 * Look up the given hash in the NSRL database
	 *
	 * @param md5Hash The hash to look up
	 * @return the status of the hash in the NSRL
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 * core
	 */
	public TskData.FileKnown nsrlLookupMd5(String md5Hash) throws TskCoreException {
		return SleuthkitJNI.nsrlHashLookup(md5Hash);
	}

	/**
	 * Look up the given hash in the known bad database
	 *
	 * @param md5Hash The hash to look up
	 * @param dbHandle The handle of the open database to look in
	 * @return the status of the hash in the known bad database
	 * @throws TskCoreException thrown if a critical error occurred within tsk
	 * core
	 */
	public TskData.FileKnown knownBadLookupMd5(String md5Hash, int dbHandle) throws TskCoreException {
		return SleuthkitJNI.knownBadHashLookup(md5Hash, dbHandle);
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
		int count = 0;
		Short contentShort = contentType.getValue();
		dbReadLock();
		try {
			Statement s = con.createStatement();
			ResultSet rs = s.executeQuery("SELECT COUNT(*) FROM tsk_files WHERE meta_type = '" + contentShort.toString() + "'");
			while (rs.next()) {
				count = rs.getInt(1);
			}
			rs.close();
			s.close();
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting number of objects.", ex);
		} finally {
			dbReadUnlock();
		}
		return count;
	}
	

	/**
	 * Escape the single quotes in the given string so they can be added to the
	 * SQL db
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
		ResultSet rs = null;
		Statement s = null;
		dbReadLock();
		try {
			s = con.createStatement();
			rs = s.executeQuery("SELECT * FROM tsk_files WHERE "
				+ " md5 = '" + md5Hash + "' "
					+ "AND size > 0");
			return resultSetToAbstractFiles(rs);


		} catch (SQLException ex) {
			logger.log(Level.WARNING, "Error querying database.", ex);
		} finally {
			if (rs != null) {
				try {
					rs.close();
					s.close();


				} catch (SQLException ex) {
					logger.log(Level.WARNING, "Unable to close ResultSet and Statement.", ex);
				}
			}
			dbReadUnlock();
		}
		return Collections.<AbstractFile>emptyList();
	}

	/**
	 * Query all the files to verify if they have an MD5 hash associated with
	 * them.
	 *
	 * @return true if all files have an MD5 hash
	 */
	public boolean allFilesMd5Hashed() {
		ResultSet rs = null;
		Statement s = null;
		dbReadLock();
		try {
			s = con.createStatement();
			rs = s.executeQuery("SELECT COUNT(*) FROM tsk_files "
					+ "WHERE type = '" + TskData.TSK_DB_FILES_TYPE_ENUM.FS.getFileType() + "' "
					+ "AND dir_type = '" + TskData.TSK_FS_NAME_TYPE_ENUM.REG.getValue() + "' "
					+ "AND md5 IS NULL "
					+ "AND size > '0'");
			rs.next();
			int size = rs.getInt(1);
			if (size == 0) {
				return true;


			}
		} catch (SQLException ex) {
			logger.log(Level.WARNING, "Failed to query for all the files.", ex);
		} finally {
			if (rs != null) {
				try {
					rs.close();
					s.close();


				} catch (SQLException ex) {
					logger.log(Level.WARNING, "Failed to close the result set.", ex);
				}
			}
			dbReadUnlock();
		}
		return false;
	}

	/**
	 * Query all the files and counts how many have an MD5 hash.
	 *
	 * @return the number of files with an MD5 hash
	 */
	public int countFilesMd5Hashed() {
		ResultSet rs = null;
		Statement s = null;
		int count = 0;
		dbReadLock();
		try {
			s = con.createStatement();
			rs = s.executeQuery("SELECT COUNT(*) FROM tsk_files "
					+ "WHERE type = '" + TskData.TSK_DB_FILES_TYPE_ENUM.FS.getFileType() + "' "
					+ "AND dir_type = '" + TskData.TSK_FS_NAME_TYPE_ENUM.REG.getValue() + "' "
					+ "AND md5 IS NOT NULL "
					+ "AND size > '0'");
			rs.next();
			count = rs.getInt(1);


		} catch (SQLException ex) {
			logger.log(Level.WARNING, "Failed to query for all the files.", ex);
		} finally {
			if (rs != null) {
				try {
					rs.close();
					s.close();


				} catch (SQLException ex) {
					logger.log(Level.WARNING, "Failed to close the result set.", ex);
				}
			}
			dbReadUnlock();
		}
		return count;
	}
}
