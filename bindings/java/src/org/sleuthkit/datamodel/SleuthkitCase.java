/*
 * Sleuth Kit Data Model
 *
 * Copyright 2011 Basis Technology Corp.
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

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.*;
import java.util.logging.Level;
import org.sleuthkit.datamodel.TskData.ObjectType;
import java.util.logging.Logger;
import org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE;
import org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE;
import org.sleuthkit.datamodel.SleuthkitJNI.CaseDbHandle.AddImageProcess;
import org.sleuthkit.datamodel.TskData.FileKnown;
import org.sleuthkit.datamodel.TskData.TSK_FS_META_TYPE_ENUM;

/**
 * Highest level object in Sleuthkit hierarchy that represents the database.  
 * Stores one or more Images and children data.
 */
public class SleuthkitCase {

	private String dbPath;
	private String imageDirectory;
	private SleuthkitJNI.CaseDbHandle caseHandle;
	private Connection con;
	private ResultSetHelper rsHelper = new ResultSetHelper(this);
	private int artifactIDcounter = 1001;
	private int attributeIDcounter = 1001;
	private static final Object caseLock = new Object();

	/**
	 * constructor
	 * @param dbPath path to the database
	 * @throws SQLException
	 * @throws ClassNotFoundException
	 */
	private SleuthkitCase(String dbPath, SleuthkitJNI.CaseDbHandle caseHandle) throws SQLException, ClassNotFoundException, TskException {
		Class.forName("org.sqlite.JDBC");
		this.dbPath = dbPath;
		this.caseHandle = caseHandle;
		con = DriverManager.getConnection("jdbc:sqlite:" + dbPath);
		initBlackboardTypes();
	}

	/**
	 * Open an existing case.
	 * @param dbPath Path to SQLite database.
	 * @return Case object
	 */
	public static SleuthkitCase openCase(String dbPath) throws TskException {
		synchronized (caseLock) {
			SleuthkitJNI.CaseDbHandle caseHandle = SleuthkitJNI.openCaseDb(dbPath);
			try {
				return new SleuthkitCase(dbPath, caseHandle);
			} catch (SQLException ex) {
				throw new TskException("Couldn't open case at " + dbPath, ex);
			} catch (ClassNotFoundException ex) {
				throw new TskException("Couldn't open case at " + dbPath, ex);
			}
		}
	}

	/**
	 * Create a new case
	 * @param dbPath Path to where SQlite database should be created.
	 * @return Case object
	 */
	public static SleuthkitCase newCase(String dbPath) throws TskException {
		synchronized (caseLock) {
			SleuthkitJNI.CaseDbHandle caseHandle = SleuthkitJNI.newCaseDb(dbPath);
			try {
				return new SleuthkitCase(dbPath, caseHandle);
			} catch (SQLException ex) {
				throw new TskException("Couldn't open case at " + dbPath, ex);
			} catch (ClassNotFoundException ex) {
				throw new TskException("Couldn't open case at " + dbPath, ex);
			}
		}
	}

	private void initBlackboardTypes() throws SQLException, TskException {
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
	}

	/**
	 * Start process of adding an image to the case. 
	 * Adding an image is a multi-step process and this returns
	 * an object that allows it to happen.
	 * @param timezone TZ timezone string to use for ingest of image.
	 * @return object to start ingest
	 */
	public AddImageProcess makeAddImageProcess(String timezone) {
		synchronized (caseLock) {
			return this.caseHandle.initAddImageProcess(timezone);
		}
	}

	/**
	 * Set the path to NSRL database
	 * @param path Path to database ( not index )
	 */
	public void setNSRLDatabase(String path) throws TskException {
		this.caseHandle.setNSRLDatabase(path);
	}

	/**
	 * Set the path to known bad database
	 * @param path Path to database ( not index )
	 */
	public void setKnownBadDatabase(String path) throws TskException {
		this.caseHandle.setKnownBadDatabase(path);
	}

	public void clearLookupDatabases() throws TskException {
		this.caseHandle.clearLookupDatabases();
	}

//
//	/**
//	 * fills a new file system object with data from the database
//	 * @param vol_id the volume to get the filesystem from
//	 * @return a new file system object
//	 */
//	public FileSystem getFileSystem(long vol_id) throws SQLException{
//		Statement statement;
//		statement = con.createStatement();
//
//		ResultSet rs = statement.executeQuery("select * from tsk_fs_info " +
//				"where vol_id = " + vol_id);
//		if(!rs.next()){
//			rs.close();
//			statement.close();
//			return null;
//		}
//		else{
//			FileSystem fs = new FileSystem(this, rs.getLong("fs_id"), rs.getLong("img_offset"), rs.getLong("vol_id"),
//					rs.getLong("fs_type"), rs.getLong("block_size"), rs.getLong("block_count"),
//					rs.getLong("root_inum"), rs.getLong("first_inum"), rs.getLong("last_inum"));
//			rs.close();
//			statement.close();
//			return fs;
//		}
//	}
//
//	/**
//	 * Gets a new file system object with data from the database
//	 * @param fs_id  the FileSystem ID to get the filesystem from
//	 * @return fs	a new file system object
//	 */
//	public FileSystem getFileSystemFromID(long fs_id) throws SQLException{
//		Statement statement = con.createStatement();
//		ResultSet rs = statement.executeQuery("select * from tsk_fs_info " +
//				"where fs_id = " + fs_id);
//		if(!rs.next()){
//			rs.close();
//			statement.close();
//			return null;
//		}
//		else{
//			FileSystem fs = new FileSystem(this, rs.getLong("fs_id"), rs.getLong("img_offset"), rs.getLong("vol_id"),
//					rs.getLong("fs_type"), rs.getLong("block_size"), rs.getLong("block_count"),
//					rs.getLong("root_inum"), rs.getLong("first_inum"), rs.getLong("last_inum"));
//			return fs;
//		}
//	}
//
//	/**
//	 * fills a new volume object from the database
//	 * @param vol_id volume id
//	 * @return new volume object
//	 */
//	public Volume getVolume(long vol_id) throws SQLException{
//		//get volume info from the database
//		Statement statement;
//		statement = con.createStatement();
//
//		ResultSet rs = statement.executeQuery("select * from tsk_vs_parts " +
//				"where vol_id = " + vol_id);
//		if(!rs.next()){
//			rs.close();
//			statement.close();
//			return null;
//		}
//		else{
//			Volume vol = new Volume(this, rs.getLong("vol_id"), rs.getLong("start"), rs.getLong("length"),
//					rs.getLong("flags"), rs.getString("desc"));
//			rs.close();
//			statement.close();
//			return vol;
//		}
//	}
//
//	/**
//	 * fills a new volume system object from the database
//	 * @param offset offset to the volume system
//	 * @return a new volume system object
//	 */
//	public VolumeSystem getVolumeSystem(long offset) throws SQLException{
//		Statement statement;
//		ArrayList<Long> vol_ids = new ArrayList<Long>();
//		statement = con.createStatement();
//
//		ResultSet rs = statement.executeQuery("select * from tsk_vs_info " +
//				"where img_offset = " + offset);
//		if(!rs.next()){
//			rs.close();
//			statement.close();
//			return null;
//		}
//		else{
//			long type = rs.getLong("vs_type");
//			long imgOffset = rs.getLong("img_offset");
//			long blockSize = rs.getLong("block_size");
//			rs = statement.executeQuery("select vol_id from tsk_vs_parts");
//			if(!rs.next()){
//				rs.close();
//				statement.close();
//				return null;
//			}
//			else{
//				do{
//					vol_ids.add(new Long(rs.getLong("vol_id")));
//				}while(rs.next());
//			}
//			VolumeSystem vs = new VolumeSystem(this, type, imgOffset, blockSize,
//					vol_ids);
//			rs.close();
//			statement.close();
//			return vs;
//		}
//	}
//
//	/**
//	 * get the name of this volume (based on the volume id)
//	 * @param fs_id file system
//	 * @return string with the name
//	 * @throws SQLException
//	 */
//	public String getVolName(long fs_id) throws SQLException{
//		Statement statement;
//		ArrayList<Long> vol_ids = new ArrayList<Long>();
//		statement = con.createStatement();
//
//		ResultSet rs = statement.executeQuery("select vol_id from tsk_fs_info " +
//				"where fs_id = " + fs_id);
//		if(!rs.next()){
//			return null;
//		}
//		else{
//			return "vol" + rs.getLong("vol_id");
//		}
//	}
//
//	/**
//	 * fills a new image object with data from the database
//	 * @param imagePath path to the image
//	 * @return a new image object
//	 */
//	public Image getImage() throws TskException, SQLException{
//		//get image info from the database
//		Statement statement;
//		long type, ssize;
//		String name;
//		ArrayList<String> names = new ArrayList<String>();
//		statement = con.createStatement();
//
//		ResultSet rs = statement.executeQuery("select * from tsk_image_info");
//		if(!rs.next()){
//			rs.close();
//			statement.close();
//			return null;
//		}
//		else{
//			type = rs.getLong("type");
//			ssize = rs.getLong("ssize");
//		}
//		rs = statement.executeQuery("select * from tsk_image_names");
//		if(!rs.next()){
//			rs.close();
//			statement.close();
//			return null;
//		}
//		else{
//			name = rs.getString("name");
//			do{
//				names.add(imageDirectory + "\\" + rs.getString("name"));
//			}while(rs.next());
//
//		}
//
//		Image img = new Image(this, type, ssize, name, names.toArray(new String[names.size()]));
//		rs.close();
//		statement.close();
//		return img;
//	}
//
//
//	/**
//	 * searches the database for files whose parent is the given file
//	 * @param dir_id directory id
//	 * @param fs_id file system to search
//	 * @return an arraylist of fscontent objects
//	 */
//	public ArrayList<FsContent> getChildren(long dir_id, long fs_id, FileSystem parent) throws SQLException{
//		Statement statement = con.createStatement();
//		ArrayList<FsContent> children = new ArrayList<FsContent>();
//		ResultSet rs = statement.executeQuery("SELECT * FROM tsk_fs_files " +
//				"WHERE fs_id = " + fs_id + " AND par_file_id = " + dir_id + " ORDER BY name");
//		if(!rs.next()){
//			rs.close();
//			statement.close();
//			return children;
//		}
//		else{
//			do{
//				String tempName = "";
//
//				tempName = rs.getString("name");
//
//				if (rs.getLong("dir_type") == TSK_FS_NAME_TYPE_ENUM.DIR.getDirType()){
//					Directory dir = new Directory(this, rs.getLong("fs_id"), rs.getLong("file_id"), rs.getLong("attr_type"),
//							rs.getLong("attr_id"), tempName, rs.getLong("par_file_id"), rs.getLong("dir_type"),
//							rs.getLong("meta_type"), rs.getLong("dir_flags"), rs.getLong("meta_flags"), rs.getLong("size"),
//							rs.getLong("ctime"), rs.getLong("crtime"), rs.getLong("atime"), rs.getLong("mtime"),
//							rs.getLong("mode"), rs.getLong("uid"), rs.getLong("gid"));
//					dir.setFileSystem(parent);
//					children.add(dir);
//				}
//				else{
//					File file = new File(this, rs.getLong("fs_id"), rs.getLong("file_id"), rs.getLong("attr_type"),
//							rs.getLong("attr_id"), rs.getString("name"), rs.getLong("par_file_id"), rs.getLong("dir_type"),
//							rs.getLong("meta_type"), rs.getLong("dir_flags"), rs.getLong("meta_flags"), rs.getLong("size"),
//							rs.getLong("ctime"), rs.getLong("crtime"), rs.getLong("atime"), rs.getLong("mtime"),
//							rs.getLong("mode"), rs.getLong("uid"), rs.getLong("gid"));
//					file.setFileSystem(parent);
//					children.add(file);
//				}
//			}while(rs.next());
//		}
//		rs.close();
//		statement.close();
//		return children;
//	}
	/**
	 * Get the list of root objects, meaning image files or local files.
	 * @return list of content objects.
	 */
	public List<Content> getRootObjects() throws TskException {
		Collection<ObjectInfo> infos = new ArrayList<ObjectInfo>();
		try {
			synchronized (caseLock) {
				Statement s = con.createStatement();
				ResultSet rs = s.executeQuery("select obj_id, type from tsk_objects "
						+ "where par_obj_id is NULL");

				while (rs.next()) {
					infos.add(new ObjectInfo(rs.getLong("obj_id"), ObjectType.valueOf(rs.getLong("type"))));
				}
				rs.close();
				s.close();
			}

			List<Content> rootObjs = new ArrayList<Content>();

			for (ObjectInfo i : infos) {
				if (i.type == ObjectType.IMG) {
					rootObjs.add(getImageById(i.id));
				} else {
					throw new TskException("Parentless object has wrong type to be a root: " + i.type);
				}
			}

			return rootObjs;
		} catch (SQLException ex) {
			throw new TskException("Error getting root objects.", ex);
		}
	}

	/**
	 * Get all blackboard artifacts of a given type
	 * @param artifactTypeID artifact type id (must exist in database)
	 * @return list of blackboard artifacts
	 */
	public ArrayList<BlackboardArtifact> getBlackboardArtifacts(int artifactTypeID) throws TskException {
		synchronized (caseLock) {
			String artifactTypeName = this.getArtifactTypeString(artifactTypeID);
			try {
				ArrayList<BlackboardArtifact> artifacts = new ArrayList<BlackboardArtifact>();
				Statement s = con.createStatement();
				ResultSet rs = s.executeQuery("SELECT artifact_id, obj_id FROM blackboard_artifacts WHERE artifact_type_id = " + artifactTypeID);

				while (rs.next()) {
					artifacts.add(new BlackboardArtifact(this, rs.getLong(1), rs.getLong(2),
							artifactTypeID, artifactTypeName, ARTIFACT_TYPE.fromID(artifactTypeID).getDisplayName()));
				}
				rs.close();
				s.close();
				return artifacts;
			} catch (SQLException ex) {
				throw new TskException("Error getting or creating a blackboard artifact. " + ex.getMessage(), ex);
			}
		}
	}

	/**
	 * Get all blackboard artifact types
	 * @return list of blackboard artifact types
	 */
	public ArrayList<BlackboardArtifact.ARTIFACT_TYPE> getBlackboardArtifactTypes() throws TskException {
		synchronized (caseLock) {
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
				throw new TskException("Error getting artifact types. " + ex.getMessage(), ex);
			}
		}
	}

	/**
	 * helper method to get all artifacts matching the type id name and object id
	 * @param artifactTypeID artifact type id
	 * @param artifactTypeName artifact type name
	 * @param obj_id associated object id
	 * @return list of blackboard artifacts
	 * @throws TskException 
	 */
	private ArrayList<BlackboardArtifact> getArtifactsHelper(int artifactTypeID, String artifactTypeName, long obj_id) throws TskException {
		synchronized (caseLock) {
			try {
				ArrayList<BlackboardArtifact> artifacts = new ArrayList<BlackboardArtifact>();
				Statement s = con.createStatement();
				ResultSet rs = s.executeQuery("SELECT artifact_id FROM blackboard_artifacts WHERE obj_id = " + obj_id + " AND artifact_type_id = " + artifactTypeID);

				while (rs.next()) {
					artifacts.add(new BlackboardArtifact(this, rs.getLong(1), obj_id, artifactTypeID, artifactTypeName, this.getArtifactTypeDisplayName(artifactTypeID)));
				}
				rs.close();
				s.close();
				return artifacts;
			} catch (SQLException ex) {
				throw new TskException("Error getting or creating a blackboard artifact. " + ex.getMessage(), ex);
			}
		}
	}

	/**
	 * Get all blackboard artifacts of a given type for the given object id
	 * @param artifactTypeName artifact type name
	 * @param obj_id object id
	 * @return list of blackboard artifacts
	 */
	public ArrayList<BlackboardArtifact> getBlackboardArtifacts(String artifactTypeName, long obj_id) throws TskException {
		int artifactTypeID = this.getArtifactTypeID(artifactTypeName);
		return getArtifactsHelper(artifactTypeID, artifactTypeName, obj_id);
	}

	/**
	 * Get all blackboard artifacts of a given type for the given object id
	 * @param artifactTypeID artifact type id (must exist in database)
	 * @param obj_id object id
	 * @return list of blackboard artifacts
	 */
	public ArrayList<BlackboardArtifact> getBlackboardArtifacts(int artifactTypeID, long obj_id) throws TskException {
		String artifactTypeName = this.getArtifactTypeString(artifactTypeID);

		return getArtifactsHelper(artifactTypeID, artifactTypeName, obj_id);
	}

	/**
	 * Get all blackboard artifacts of a given type for the given object id
	 * @param artifactType artifact type enum
	 * @param obj_id object id
	 * @return list of blackboard artifacts
	 */
	public ArrayList<BlackboardArtifact> getBlackboardArtifacts(ARTIFACT_TYPE artifactType, long obj_id) throws TskException {
		return getArtifactsHelper(artifactType.getTypeID(), artifactType.getLabel(), obj_id);
	}

	/**
	 * Get the blackboard artifact with the given artifact id
	 * @param artifactID artifact ID
	 * @return blackboard artifact
	 */
	public BlackboardArtifact getBlackboardArtifact(long artifactID) throws TskException {
		synchronized (caseLock) {
			try {
				Statement s = con.createStatement();
				ResultSet rs;

				rs = s.executeQuery("SELECT obj_id, artifact_type_id FROM blackboard_artifacts WHERE artifact_id = " + artifactID);
				long obj_id = rs.getLong(1);
				int artifact_type_id = rs.getInt(2);

				rs.close();
				s.close();
				return new BlackboardArtifact(this, artifactID, obj_id, artifact_type_id, this.getArtifactTypeString(artifact_type_id), this.getArtifactTypeDisplayName(artifact_type_id));

			} catch (SQLException ex) {
				throw new TskException("Error getting a blackboard artifact. " + ex.getMessage(), ex);
			}
		}
	}

	/**
	 * Add a blackboard attribute. All information for the attribute should be in the given attribute
	 * @param attr a blackboard attribute. All necessary information should be filled in.
	 */
	public void addBlackboardAttribute(BlackboardAttribute attr) throws TskException {
		synchronized (caseLock) {
			try {
				Statement s = con.createStatement();
				switch (attr.getValueType()) {
					case STRING:
						s.executeUpdate("INSERT INTO blackboard_attributes (artifact_id, source, context, attribute_type_id, value_type, value_text) VALUES ("
								+ attr.getArtifactID() + ", '" + attr.getModuleName() + "', '" + attr.getContext() + "', " + attr.getAttributeTypeID() + ", " + attr.getValueType().getType() + ", '" + attr.getValueString() + "')");
						break;
					case BYTE:
						PreparedStatement ps = con.prepareStatement("INSERT INTO blackboard_attributes (artifact_id, source, context, attribute_type_id, value_type, value_byte) VALUES ("
								+ attr.getArtifactID() + ", '" + attr.getModuleName() + "', '" + attr.getContext() + "', " + attr.getAttributeTypeID() + ", " + attr.getValueType().getType() + ", ?)");
						ps.setBytes(1, attr.getValueBytes());
						ps.executeUpdate();
						ps.close();
						break;
					case INTEGER:
						s.executeUpdate("INSERT INTO blackboard_attributes (artifact_id, source, context, attribute_type_id, value_type, value_int32) VALUES ("
								+ attr.getArtifactID() + ", '" + attr.getModuleName() + "', '" + attr.getContext() + "', " + attr.getAttributeTypeID() + ", " + attr.getValueType().getType() + ", " + attr.getValueInt() + ")");
						break;
					case LONG:
						s.executeUpdate("INSERT INTO blackboard_attributes (artifact_id, source, context, attribute_type_id, value_type, value_int64) VALUES ("
								+ attr.getArtifactID() + ", '" + attr.getModuleName() + "', '" + attr.getContext() + "', " + attr.getAttributeTypeID() + ", " + attr.getValueType().getType() + ", " + attr.getValueLong() + ")");
						break;
					case DOUBLE:
						s.executeUpdate("INSERT INTO blackboard_attributes (artifact_id, source, context, attribute_type_id, value_type, value_double) VALUES ("
								+ attr.getArtifactID() + ", '" + attr.getModuleName() + "', '" + attr.getContext() + "', " + attr.getAttributeTypeID() + ", " + attr.getValueType().getType() + ", " + attr.getValueDouble() + ")");
						break;
				}
				s.close();
			} catch (SQLException ex) {
				throw new TskException("Error getting or creating a blackboard artifact.", ex);
			}
		}
	}

	/**
	 * Add a blackboard attributes in bulk. All information for the attribute should be in the given attribute
	 * @param attributes collection of blackboard attributes. All necessary information should be filled in.
	 */
	public void addBlackboardAttributes(Collection<BlackboardAttribute> attributes) throws TskException {
		synchronized (caseLock) {
			try {
				con.setAutoCommit(false);
			} catch (SQLException ex) {
				throw new TskException("Error creating transaction, no attributes created.", ex);
			}
			for (BlackboardAttribute attr : attributes) {
				PreparedStatement ps = null;
				try {
					switch (attr.getValueType()) {
						case STRING:
							ps = con.prepareStatement("INSERT INTO blackboard_attributes (artifact_id, source, context, attribute_type_id, value_type, value_text) VALUES ("
									+ attr.getArtifactID() + ", '" + attr.getModuleName() + "', '" + attr.getContext() + "', " + attr.getAttributeTypeID() + ", " + attr.getValueType().getType() + ", '" + attr.getValueString() + "')");
							break;
						case BYTE:
							ps = con.prepareStatement("INSERT INTO blackboard_attributes (artifact_id, source, context, attribute_type_id, value_type, value_byte) VALUES ("
									+ attr.getArtifactID() + ", '" + attr.getModuleName() + "', '" + attr.getContext() + "', " + attr.getAttributeTypeID() + ", " + attr.getValueType().getType() + ", ?)");
							ps.setBytes(1, attr.getValueBytes());
							break;
						case INTEGER:
							ps = con.prepareStatement("INSERT INTO blackboard_attributes (artifact_id, source, context, attribute_type_id, value_type, value_int32) VALUES ("
									+ attr.getArtifactID() + ", '" + attr.getModuleName() + "', '" + attr.getContext() + "', " + attr.getAttributeTypeID() + ", " + attr.getValueType().getType() + ", " + attr.getValueInt() + ")");
							break;
						case LONG:
							ps = con.prepareStatement("INSERT INTO blackboard_attributes (artifact_id, source, context, attribute_type_id, value_type, value_int64) VALUES ("
									+ attr.getArtifactID() + ", '" + attr.getModuleName() + "', '" + attr.getContext() + "', " + attr.getAttributeTypeID() + ", " + attr.getValueType().getType() + ", " + attr.getValueLong() + ")");
							break;
						case DOUBLE:
							ps = con.prepareStatement("INSERT INTO blackboard_attributes (artifact_id, source, context, attribute_type_id, value_type, value_double) VALUES ("
									+ attr.getArtifactID() + ", '" + attr.getModuleName() + "', '" + attr.getContext() + "', " + attr.getAttributeTypeID() + ", " + attr.getValueType().getType() + ", " + attr.getValueDouble() + ")");
							break;
					}
					ps.executeUpdate();
					ps.close();
				} catch (SQLException ex) {
					throw new TskException("Error creating a blackboard artifact.", ex);
				}

			}

			//commit transaction
			try {
				con.commit();
			} catch (SQLException ex) {
				throw new TskException("Error committing transaction, no attributes created.", ex);
			} finally {
				try {
					con.setAutoCommit(true);
				} catch (SQLException ex) {
					throw new TskException("Error setting autocommit and closing the transaction!", ex);
				}
			}

		}
	}

	/**
	 * add an attribute type with the given name
	 * @param attrTypeString name of the new attribute
	 * @return the id of the new attribute
	 * @throws TskException 
	 */
	public int addAttrType(String attrTypeString, String displayName) throws TskException {
		addAttrType(attrTypeString, displayName, attributeIDcounter);
		int retval = attributeIDcounter;
		attributeIDcounter++;
		return retval;

	}

	/**
	 * helper method. add an attribute type with the given name and id
	 * @param attrTypeString type name
	 * @param typeID type id
	 * @throws TskException 
	 */
	private void addAttrType(String attrTypeString, String displayName, int typeID) throws TskException {
		synchronized (caseLock) {
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
					throw new TskException("Attribute with that name already exists");
				}
			} catch (SQLException ex) {
				throw new TskException("Error getting attribute type id.", ex);
			}
		}

	}

	/**
	 * Get the attribute id that corresponds to the given string. If that string does not exist
	 * it will be added to the table.
	 * @param attrTypeString attribute type string
	 * @return attribute id
	 */
	public int getAttrTypeID(String attrTypeString) throws TskException {
		synchronized (caseLock) {
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
					throw new TskException("No id with that name");
				}
			} catch (SQLException ex) {
				throw new TskException("Error getting attribute type id.", ex);
			}
		}
	}

	/**
	 * Get the string associated with the given id. Will throw an error if that id does not exist
	 * @param attrTypeID attribute id
	 * @return string associated with the given id
	 */
	public String getAttrTypeString(int attrTypeID) throws TskException {
		synchronized (caseLock) {
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
					throw new TskException("No type with that id.");
				}

			} catch (SQLException ex) {
				throw new TskException("Error getting or creating a attribute type name.", ex);
			}
		}
	}

	/**
	 * Get the display name for the attribute with the given id. Will throw an error if that id does not exist
	 * @param attrTypeID attribute id
	 * @return string associated with the given id
	 */
	public String getAttrTypeDisplayName(int attrTypeID) throws TskException {
		synchronized (caseLock) {
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
					throw new TskException("No type with that id.");
				}

			} catch (SQLException ex) {
				throw new TskException("Error getting or creating a attribute type name.", ex);
			}
		}
	}

	/**
	 * Get artifact type id for the given string. Will throw an error if one with that
	 * name does not exist.
	 * @param artifactTypeString name for an artifact type
	 * @return artifact type
	 */
	int getArtifactTypeID(String artifactTypeString) throws TskException {
		synchronized (caseLock) {
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
					throw new TskException("No artifact with that name exists");
				}

			} catch (SQLException ex) {
				throw new TskException("Error getting artifact type id." + ex.getMessage(), ex);
			}
		}
	}

	/**
	 * Get artifact type name for the given string. Will throw an error if that artifact doesn't
	 * exist. Use addArtifactType(...) to create a new one.
	 * @param artifactTypeID id for an artifact type
	 * @return name of that artifact type
	 */
	String getArtifactTypeString(int artifactTypeID) throws TskException {
		synchronized (caseLock) {
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
					throw new TskException("Error: no artifact with that name in database");
				}

			} catch (SQLException ex) {
				throw new TskException("Error getting artifact type id.", ex);
			}
		}
	}

	/**
	 * Get artifact type display name for the given string. Will throw an error if that artifact doesn't
	 * exist. Use addArtifactType(...) to create a new one.
	 * @param artifactTypeID id for an artifact type
	 * @return display name of that artifact type
	 */
	String getArtifactTypeDisplayName(int artifactTypeID) throws TskException {
		synchronized (caseLock) {
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
					throw new TskException("Error: no artifact with that name in database");
				}

			} catch (SQLException ex) {
				throw new TskException("Error getting artifact type id.", ex);
			}
		}
	}

	/**
	 * Add an artifact type with the given name. Will return an id that can be used
	 * to look that artifact type up.
	 * @param artifactTypeID id for an artifact type
	 * @return name of that artifact type
	 */
	public int addArtifactType(String artifactTypeName, String displayName) throws TskException {
		addArtifactType(artifactTypeName, displayName, artifactIDcounter);
		int retval = artifactIDcounter;
		artifactIDcounter++;
		return retval;
	}

	/**
	 * helper method. add an artifact with the given type and id
	 * @param artifactTypeName type name
	 * @param typeID type id
	 * @throws TskException 
	 */
	private void addArtifactType(String artifactTypeName, String displayName, int typeID) throws TskException {
		synchronized (caseLock) {
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
					throw new TskException("Artifact with that name already exists");
				}
			} catch (SQLException ex) {
				throw new TskException("Error adding artifact type.", ex);
			}
		}
	}

	/**
	 * Get all attributes that match a where clause. The clause should begin with
	 * "WHERE" or "JOIN". To use this method you must know the database tables
	 * @param whereClause a sqlite where clause
	 * @return a list of matching attributes
	 */
	public ArrayList<BlackboardAttribute> getMatchingAttributes(String whereClause) throws TskException {
		ArrayList<BlackboardAttribute> matches = new ArrayList<BlackboardAttribute>();
		try {
			Statement s;
			synchronized (caseLock) {
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
			}
			return matches;
		} catch (SQLException ex) {
			throw new TskException("Error getting attributes. using this where clause: " + whereClause, ex);
		}
	}

	/**
	 * Get all artifacts that match a where clause. The clause should begin with
	 * "WHERE" or "JOIN". To use this method you must know the database tables
	 * @param whereClause a sqlite where clause
	 * @return a list of matching artifacts
	 */
	public ArrayList<BlackboardArtifact> getMatchingArtifacts(String whereClause) throws TskException {
		ArrayList<BlackboardArtifact> matches = new ArrayList<BlackboardArtifact>();
		try {
			Statement s;
			synchronized (caseLock) {
				s = con.createStatement();

				ResultSet rs = s.executeQuery("Select artifact_id, obj_id, artifact_type_id FROM blackboard_artifacts " + whereClause);

				while (rs.next()) {
					BlackboardArtifact artifact = new BlackboardArtifact(this, rs.getLong(1), rs.getLong(2), rs.getInt(3), this.getArtifactTypeString(rs.getInt(3)), this.getArtifactTypeDisplayName(rs.getInt(3)));
					matches.add(artifact);
				}
				rs.close();
				s.close();
			}
			return matches;
		} catch (SQLException ex) {
			throw new TskException("Error getting attributes. using this where clause: " + whereClause, ex);
		}
	}

	/**
	 * Add a new blackboard artifact with the given type. If that artifact type does not
	 * exist an error will be thrown. The artifact typename can be looked up in the 
	 * returned blackboard artifact
	 * @param artifactTypeID the type the given artifact should have
	 * @return a new blackboard artifact
	 */
	BlackboardArtifact newBlackboardArtifact(int artifactTypeID, long obj_id) throws TskException {
		synchronized (caseLock) {
			try {
				Statement s = con.createStatement();

				String artifactTypeName = this.getArtifactTypeString(artifactTypeID);
				String artifactDisplayName = this.getArtifactTypeDisplayName(artifactTypeID);

				long artifactID = -1;
				s.executeUpdate("INSERT INTO blackboard_artifacts (artifact_id, obj_id, artifact_type_id) VALUES (NULL, " + obj_id + ", " + artifactTypeID + ")");
				ResultSet rs = s.executeQuery("SELECT artifact_id from blackboard_artifacts WHERE obj_id = " + obj_id + " AND + artifact_type_id = " + artifactTypeID);
				while (rs.next()) {
					if (rs.getLong(1) > artifactID) {
						artifactID = rs.getLong(1);
					}
				}
				rs.close();
				s.close();
				return new BlackboardArtifact(this, artifactID, obj_id, artifactTypeID, artifactTypeName, artifactDisplayName);

			} catch (SQLException ex) {
				throw new TskException("Error getting or creating a blackboard artifact. " + ex.getMessage(), ex);
			}
		}
	}

	/**
	 * Add a new blackboard artifact with the given type. 
	 * @param artifactType the type the given artifact should have
	 * @return a new blackboard artifact
	 */
	BlackboardArtifact newBlackboardArtifact(ARTIFACT_TYPE artifactType, long obj_id) throws TskException {
		synchronized (caseLock) {
			try {
				Statement s = con.createStatement();
				ResultSet rs;
				int type = artifactType.getTypeID();

				long artifactID = -1;
				s.executeUpdate("INSERT INTO blackboard_artifacts (artifact_id, obj_id, artifact_type_id) VALUES (NULL, " + obj_id + ", " + type + ")");
				rs = s.executeQuery("SELECT artifact_id from blackboard_artifacts WHERE obj_id = " + obj_id + " AND + artifact_type_id = " + type);
				while (rs.next()) {
					if (rs.getLong(1) > artifactID) {
						artifactID = rs.getLong(1);
					}
				}
				rs.close();
				s.close();
				return new BlackboardArtifact(this, artifactID, obj_id, type, artifactType.getLabel(), artifactType.getDisplayName());

			} catch (SQLException ex) {
				throw new TskException("Error getting or creating a blackboard artifact. " + ex.getMessage(), ex);
			}
		}
	}

	/**
	 * add one of the built in artifact types
	 * @param type type enum
	 * @throws TskException 
	 */
	private void addBuiltInArtifactType(ARTIFACT_TYPE type) throws TskException {
		addArtifactType(type.getLabel(), type.getDisplayName(), type.getTypeID());
	}

	/**
	 * add one of the built in attribute types
	 * @param type type enum
	 * @throws TskException 
	 */
	private void addBuiltInAttrType(ATTRIBUTE_TYPE type) throws TskException {
		addAttrType(type.getLabel(), type.getDisplayName(), type.getTypeID());
	}

	/** 
	 * Stores a pair of object ID and its type 
	 */
	private static class ObjectInfo {

		long id;
		TskData.ObjectType type;

		ObjectInfo(long id, ObjectType type) {
			this.id = id;
			this.type = type;
		}
	}

	/**
	 * Get info about children of a given Content from the database.
	 * @param c Parent object to run query against
	 */
	Collection<ObjectInfo> getChildrenInfo(Content c) throws SQLException {
		synchronized (caseLock) {
			Statement s = con.createStatement();
			ResultSet rs = s.executeQuery("select obj_id, type from tsk_objects "
					+ "where par_obj_id = " + c.getId());

			Collection<ObjectInfo> infos = new ArrayList<ObjectInfo>();

			while (rs.next()) {
				infos.add(new ObjectInfo(rs.getLong("obj_id"), ObjectType.valueOf(rs.getLong("type"))));
			}
			rs.close();
			s.close();
			return infos;
		}
	}

	ObjectInfo getParentInfo(Content c) throws SQLException, TskException {
		synchronized (caseLock) {
			Statement s = con.createStatement();
			ResultSet rs = s.executeQuery("SELECT parent.obj_id, parent.type "
					+ "FROM tsk_objects AS parent JOIN tsk_objects AS child "
					+ "ON child.par_obj_id = parent.obj_id "
					+ "WHERE child.obj_id = " + c.getId());

			ObjectInfo info;

			if (rs.next()) {
				info = new ObjectInfo(rs.getLong("obj_id"), ObjectType.valueOf(rs.getLong("type")));
				rs.close();
				s.close();
				return info;
			} else {
				rs.close();
				s.close();
				throw new TskException("Given content (id: " + c.getId() + ") has no parent.");
			}
		}
	}

	Directory getParentDirectory(FsContent fsc) throws SQLException, TskException {
		if (fsc.isRoot()) {
			throw new TskException("Given FsContent (id: " + fsc.getId() + ") is a root object (can't have parent directory).");
		} else {
			ObjectInfo parentInfo = getParentInfo(fsc);

			Directory parent;

			if (parentInfo.type == ObjectType.FILE) {
				parent = getDirectoryById(parentInfo.id, fsc.getFileSystem());
			} else {
				throw new TskException("Parent of FsContent (id: " + fsc.getId() + ") has wrong type to be directory: " + parentInfo.type);
			}

			return parent;
		}
	}

	public File getFileById(long id) throws SQLException, TskException {
		synchronized (caseLock) {
			Statement s = con.createStatement();

			ResultSet rs = s.executeQuery("select * from tsk_files where obj_id = " + id);
			FsContent temp = null;
			List<FsContent> results;
			if ((results = resultSetToFsContents(rs)).size() > 0) {
				s.close();
				if ((temp = results.get(0)).isFile()) {
					return (File) temp;
				} else {
					throw new TskException("Query returned non-file FsContent");
				}
			} else {
				s.close();
			}
		}
		throw new TskException("No file found for id " + id);
	}

	public Image getImageById(long id) throws SQLException, TskException {
		synchronized (caseLock) {
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
				throw new TskException("No image found for id: " + id);
			}
			rs1.close();
			s1.close();
			return temp;
		}
	}

	VolumeSystem getVolumeSystemById(long id, Image parent) throws SQLException, TskException {
		synchronized (caseLock) {
			Statement s = con.createStatement();

			ResultSet rs = s.executeQuery("select * from tsk_vs_info "
					+ "where obj_id = " + id);
			VolumeSystem temp;

			if (rs.next()) {
				temp = rsHelper.volumeSystem(rs, parent);
			} else {
				rs.close();
				s.close();
				throw new TskException("No volume system found for id:" + id);
			}
			rs.close();
			s.close();
			return temp;
		}
	}

	FileSystem getFileSystemById(long id, FileSystemParent parent) throws SQLException, TskException {
		synchronized (caseLock) {
			Statement s = con.createStatement();
			FileSystem temp;

			ResultSet rs = s.executeQuery("select * from tsk_fs_info "
					+ "where obj_id = " + id);

			if (rs.next()) {
				temp = rsHelper.fileSystem(rs, parent);
			} else {
				rs.close();
				s.close();
				throw new TskException("No file system found for id:" + id);
			}
			rs.close();
			s.close();

			return temp;
		}
	}

	Volume getVolumeById(long id, VolumeSystem parent) throws SQLException, TskException {
		synchronized (caseLock) {
			Statement s = con.createStatement();
			Volume temp;

			ResultSet rs = s.executeQuery("select * from tsk_vs_parts "
					+ "where obj_id = " + id);

			if (rs.next()) {
				temp = rsHelper.volume(rs, parent);
			} else {
				rs.close();
				s.close();
				throw new TskException("No volume found for id:" + id);
			}
			rs.close();
			s.close();
			return temp;
		}
	}

	Directory getDirectoryById(long id, FileSystem parentFs) throws SQLException, TskException {
		synchronized (caseLock) {
			Statement s = con.createStatement();
			Directory temp;

			ResultSet rs = s.executeQuery("select * from tsk_files "
					+ "where obj_id = " + id);

			if (rs.next() && rs.getLong("meta_type") == TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_DIR.getMetaType()) {
				temp = rsHelper.directory(rs, parentFs);
			} else {
				rs.close();
				s.close();
				throw new TskException("No Directory found for id:" + id);
			}
			rs.close();
			s.close();
			return temp;
		}
	}

	/**
	 * Initializes the entire heritage of the visited Content.
	 */
	private class SetParentVisitor implements ContentVisitor<Void> {

		SetParentVisitor() {
		}
		// make File/Directory visits (majority of cases) faster by caching 
		// fully initialized parent FileSystems
		Map<Long, FileSystem> fileSystemCache = new HashMap<Long, FileSystem>();

		private void visitFsContent(FsContent fc) {
			try {
				long fileSystemId = fc.fs_obj_id;
				FileSystem parent = fileSystemCache.get(fileSystemId);
				if (parent == null) {
					parent = getFileSystemById(fileSystemId, null);
					parent.accept(this);
					fileSystemCache.put(fileSystemId, parent);
				}
				fc.setFileSystem(parent);
			} catch (SQLException ex) {
				throw new RuntimeException(ex);
			} catch (TskException ex) {
				throw new RuntimeException(ex);
			}
		}

		@Override
		public Void visit(Directory d) {
			visitFsContent(d);
			return null;
		}

		@Override
		public Void visit(File f) {
			visitFsContent(f);
			return null;
		}

		@Override
		public Void visit(FileSystem fs) {
			try {
				ObjectInfo parentInfo = getParentInfo(fs);
				FileSystemParent parent;
				if (parentInfo.type == ObjectType.IMG) {
					parent = getImageById(parentInfo.id);
				} else if (parentInfo.type == ObjectType.VOL) {
					parent = getVolumeById(parentInfo.id, null);
				} else {
					throw new IllegalStateException("Parent has wrong type to be FileSystemParent: " + parentInfo.type);
				}
				fs.setParent(parent);
				parent.accept(this);
			} catch (SQLException ex) {
				throw new RuntimeException(ex);
			} catch (TskException ex) {
				throw new RuntimeException(ex);
			}
			return null;
		}

		@Override
		public Void visit(Image i) {
			// images are currently parentless 
			return null;
		}

		@Override
		public Void visit(Volume v) {
			try {
				ObjectInfo parentInfo = getParentInfo(v);
				VolumeSystem parent;
				if (parentInfo.type == ObjectType.VS) {
					parent = getVolumeSystemById(parentInfo.id, null);
				} else {
					throw new IllegalStateException("Parent has wrong type to be VolumeSystem: " + parentInfo.type);
				}
				v.setParent(parent);
				parent.accept(this);
			} catch (SQLException ex) {
				throw new RuntimeException(ex);
			} catch (TskException ex) {
				throw new RuntimeException(ex);
			}
			return null;
		}

		@Override
		public Void visit(VolumeSystem vs) {
			try {
				ObjectInfo parentInfo = getParentInfo(vs);
				Image parent;
				if (parentInfo.type == ObjectType.IMG) {
					parent = getImageById(parentInfo.id);
				} else {
					throw new IllegalStateException("Parent has wrong type to be Image: " + parentInfo.type);
				}
				vs.setParent(parent);
				parent.accept(this);
			} catch (SQLException ex) {
				throw new RuntimeException(ex);
			} catch (TskException ex) {
				throw new RuntimeException(ex);
			}
			return null;
		}
	}

	/**
	 * Helper to return FileSystems in an Image
	 * @param image Image to lookup FileSystem for
	 * @return Collection of FileSystems in the image
	 */
	public Collection<FileSystem> getFileSystems(Image image) {
		return new GetFileSystemsVisitor().visit(image);
	}

	/**
	 * top-down FileSystem visitor to be be visited on parent of FileSystem
	 * and return a Collection<FileSystem> for that parent
	 * visiting children of FileSystem is not supported
	 */
	private static class GetFileSystemsVisitor implements
			ContentVisitor<Collection<FileSystem>> {

		@Override
		public Collection<FileSystem> visit(Directory directory) {
			//should never get here
			return null;
		}

		@Override
		public Collection<FileSystem> visit(File file) {
			//should never get here
			return null;
		}

		@Override
		public Collection<FileSystem> visit(FileSystem fs) {
			Collection<FileSystem> col = new ArrayList<FileSystem>();
			col.add(fs);
			return col;
		}

		@Override
		public Collection<FileSystem> visit(Image image) {
			return getAllFromChildren(image);
		}

		@Override
		public Collection<FileSystem> visit(Volume volume) {
			return getAllFromChildren(volume);
		}

		@Override
		public Collection<FileSystem> visit(VolumeSystem vs) {
			return getAllFromChildren(vs);
		}

		private Collection<FileSystem> getAllFromChildren(Content parent) {
			Collection<FileSystem> all = new ArrayList<FileSystem>();

			try {
				for (Content child : parent.getChildren()) {
					all.addAll(child.accept(this));
				}
			} catch (TskException ex) {
			}

			return all;
		}
	}

	/**
	 * Returns the list of children for a given Image
	 */
	List<Content> getImageChildren(Image img) throws SQLException, TskException {
		Collection<ObjectInfo> childInfos = getChildrenInfo(img);

		List<Content> children = new ArrayList<Content>(childInfos.size());

		for (ObjectInfo info : childInfos) {

			if (info.type == ObjectType.VS) {
				children.add(getVolumeSystemById(info.id, img));
			} else if (info.type == ObjectType.FS) {
				children.add(getFileSystemById(info.id, img));
			} else {
				throw new TskException("Image has child of invalid type: " + info.type);
			}
		}

		return children;
	}

	/**
	 * Returns the list of children for a given VolumeSystem
	 */
	List<Content> getVolumeSystemChildren(VolumeSystem vs) throws SQLException, TskException {
		Collection<ObjectInfo> childInfos = getChildrenInfo(vs);

		List<Content> children = new ArrayList<Content>(childInfos.size());

		for (ObjectInfo info : childInfos) {

			if (info.type == ObjectType.VOL) {
				children.add(getVolumeById(info.id, vs));
			} else {
				throw new TskException("VolumeSystem has child of invalid type: " + info.type);
			}
		}

		return children;
	}

	/**
	 * Returns a list of children for a given Volume
	 */
	List<Content> getVolumeChildren(Volume vol) throws SQLException, TskException {
		Collection<ObjectInfo> childInfos = getChildrenInfo(vol);

		List<Content> children = new ArrayList<Content>(childInfos.size());

		for (ObjectInfo info : childInfos) {
			if (info.type == ObjectType.FS) {
				children.add(getFileSystemById(info.id, vol));
			} else {
				throw new TskException("Volume has child of invalid type: " + info.type);
			}
		}

		return children;
	}

	/**
	 * Returns a list of children for a given file system
	 */
	List<Content> getFileSystemChildren(FileSystem fs) throws SQLException {
		return getChildFsContents(fs.getId(), fs);
	}

	/**
	 * Returns a list of children for a given file system or directory
	 * @param par_obj_id Parent ID
	 */
	List<Content> getChildFsContents(long par_obj_id, FileSystem parentFs) throws SQLException {
		List<Content> children = new ArrayList<Content>();
		synchronized (caseLock) {
			Statement s = con.createStatement();
			ResultSet rs = s.executeQuery("select tsk_files.* from tsk_files join "
					+ "tsk_objects on tsk_files.obj_id = tsk_objects.obj_id "
					+ "where par_obj_id = " + par_obj_id + " order by name asc");


			while (rs.next()) {
				if (rs.getLong("meta_type") == TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_DIR.getMetaType()) {
					children.add(rsHelper.directory(rs, parentFs));
				} else {
					children.add(rsHelper.file(rs, parentFs));
				}
			}
			rs.close();
			s.close();
		}
		return children;
	}

	/**
	 * Returns a list of children for a given directory
	 */
	List<Content> getDirectoryChildren(Directory dir) throws SQLException {
		return getChildFsContents(dir.getId(), dir.getFileSystem());
	}

//	
//	/**
//	 * searches the database for files whose parent is the given file
//	 * @param dir_id directory id
//	 * @param fs_id file system to search
//	 * @return an arraylist of file ids
//	 */
//	public ArrayList<Long> getChildIds(long dir_id, long fs_id) throws SQLException{
//		Statement statement = con.createStatement();
//		ArrayList<Long> childIds = new ArrayList<Long>();
//		ResultSet rs = statement.executeQuery("SELECT file_id FROM tsk_fs_files " +
//				"WHERE fs_id = " + fs_id + " AND par_file_id = " + dir_id);
//		if(!rs.next()){
//			rs.close();
//			statement.close();
//			return childIds;
//		}
//		else{
//			do{
//				childIds.add(rs.getLong("file_id"));
//			}while(rs.next());
//		}
//		rs.close();
//		statement.close();
//		return childIds;
//	}
//
//
//	/**
//	 * get the names of the child files and directories. important for differentiating
//	 * between directories and . and .. directories
//	 * @param dir_id directory id
//	 * @param fs_id file system to search
//	 * @return an arraylist of names
//	 */
//	public ArrayList<String> getChildNames(long dir_id, long fs_id) throws SQLException {
//		Statement statement = con.createStatement();
//		ArrayList<String> childIds = new ArrayList<String>();
//		ResultSet rs = statement.executeQuery("SELECT name FROM tsk_fs_files " +
//				"WHERE fs_id = " + fs_id + " AND par_file_id = " + dir_id);
//		if(!rs.next()){
//			rs.close();
//			statement.close();
//			return childIds;
//		}
//		else{
//			do{
//				childIds.add(rs.getString("name"));
//			}while(rs.next());
//		}
//		rs.close();
//		statement.close();
//		return childIds;
//	}
	/**
	 * Creates FsContents from a SQL query result set of rows from the tsk_files
	 * table.  Assumes that the query was of the form
	 * "SELECT * FROM tsk_files WHERE XYZ".
	 * @param rs ResultSet to get content from. Caller is responsible for closing it.
	 * @return A List<FsContent> containing the results
	 * @throws SQLException  
	 */
	public List<FsContent> resultSetToFsContents(ResultSet rs) throws SQLException {
		SetParentVisitor setParent = new SetParentVisitor();
		ArrayList<FsContent> results = new ArrayList<FsContent>();

		synchronized (caseLock) {
			while (rs.next()) {
				FsContent result;
				if (rs.getLong("meta_type") == TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_DIR.getMetaType()) {
					result = rsHelper.directory(rs, null);
				} else {
					result = rsHelper.file(rs, null);
				}
				result.accept(setParent);
				results.add(result);
			}
		}

		return results;
	}

	/**
	 * Process a query on the database to find files of a given criteria.
	 * resultSetToFsContents will convert the results to useful objects.
	 * Requires subsequent call to closeRunQuery()
	 *
	 * @param query  the given string query to run
	 * @return	   the resultSet from running the query. 
	 * Caller should call closeRunQuery(resultSet) as soon as possible, when done with retrieving data from the resultSet
	 * @throws SQLException
	 */
	public ResultSet runQuery(String query) throws SQLException {
		Statement statement;
		synchronized (caseLock) {
			statement = con.createStatement();
			ResultSet rs = statement.executeQuery(query);
			return rs;
		}
	}

	/**
	 * Closes ResultSet and its Statement previously retrieved from runQuery()
	 * 
	 * @param resultSet with its Statement to close
	 * @throws SQLException 
	 */
	public void closeRunQuery(ResultSet resultSet) throws SQLException {
		synchronized (caseLock) {
			final Statement statement = resultSet.getStatement();
			resultSet.close();
			if (statement != null) {
				statement.close();
			}
		}
	}

	@Override
	public void finalize() {
		close();
	}

	/**
	 * Closes the database connection of this instance.
	 */
	private void closeConnection() {
		try {
			synchronized (caseLock) {
				if (con != null) {
					con.close();
					con = null;
				}
			}
		} catch (SQLException e) {
			// connection close failed.
			System.err.println(e);
		}
	}

	/**
	 * Call to free resources when done with instance.
	 */
	public void close() {
		System.err.println(this.hashCode() + " closed");
		System.err.flush();
		synchronized (caseLock) {
			this.closeConnection();
			try {
				if (this.caseHandle != null) {
					this.caseHandle.free();
					this.caseHandle = null;
				}
			} catch (TskException ex) {
				Logger.getLogger(SleuthkitCase.class.getName()).log(Level.WARNING,
						"Error freeing case handle.", ex);
			}
		}
	}

	/**
	 * Update the given hash and known status of the object in the DB denoted by id
	 * 
	 * @param id		The object's unique ID in the database
	 * @param md5Hash	The object's calculated md5 hash
	 * @param fileKnown	The object's known status
	 * @throws SQLException
	 */
	private void updateHashAndKnown(long id, String md5Hash, FileKnown fileKnown) throws SQLException {
		synchronized (caseLock) {
			Statement s = con.createStatement();
			s.executeUpdate("UPDATE tsk_files "
					+ "SET known='" + fileKnown.toLong() + "', md5='" + md5Hash + "' "
					+ "WHERE obj_id=" + id);
			s.close();
		}
	}

//	Useful if we want to queue sql updates for performance reasons
//	/**
//	 * Update the given hash and known status of the objects in the DB denoted by id
//	 * 
//	 * @param ids		The objects' unique IDs in the database
//	 * @param md5Hashes	The objects' calculated md5 hashes
//	 * @param knowns	The objects' known statuses
//	 * @throws SQLException
//	 */
//	private void updateHashesAndKnowns(List<Long> ids, List<String> md5Hashes, List<Long> knowns) throws SQLException{
//		int idsSize = ids.size();
//		int md5sSize = md5Hashes.size();
//		int knownsSize = knowns.size();
//		if(idsSize == md5sSize && md5sSize == knownsSize && knownsSize == idsSize){
//			StringBuilder query = new StringBuilder("UPDATE tsk_files SET known = CASE obj_id");
//			for(int i = 0; i<idsSize; i++){
//				// " WHEN id THEN known"
//				query.append(" WHEN ").append(ids.get(i))
//					 .append(" THEN ").append(knowns.get(i));
//			}
//			query.append(" END, md5 = CASE obj_id");
//			for(int i = 0; i<idsSize; i++){
//				// " WHEN id THEN hash"
//				query.append(" WHEN ").append(ids.get(i))
//				     .append(" THEN '").append(md5Hashes.get(i)).append("'");
//			}
//			query.append(" END WHERE id in (");
//			for(int i = 0; i<idsSize; i++){
//				// "1,2,3,4,"
//				query.append(ids.get(i)).append(",");
//			}
//			// remove the last unnecessary comma
//			query.deleteCharAt(query.length()-1);
//			query.append(")");
//			Statement s = con.createStatement();
//			s.executeUpdate(query.toString());
//			s.close();
//		}else{
//			throw new IllegalArgumentException("Lists must be of equal length!");
//		}
//	}
	/**
	 * Calculate the given Content object's md5 hash, look it up in the
	 * known databases, and then update the case database with both hash and
	 * known status
	 *
	 * @param cont The content whose md5 you want to look up
	 * @return	   The content's known status from the databases
	 * @throws TskException
	 */
	public String lookupFileMd5(Content cont) throws TskException {
		Logger logger = Logger.getLogger(SleuthkitCase.class.getName());
		try {
			long contId = cont.getId();
			String md5Hash = Hash.calculateMd5(cont);
			FileKnown fileKnown = SleuthkitJNI.lookupHash(md5Hash);
			updateHashAndKnown(contId, md5Hash, fileKnown);
			return fileKnown.getName();
		} catch (TskException ex) {
			// TODO This should be higher than INFO, but we want to avoid pop-ups during ingest.  Find better fix in future.
			logger.log(Level.INFO, "Error looking up known status", ex);
		} catch (SQLException ex) {
			// TODO This should be higher than INFO, but we want to avoid pop-ups during ingest.  Find better fix in future.
			logger.log(Level.INFO, "Error updating SQL database", ex);
		}


		throw new TskException(
				"Error analyzing file");
	}
//	Useful if we want to queue sql updates for performance reasons
//	/**
//	 * Calculate the given Content objects' md5 hashes, look them up in the
//	 * known databases, and then update the case database with both hash and
//	 * known status
//	 *
//	 * @param cont The list of contents whose md5s you want to look up
//	 * @return	   The contents' known statuses from the databases
//	 * @throws TskException
//	 */
//	public List<Long> lookupFilesMd5(List<? extends Content> cont) throws TskException{
//		List<Long> ids = new ArrayList<Long>();
//		List<String> md5Hashes = new ArrayList<String>();
//		List<Long> knowns = new ArrayList<Long>();
//		
//		try{
//			for(Content c : cont){
//				ids.add(c.getId());
//				String md5Hash = Hash.calculateMd5(c);
//				md5Hashes.add(md5Hash);
//				knowns.add(SleuthkitJNI.lookupHash(md5Hash).toLong());
//			}
//			updateHashesAndKnowns(ids, md5Hashes, knowns);
//			return knowns;
//		} catch (TskException ex) {
//			Logger.getLogger(SleuthkitCase.class.getName()).log(Level.SEVERE,
//					"Error looking up known status", ex);
//		} catch(SQLException ex) {
//			Logger.getLogger(SleuthkitCase.class.getName()).log(Level.SEVERE,
//				"Error updating SQL database", ex);
//		}
//		throw new TskException("Error analyzing files");
//	}
}
