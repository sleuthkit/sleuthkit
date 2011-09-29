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
 *     http://www.apache.org/licenses/LICENSE-2.0
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
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.*;
import java.util.logging.Level;
import org.sleuthkit.datamodel.TskData.ObjectType;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_TYPE_ENUM;
import java.util.logging.Logger;
import org.sleuthkit.datamodel.SleuthkitJNI.CaseDbHandle.AddImageProcess;

/**
 * database connection object. makes use of the sqlite jdbc libraries
 * @author alawrence
 */
public class SleuthkitCase {
	private String dbPath;
	private String imageDirectory;
	private SleuthkitJNI.CaseDbHandle caseHandle;
	private Connection con;
	private ResultSetHelper rsHelper = new ResultSetHelper(this);

	/**
	 * constructor
	 * @param dbPath path to the database
	 * @throws SQLException
	 * @throws ClassNotFoundException
	 */
	private SleuthkitCase(String dbPath, String imageDirectory, SleuthkitJNI.CaseDbHandle caseHandle) throws SQLException, ClassNotFoundException {
		Class.forName("org.sqlite.JDBC");
		this.dbPath = dbPath;
		this.caseHandle = caseHandle;
		this.imageDirectory = imageDirectory;
		con = DriverManager.getConnection("jdbc:sqlite:" + dbPath);
		con.setReadOnly(true);
	}
	
	public static SleuthkitCase openCase(String dbPath, String imageDirectory) throws TskException {
		SleuthkitJNI.CaseDbHandle caseHandle = SleuthkitJNI.openCaseDb(dbPath);
		try {
			return new SleuthkitCase(dbPath, imageDirectory, caseHandle);
		} catch (SQLException ex) {
			throw new TskException("Couldn't open case.", ex);
		} catch (ClassNotFoundException ex) {
			throw new TskException("Couldn't open case.", ex);
		}
	}
	
	public static SleuthkitCase newCase(String dbPath, String imageDirectory) throws TskException {
		SleuthkitJNI.CaseDbHandle caseHandle = SleuthkitJNI.newCaseDb(dbPath);
		try {
			return new SleuthkitCase(dbPath, imageDirectory, caseHandle);
		} catch (SQLException ex) {
			throw new TskException("Couldn't open case.", ex);
		} catch (ClassNotFoundException ex) {
			throw new TskException("Couldn't open case.", ex);
		}
	}
	
	public AddImageProcess makeAddImageProcess(String timezone) {
		return this.caseHandle.initAddImageProcess(timezone);
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
//	 * @return fs    a new file system object
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
	
	
	public List<Content> getRootObjects() throws TskException {
		try {
			Statement s = con.createStatement();
			ResultSet rs = s.executeQuery("select obj_id, type from tsk_objects " +
					"where par_obj_id is NULL");

			Collection<ObjectInfo> infos = new ArrayList<ObjectInfo>();

			while (rs.next()) {
				infos.add(new ObjectInfo(rs.getLong("obj_id"), ObjectType.valueOf(rs.getLong("type"))));
			}

			s.close();

			List<Content> rootObjs = new ArrayList<Content>();

			for(ObjectInfo i : infos) {
				if (i.type == ObjectType.IMG) {
					rootObjs.add(getImageById(i.id));
				} else {
					throw new IllegalStateException("Parentless object has wrong type to be a root: " + i.type);
				}
			}

			return rootObjs;
		} catch (SQLException ex) {
			throw new TskException("Error getting root objects.", ex);
		}
	}
	
	private static class ObjectInfo {
		long id;
		TskData.ObjectType type;

		ObjectInfo(long id, ObjectType type) {
			this.id = id;
			this.type = type;
		}
	}
	
	Collection<ObjectInfo> getChildrenInfo(Content c) throws SQLException {
		Statement s = con.createStatement();
		ResultSet rs = s.executeQuery("select obj_id, type from tsk_objects " +
				"where par_obj_id = " + c.getId());
		
		Collection<ObjectInfo> infos = new ArrayList<ObjectInfo>();
		
		while (rs.next()) {
			infos.add(new ObjectInfo(rs.getLong("obj_id"), ObjectType.valueOf(rs.getLong("type"))));
		}
		
		s.close();
		return infos;
	}
	
	ObjectInfo getParentInfo(Content c) throws SQLException {
		Statement s = con.createStatement();
		ResultSet rs = s.executeQuery("SELECT parent.obj_id, parent.type "
				+ "FROM tsk_objects AS parent JOIN tsk_objects AS child "
				+ "ON child.par_obj_id = parent.obj_id "
				+ "WHERE child.obj_id = " + c.getId());
		
		ObjectInfo info;
		
		if (rs.next()) {
			info = new ObjectInfo(rs.getLong("obj_id"), ObjectType.valueOf(rs.getLong("type")));
			s.close();
			return info;
		} else {
			s.close();
			throw new IllegalArgumentException("Given content has no parent.");
		}
	}
	
	Directory getParentDirectory(FsContent fsc) throws SQLException {
		if (fsc.isRoot()) {
			throw new IllegalArgumentException("Given FsContent is a root object (can't have parent directory).");
		} else {
			ObjectInfo parentInfo = getParentInfo(fsc);
			
			Directory parent;

			if (parentInfo.type == ObjectType.FILE) {
				parent = getDirectoryById(parentInfo.id, fsc.getFileSystem());
			} else {
				throw new IllegalStateException("Parent has wrong type to be directory: " + parentInfo.type);
			}

			return parent;
		}
	}
	
	public Image getImageById(long id) throws SQLException, TskException {
		Statement s1 = con.createStatement();
		
		ResultSet rs1 = s1.executeQuery("select * from tsk_image_info where obj_id = " + id);
		
		Image temp;
		if (rs1.next()) {
			long obj_id = rs1.getLong("obj_id");
			Statement s2 = con.createStatement();
			ResultSet rs2 = s2.executeQuery("select * from tsk_image_names where obj_id = " + obj_id);
			List<String> imageNames = new ArrayList<String>();
			while(rs2.next()) {
				imageNames.add(rsHelper.imagePath(rs2));
			}
			
			temp = rsHelper.image(rs1, imageNames.get(0), imageNames.toArray(new String[imageNames.size()]), imageDirectory);
		} else {
			throw new IllegalStateException("No image found in database!");
		}
		
		s1.close();
		return temp;
	}
	

	VolumeSystem getVolumeSystemById(long id, Image parent) throws SQLException {
		Statement s = con.createStatement();
		
		ResultSet rs = s.executeQuery("select * from tsk_vs_info " +
			"where obj_id = " + id);
				VolumeSystem temp;

		if (rs.next()) {
			temp = rsHelper.volumeSystem(rs, parent);
		} else {
			throw new IllegalStateException("No volume system found for id:" + id);
		}
		
		s.close();
		return temp;
	}
	
	FileSystem getFileSystemById(long id, FileSystemParent parent) throws SQLException {
		Statement s = con.createStatement();
		FileSystem temp;

		ResultSet rs = s.executeQuery("select * from tsk_fs_info " +
			"where obj_id = " + id);

		if (rs.next()) {
			temp = rsHelper.fileSystem(rs, parent);
		} else {
			throw new IllegalStateException("No file system found for id:" + id);
		}
		s.close();
		
		return temp;
	}
	
	Volume getVolumeById(long id, VolumeSystem parent) throws SQLException {
		Statement s = con.createStatement();
		Volume temp;
		
		ResultSet rs = s.executeQuery("select * from tsk_vs_parts " +
			"where obj_id = " + id);

		if (rs.next()) {
			temp = rsHelper.volume(rs, parent);
		} else {
			throw new IllegalStateException("No volume found for id:" + id);
		}

		s.close();
		return temp;
	}
	
	Directory getDirectoryById(long id, FileSystem parentFs) throws SQLException {
		Statement s = con.createStatement();
		Directory temp;
		
		ResultSet rs = s.executeQuery("select * from tsk_files " +
			"where obj_id = " + id);

		if (rs.next() && rs.getLong("dir_type") == TSK_FS_NAME_TYPE_ENUM.DIR.getDirType()) {
				temp = rsHelper.directory(rs, parentFs);
		} else {
			s.close();
			throw new IllegalStateException("No Directory found for id:" + id);
		}

		s.close();
		return temp;
	}
	
	/**
	 * Initializes the entire heritage of the visited Content.
	 */
	private class SetParentVisitor implements ContentVisitor<Void> {
		
		SetParentVisitor() {}
		
		// make File/Directory visits (majority of cases) faster by caching 
		// fully initialized parent FileSystems
		Map<Long,FileSystem> fileSystemCache = new HashMap<Long,FileSystem>();
		
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
	


	List<Content> getImageChildren(Image img) throws SQLException {
		Collection<ObjectInfo> childInfos = getChildrenInfo(img);
		
		List<Content> children = new ArrayList<Content>(childInfos.size());
		
		for (ObjectInfo info : childInfos) {

			if (info.type == ObjectType.VS) {
				children.add(getVolumeSystemById(info.id, img));
			} else if (info.type == ObjectType.FS) {
				children.add(getFileSystemById(info.id, img));
			} else {
				throw new IllegalStateException("Image has child of invalid type: " + info.type);
			}
		}
		
		return children;
	}
	
	List<Content> getVolumeSystemChildren(VolumeSystem vs) throws SQLException {
		Collection<ObjectInfo> childInfos = getChildrenInfo(vs);
		
		List<Content> children = new ArrayList<Content>(childInfos.size());
		
		for (ObjectInfo info : childInfos) {

			if (info.type == ObjectType.VOL) {
				children.add(getVolumeById(info.id, vs));
			} else {
				throw new IllegalStateException("VolumeSystem has child of invalid type: " + info.type);
			}
		}
		
		return children;
	}
	
	List<Content> getVolumeChildren(Volume vol) throws SQLException {
		Collection<ObjectInfo> childInfos = getChildrenInfo(vol);
		
		List<Content> children = new ArrayList<Content>(childInfos.size());
		
		for (ObjectInfo info : childInfos) {
			if (info.type == ObjectType.FS) {
				children.add(getFileSystemById(info.id, vol));
			} else {
				throw new IllegalStateException("Volume has child of invalid type: " + info.type);
			}
		}
		
		return children;
	}
	
	List<Content> getFileSystemChildren(FileSystem fs) throws SQLException {
		return getChildFsContents(fs.getId(), fs);
	}


	List<Content> getChildFsContents(long par_obj_id, FileSystem parentFs) throws SQLException {
		Statement s = con.createStatement();
		ResultSet rs = s.executeQuery("select tsk_files.* from tsk_files join "
				+ "tsk_objects on tsk_files.obj_id = tsk_objects.obj_id "
				+ "where par_obj_id = " + par_obj_id + " order by name asc");
		
		List<Content> children = new ArrayList<Content>();
		
		while(rs.next()) {
			if (rs.getLong("dir_type") == TSK_FS_NAME_TYPE_ENUM.DIR.getDirType()) {
				children.add(rsHelper.directory(rs, parentFs));
			} else {
				children.add(rsHelper.file(rs, parentFs));
			}
		}
		
		s.close();
		return children;
	}
	
	
	
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
	 * table
	 * @param rs ResultSet to get content from
	 * @return A List<FsContent> containing the results
	 * @throws SQLException  
	 */
	public List<FsContent> resultSetToFsContents(ResultSet rs) throws SQLException {
		SetParentVisitor setParent = new SetParentVisitor();
		ArrayList<FsContent> results = new ArrayList<FsContent>();

		while (rs.next()) {
			FsContent result;
			if (rs.getLong("dir_type") == TSK_FS_NAME_TYPE_ENUM.DIR.getDirType()) {
				result = rsHelper.directory(rs, null);
			} else {
				result = rsHelper.file(rs, null);
			}
			result.accept(setParent);
			results.add(result);
		}
		
		return results;
	}
	
	
	/**
	 * Returns the ResultSet from the given query.
	 *
	 * @param query  the given string query to run
	 * @return       the resultSet
	 * @throws SQLException
	 */
	public ResultSet runQuery(String query) throws SQLException{
		Statement statement;
		statement = con.createStatement();

		ResultSet rs = statement.executeQuery(query);
		return rs;
	}

	public void finalize(){
		try
		{
			if(con != null)
				con.close();
		}
		catch(SQLException e)
		{
			// connection close failed.
			System.err.println(e);
		}
	}

	/**
	 * Closes the connection of this class.
	 */
	public void closeConnection(){
		try
		{
			if(con != null)
				con.close();
		}
		catch(SQLException e)
		{
			// connection close failed.
			System.err.println(e);
		}
	}
	
	/**
	 * Call to free resources when done with instance.
	 */
	public void close() {
		this.closeConnection();
		try {
			this.caseHandle.free();
		} catch (TskException ex) {
			Logger.getLogger(SleuthkitCase.class.getName()).log(Level.WARNING,
					"Error freeing case handle.", ex);
		}
	}
} 
