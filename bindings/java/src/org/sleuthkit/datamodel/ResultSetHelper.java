package org.sleuthkit.datamodel;

import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Database helper class the wraps most of the mappings from ResultSet to
 * Content subclass constructors.
 *
 */
class ResultSetHelper {

	SleuthkitCase db;

	ResultSetHelper(SleuthkitCase db) {
		this.db = db;
	}

	/**
	 * Create an image from the result set containing query results on tsk_image_info table
	 * @param rs result set containing query results
	 * @param name name of the image
	 * @param imagePaths image file paths
	 * @return image object created
	 * @throws TskCoreException thrown if critical error occurred within tsk core
	 * @throws SQLException thrown if SQL error occurres
	 */
	Image image(ResultSet rs, String name, String[] imagePaths) throws TskCoreException, SQLException {

		long obj_id, type, ssize;
		String tzone;

		obj_id = rs.getLong("obj_id");
		type = rs.getLong("type");
		ssize = rs.getLong("ssize");
		tzone = rs.getString("tzone");

		Image img = new Image(db, obj_id, type, ssize, name, imagePaths, tzone);
		return img;
	}

	/**
	 * Get image path string from the result set on tsk_image_names table
	 * @param rs result set with the tsk_image_names query result
	 * @return image path 
	 * @throws SQLException thrown if SQL error occurred
	 */
	String imagePath(ResultSet rs) throws SQLException {
		return rs.getString("name");
	}

	
	/**
	 * Create an VolumeSystem object from the result set containing query results on tsk_vs_info table
	 * @param rs resultset containing query results
	 * @param parent parent image
	 * @return volume system object newly created
	 * @throws SQLException exception thrown if SQL error occurred
	 */
	VolumeSystem volumeSystem(ResultSet rs, Image parent) throws SQLException {

		long id = rs.getLong("obj_id");
		long type = rs.getLong("vs_type");
		long imgOffset = rs.getLong("img_offset");
		long blockSize = rs.getLong("block_size");

		VolumeSystem vs = new VolumeSystem(db, id, "Volume System", type, imgOffset, blockSize);

		vs.setParent(parent);
		return vs;
	}

	/**
	 * Create an Volume object from the result set containing query results on tsk_vs_parts table
	 * 
	 * @param rs result set containing query results
	 * @param parent parent volume system
	 * @return newly created Volume object
	 * @throws SQLException thrown if SQL error occurred
	 */
	Volume volume(ResultSet rs, VolumeSystem parent) throws SQLException {
		Volume vol = new Volume(db, rs.getLong("obj_id"), rs.getLong("addr"),
				rs.getLong("start"), rs.getLong("length"), rs.getLong("flags"),
				rs.getString("desc"));
		vol.setParent(parent);
		return vol;
	}
	
	/**
	 * Create a FileSystem object from the result set containing query results on tsk_fs_info table
	 * @param rs the result set 
	 * @param parent parent content object
	 * @return newly create FileSystem object
	 * @throws SQLException thrown if SQL error occurred
	 */
	FileSystem fileSystem(ResultSet rs, Content parent) throws SQLException {

		FileSystem fs = new FileSystem(db, rs.getLong("obj_id"), "File System", rs.getLong("img_offset"),
				rs.getLong("fs_type"), rs.getLong("block_size"), rs.getLong("block_count"),
				rs.getLong("root_inum"), rs.getLong("first_inum"), rs.getLong("last_inum"));
		fs.setParent(parent);
		return fs;
	}

	/**
	 * Create a File object from the result set containing query results on tsk_files table
	 * @param rs the result set
	 * @param fs parent file system
	 * @return a newly create File
	 * @throws SQLException 
	 */
	File file(ResultSet rs, FileSystem fs) throws SQLException {
		File f = new File(db, rs.getLong("obj_id"), rs.getLong("fs_obj_id"), rs.getLong("meta_addr"), rs.getLong("attr_type"),
				rs.getLong("attr_id"), rs.getString("name"), rs.getLong("dir_type"),
				rs.getLong("meta_type"), rs.getLong("dir_flags"), rs.getLong("meta_flags"), rs.getLong("size"),
				rs.getLong("ctime"), rs.getLong("crtime"), rs.getLong("atime"), rs.getLong("mtime"),
				rs.getLong("mode"), rs.getLong("uid"), rs.getLong("gid"), rs.getLong("known"), rs.getString("parent_path"), rs.getString("md5"));
		f.setFileSystem(fs);
		return f;
	}

	/**
	 * Create a Directory object from the result set containing query results on tsk_files table
	 * @param rs the result set
	 * @param fs parent file system
	 * @name the directory name (TODO why do we need it passed, just query it )
	 * @return a newly created Directory object
	 * @throws SQLException thrown if SQL error occurred
	 */
	Directory directory(ResultSet rs, FileSystem fs, String name) throws SQLException {
		Directory dir = new Directory(db, rs.getLong("obj_id"), rs.getLong("fs_obj_id"), rs.getLong("meta_addr"), rs.getLong("attr_type"),
				rs.getLong("attr_id"), name, rs.getLong("dir_type"),
				rs.getLong("meta_type"), rs.getLong("dir_flags"), rs.getLong("meta_flags"), rs.getLong("size"),
				rs.getLong("ctime"), rs.getLong("crtime"), rs.getLong("atime"), rs.getLong("mtime"),
				rs.getLong("mode"), rs.getLong("uid"), rs.getLong("gid"), rs.getLong("known"), rs.getString("parent_path"), rs.getString("md5"));
		dir.setFileSystem(fs);
		return dir;
	}

	
	/**
	 * Create a Directory object from the result set containing query results on tsk_files table
	 * @param rs the result set
	 * @param fs the parent file suste,
	 * @return a newly created Directory object
	 * @throws SQLException thrown if SQL error occurred
	 */
	Directory directory(ResultSet rs, FileSystem fs) throws SQLException {
		return directory(rs, fs, rs.getString("name"));
	}

	/**
	 * Create a tsk file layout range object from the resultset on tsk_file_layout table
	 * @param rs the result set containg query results
	 * @return newly create tsk file range object
	 * @throws SQLException thrown if SQL error occurred
	 */
	TskFileRange tskFileRange(ResultSet rs) throws SQLException {
		return new TskFileRange(rs.getLong("obj_id"), rs.getLong("byte_start"),
				rs.getLong("byte_len"), rs.getLong("sequence"));
	}
}