package org.sleuthkit.datamodel;

import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Database helper class the wraps most of the mappings from ResultSet to
 * Content subclass constructors.
 *
 * @author pmartel
 */
class ResultSetHelper {

	SleuthkitCase db;

	ResultSetHelper(SleuthkitCase db) {
		this.db = db;
	}

	Image image(ResultSet rs, String name, String[] imagePaths) throws TskException, SQLException {

		long obj_id, type, ssize;
		String tzone;

		obj_id = rs.getLong("obj_id");
		type = rs.getLong("type");
		ssize = rs.getLong("ssize");
		tzone = rs.getString("tzone");

		Image img = new Image(db, obj_id, type, ssize, name, imagePaths, tzone);
		return img;
	}

	String imagePath(ResultSet rs) throws SQLException {
		return rs.getString("name");
	}

	VolumeSystem volumeSystem(ResultSet rs, Image parent) throws SQLException {

		long id = rs.getLong("obj_id");
		long type = rs.getLong("vs_type");
		long imgOffset = rs.getLong("img_offset");
		long blockSize = rs.getLong("block_size");

		VolumeSystem vs = new VolumeSystem(db, id, type, imgOffset, blockSize);

		vs.setParent(parent);
		return vs;
	}

	Volume volume(ResultSet rs, VolumeSystem parent) throws SQLException {
		Volume vol = new Volume(db, rs.getLong("obj_id"), rs.getLong("addr"),
				rs.getLong("start"), rs.getLong("length"), rs.getLong("flags"),
				rs.getString("desc"));
		vol.setParent(parent);
		return vol;
	}

	FileSystem fileSystem(ResultSet rs, FileSystemParent parent) throws SQLException {

		FileSystem fs = new FileSystem(db, rs.getLong("obj_id"), rs.getLong("img_offset"),
				rs.getLong("fs_type"), rs.getLong("block_size"), rs.getLong("block_count"),
				rs.getLong("root_inum"), rs.getLong("first_inum"), rs.getLong("last_inum"));
		fs.setParent(parent);
		return fs;
	}
			
	File file(ResultSet rs, FileSystem fs) throws SQLException {
		File f = new File(db, rs.getLong("obj_id"), rs.getLong("fs_obj_id"), rs.getLong("meta_addr"), rs.getLong("attr_type"),
				rs.getLong("attr_id"), rs.getString("name"), rs.getLong("dir_type"),
				rs.getLong("meta_type"), rs.getLong("dir_flags"), rs.getLong("meta_flags"), rs.getLong("size"),
				rs.getLong("ctime"), rs.getLong("crtime"), rs.getLong("atime"), rs.getLong("mtime"),
				rs.getLong("mode"), rs.getLong("uid"), rs.getLong("gid"), rs.getLong("known"), rs.getString("parent_path"));
		f.setFileSystem(fs);
		return f;
	}
	
	Directory directory(ResultSet rs, FileSystem fs, String name) throws SQLException {
		Directory dir = new Directory(db, rs.getLong("obj_id"), rs.getLong("fs_obj_id"), rs.getLong("meta_addr"), rs.getLong("attr_type"),
				rs.getLong("attr_id"), name, rs.getLong("dir_type"),
				rs.getLong("meta_type"), rs.getLong("dir_flags"), rs.getLong("meta_flags"), rs.getLong("size"),
				rs.getLong("ctime"), rs.getLong("crtime"), rs.getLong("atime"), rs.getLong("mtime"),
				rs.getLong("mode"), rs.getLong("uid"), rs.getLong("gid"), rs.getLong("known"), rs.getString("parent_path"));
		dir.setFileSystem(fs);
		return dir;
	}

	Directory directory(ResultSet rs, FileSystem fs) throws SQLException {
		return directory(rs, fs, rs.getString("name"));
	}
	
}