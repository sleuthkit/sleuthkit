/*
 * Sleuth Kit Data Model
 * 
 * Copyright 2014 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *  http://www.apache.org/licenses/LICENSE-2.0
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
import java.util.ArrayList;
import java.util.List;
import org.sleuthkit.datamodel.TskData.FileKnown;
import org.sleuthkit.datamodel.TskData.TSK_FS_ATTR_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_META_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_FLAG_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_TYPE_ENUM;

/**
 * Database helper class the wraps most of the mappings from ResultSet to
 * Content subclass constructors.
 */
class ResultSetHelper {
	SleuthkitCase db;

	ResultSetHelper(SleuthkitCase db) {
		this.db = db;
	}

	/**
	 * Create an image from the result set containing query results on
	 * tsk_image_info table
	 *
	 * @param rs result set containing query results
	 * @param imagePaths image file paths
	 * @return image object created
	 * @throws TskCoreException thrown if critical error occurred within tsk
	 * core
	 * @throws SQLException thrown if SQL error occurres
	 */
	Image image(ResultSet rs, String[] imagePaths) throws TskCoreException, SQLException {

		long obj_id, type, ssize;
		String tzone,md5;

		obj_id = rs.getLong("obj_id"); //NON-NLS
		type = rs.getLong("type"); //NON-NLS
		ssize = rs.getLong("ssize"); //NON-NLS
		tzone = rs.getString("tzone"); //NON-NLS
		md5="";
		if(db.getSchemaVersion() > 2) {
			md5= rs.getString("md5"); //NON-NLS
		}
		
		String name = rs.getString("display_name");
		if (name == null) {
			if (imagePaths.length > 0) {
				String path1 = imagePaths[0];
				name = (new java.io.File(path1)).getName();
			}
			else {
				name = "";
			}
		}
		
		Image img = new Image(db, obj_id, type, ssize, name, imagePaths, tzone,md5);
		return img;
	}

	/**
	 * Get image path string from the result set on tsk_image_names table
	 *
	 * @param rs result set with the tsk_image_names query result
	 * @return image path
	 * @throws SQLException thrown if SQL error occurred
	 */
	String imagePath(ResultSet rs) throws SQLException {
		return rs.getString("name"); //NON-NLS
	}

	/**
	 * Create an VolumeSystem object from the result set containing query
	 * results on tsk_vs_info table
	 *
	 * @param rs resultset containing query results
	 * @param parent parent image
	 * @return volume system object newly created
	 * @throws SQLException exception thrown if SQL error occurred
	 */
	VolumeSystem volumeSystem(ResultSet rs, Image parent) throws SQLException {

		long id = rs.getLong("obj_id"); //NON-NLS
		long type = rs.getLong("vs_type"); //NON-NLS
		long imgOffset = rs.getLong("img_offset"); //NON-NLS
		long blockSize = rs.getLong("block_size"); //NON-NLS

		VolumeSystem vs = new VolumeSystem(db, id, "", type, imgOffset, blockSize);

		vs.setParent(parent);
		return vs;
	}

	/**
	 * Create an Volume object from the result set containing query results on
	 * tsk_vs_parts table
	 *
	 * @param rs result set containing query results
	 * @param parent parent volume system
	 * @return newly created Volume object
	 * @throws SQLException thrown if SQL error occurred
	 */
	Volume volume(ResultSet rs, VolumeSystem parent) throws SQLException {
		Volume vol = new Volume(db, rs.getLong("obj_id"), rs.getLong("addr"), //NON-NLS
				rs.getLong("start"), rs.getLong("length"), rs.getLong("flags"), //NON-NLS
				rs.getString("desc")); //NON-NLS
		vol.setParent(parent);
		return vol;
	}

	/**
	 * Create a FileSystem object from the result set containing query results
	 * on tsk_fs_info table
	 *
	 * @param rs the result set
	 * @param parent parent content object
	 * @return newly create FileSystem object
	 * @throws SQLException thrown if SQL error occurred
	 */
	FileSystem fileSystem(ResultSet rs, Content parent) throws SQLException {

		TskData.TSK_FS_TYPE_ENUM fsType = TskData.TSK_FS_TYPE_ENUM.valueOf(rs.getInt("fs_type")); //NON-NLS
		FileSystem fs = new FileSystem(db, rs.getLong("obj_id"), "", rs.getLong("img_offset"), //NON-NLS
				fsType, rs.getLong("block_size"), rs.getLong("block_count"), //NON-NLS
				rs.getLong("root_inum"), rs.getLong("first_inum"), rs.getLong("last_inum")); //NON-NLS
		fs.setParent(parent);
		return fs;
	}

	/**
	 * Create a File object from the result set containing query results on
	 * tsk_files table
	 *
	 * @param rs the result set
	 * @param fs parent file system
	 * @return a newly create File
	 * @throws SQLException
	 */
	File file(ResultSet rs, FileSystem fs) throws SQLException {
		File f = new File(db, rs.getLong("obj_id"), rs.getLong("fs_obj_id"), //NON-NLS
				TSK_FS_ATTR_TYPE_ENUM.valueOf(rs.getShort("attr_type")), //NON-NLS
				rs.getShort("attr_id"), rs.getString("name"), rs.getLong("meta_addr"), rs.getInt("meta_seq"), //NON-NLS
				TSK_FS_NAME_TYPE_ENUM.valueOf(rs.getShort("dir_type")), //NON-NLS
				TSK_FS_META_TYPE_ENUM.valueOf(rs.getShort("meta_type")), //NON-NLS
				TSK_FS_NAME_FLAG_ENUM.valueOf(rs.getShort("dir_flags")), //NON-NLS
				rs.getShort("meta_flags"), rs.getLong("size"), //NON-NLS
				rs.getLong("ctime"), rs.getLong("crtime"), rs.getLong("atime"), rs.getLong("mtime"), //NON-NLS
				rs.getShort("mode"), rs.getInt("uid"), rs.getInt("gid"), //NON-NLS
				rs.getString("md5"), //NON-NLS
				FileKnown.valueOf(rs.getByte("known")), rs.getString("parent_path")); //NON-NLS
		f.setFileSystem(fs);
		return f;
	}

	/**
	 * Create a Directory object from the result set containing query results on
	 * tsk_files table
	 *
	 * @param rs the result set
	 * @param fs parent file system
	 * @name the directory name (TODO why do we need it passed, just query it )
	 * @return a newly created Directory object
	 * @throws SQLException thrown if SQL error occurred
	 */
	Directory directory(ResultSet rs, FileSystem fs, String name) throws SQLException {
		Directory dir = new Directory(db, rs.getLong("obj_id"), rs.getLong("fs_obj_id"), //NON-NLS
				TSK_FS_ATTR_TYPE_ENUM.valueOf(rs.getShort("attr_type")), //NON-NLS
				rs.getShort("attr_id"), name, rs.getLong("meta_addr"), rs.getInt("meta_seq"), //NON-NLS
				TSK_FS_NAME_TYPE_ENUM.valueOf(rs.getShort("dir_type")), //NON-NLS
				TSK_FS_META_TYPE_ENUM.valueOf(rs.getShort("meta_type")), //NON-NLS
				TSK_FS_NAME_FLAG_ENUM.valueOf(rs.getShort("dir_flags")), //NON-NLS
				rs.getShort("meta_flags"), rs.getLong("size"), //NON-NLS
				rs.getLong("ctime"), rs.getLong("crtime"), rs.getLong("atime"), rs.getLong("mtime"), //NON-NLS
				rs.getShort("mode"), rs.getInt("uid"), rs.getInt("gid"), //NON-NLS
				rs.getString("md5"), //NON-NLS
				FileKnown.valueOf(rs.getByte("known")), rs.getString("parent_path")); //NON-NLS
		dir.setFileSystem(fs);
		return dir;
	}

	/**
	 * Create a virtual directory object from a result set
	 *
	 * @param rs the result set
	 * @return
	 * @throws SQLException
	 */
	VirtualDirectory virtualDirectory(ResultSet rs) throws SQLException {
		String parentPath = rs.getString("parent_path"); //NON-NLS
		if (parentPath == null) {
			parentPath = "";
		}
		
		final VirtualDirectory vd = new VirtualDirectory(db, rs.getLong("obj_id"), //NON-NLS
				rs.getString("name"), //NON-NLS
				TSK_FS_NAME_TYPE_ENUM.valueOf(rs.getShort("dir_type")), //NON-NLS
				TSK_FS_META_TYPE_ENUM.valueOf(rs.getShort("meta_type")), //NON-NLS
				TSK_FS_NAME_FLAG_ENUM.valueOf(rs.getShort("dir_flags")), rs.getShort("meta_flags"), //NON-NLS
				rs.getLong("size"), rs.getString("md5"), //NON-NLS
				FileKnown.valueOf(rs.getByte("known")), parentPath); //NON-NLS
		return vd;
	}

	/**
	 * Create a Directory object from the result set containing query results on
	 * tsk_files table
	 *
	 * @param rs the result set
	 * @param fs the parent file system,
	 * @return a newly created Directory object
	 * @throws SQLException thrown if SQL error occurred
	 */
	Directory directory(ResultSet rs, FileSystem fs) throws SQLException {
		return directory(rs, fs, rs.getString("name")); //NON-NLS
	}

	/**
	 * Create a tsk file layout range object from the resultset on
	 * tsk_file_layout table
	 *
	 * @param rs the result set containg query results
	 * @return newly create tsk file range object
	 * @throws SQLException thrown if SQL error occurred
	 */
	TskFileRange tskFileRange(ResultSet rs) throws SQLException {
		return new TskFileRange(rs.getLong("byte_start"), //NON-NLS
				rs.getLong("byte_len"), rs.getLong("sequence")); //NON-NLS
	}

	/**
	 * Creates an derived file given result set and parent id (optional)
	 *
	 * @param rs exsting active result set
	 * @param parentId parent id or AbstractContent.UNKNOWN_ID
	 * @return derived file object created
	 * @throws SQLException
	 */
	DerivedFile derivedFile(ResultSet rs, long parentId) throws SQLException {
		boolean hasLocalPath = rs.getBoolean("has_path"); //NON-NLS
		long objId = rs.getLong("obj_id"); //NON-NLS
		String localPath = null;
		if (hasLocalPath) {
			localPath = db.getFilePath(objId);
		}

		String parentPath = rs.getString("parent_path"); //NON-NLS
		if (parentPath == null) {
			parentPath = "";
		}

		final DerivedFile df =
				new DerivedFile(db, objId, rs.getString("name"), //NON-NLS
				TSK_FS_NAME_TYPE_ENUM.valueOf(rs.getShort("dir_type")), //NON-NLS
				TSK_FS_META_TYPE_ENUM.valueOf(rs.getShort("meta_type")), //NON-NLS
				TSK_FS_NAME_FLAG_ENUM.valueOf(rs.getShort("dir_flags")), rs.getShort("meta_flags"), //NON-NLS
				rs.getLong("size"), //NON-NLS
				rs.getLong("ctime"), rs.getLong("crtime"), rs.getLong("atime"), rs.getLong("mtime"), //NON-NLS
				rs.getString("md5"), FileKnown.valueOf(rs.getByte("known")), //NON-NLS
				parentPath, localPath,
				parentId);

		return df;
	}

	/**
	 * Creates an local file given result set and parent id (optional)
	 *
	 * @param rs exsting active result set
	 * @param parentId parent id or AbstractContent.UNKNOWN_ID
	 * @return local file object created
	 * @throws SQLException
	 */
	LocalFile localFile(ResultSet rs, long parentId) throws SQLException {
		boolean hasLocalPath = rs.getBoolean("has_path"); //NON-NLS
		long objId = rs.getLong("obj_id"); //NON-NLS
		String localPath = null;
		if (hasLocalPath) {
			localPath = db.getFilePath(objId);
		}

		String parentPath = rs.getString("parent_path"); //NON-NLS
		if (parentPath == null) {
			parentPath = "";
		}

		final LocalFile lf =
				new LocalFile(db, objId, rs.getString("name"), //NON-NLS
				TSK_FS_NAME_TYPE_ENUM.valueOf(rs.getShort("dir_type")), //NON-NLS
				TSK_FS_META_TYPE_ENUM.valueOf(rs.getShort("meta_type")), //NON-NLS
				TSK_FS_NAME_FLAG_ENUM.valueOf(rs.getShort("dir_flags")), rs.getShort("meta_flags"), //NON-NLS
				rs.getLong("size"), //NON-NLS
				rs.getLong("ctime"), rs.getLong("crtime"), rs.getLong("atime"), rs.getLong("mtime"), //NON-NLS
				rs.getString("md5"), FileKnown.valueOf(rs.getByte("known")), //NON-NLS
				parentPath, localPath,
				parentId);

		return lf;
	}
	
	/**
	 * Returns the list of abstractFile objects from a result of selecting many
	 * files that meet a certain criteria. 
	 * @param rs
	 * @param parentId
	 * @return
	 * @throws SQLException 
	 */
	List<Content> fileChildren(ResultSet rs, long parentId) throws SQLException {
		List<Content> children = new ArrayList<Content>();

		while (rs.next()) {
			TskData.TSK_DB_FILES_TYPE_ENUM type = TskData.TSK_DB_FILES_TYPE_ENUM.valueOf(rs.getShort("type"));

			if (type == TskData.TSK_DB_FILES_TYPE_ENUM.FS) {
				FsContent result;
				if (rs.getShort("meta_type") == TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_DIR.getValue()) {
					result = directory(rs, null);
				} else {
					result = file(rs, null);
				}
				children.add(result);
			} else if (type == TskData.TSK_DB_FILES_TYPE_ENUM.VIRTUAL_DIR) {
				VirtualDirectory virtDir = virtualDirectory(rs);
				children.add(virtDir);
			} else if (type == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS
					|| type == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS
					|| type == TskData.TSK_DB_FILES_TYPE_ENUM.CARVED) {
				String parentPath = rs.getString("parent_path");
				if (parentPath == null) {
					parentPath = "";
				}
				final LayoutFile lf =
						new LayoutFile(db, rs.getLong("obj_id"), rs.getString("name"),
						type,
						TSK_FS_NAME_TYPE_ENUM.valueOf(rs.getShort("dir_type")),
						TSK_FS_META_TYPE_ENUM.valueOf(rs.getShort("meta_type")),
						TSK_FS_NAME_FLAG_ENUM.valueOf(rs.getShort("dir_flags")),
						rs.getShort("meta_flags"),
						rs.getLong("size"),
						rs.getString("md5"), FileKnown.valueOf(rs.getByte("known")), parentPath);
				children.add(lf);
			} else if (type == TskData.TSK_DB_FILES_TYPE_ENUM.DERIVED) {
				final DerivedFile df = derivedFile(rs, parentId);
				children.add(df);
			} else if (type == TskData.TSK_DB_FILES_TYPE_ENUM.LOCAL) {
				final LocalFile lf = localFile(rs, parentId);
				children.add(lf);
			}
		}
		return children;
	}
}