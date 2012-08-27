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

import java.util.Collections;
import java.util.List;
import java.util.StringTokenizer;
import org.sleuthkit.datamodel.TskData.FileKnown;

/**
 * Generalized class that stores metadata that are common to both File and
 * Directory objects stored in tsk_files table Caches internal tsk file handle
 * and reuses it for reads
 */
public abstract class FsContent extends AbstractFile {

	///read only database tsk_files fields
	protected final long fs_obj_id, meta_addr, attr_type, attr_id, meta_type, dir_type, dir_flags,
			meta_flags, size, ctime, crtime, atime, mtime, uid, gid, mode;

	/*
	 * path of parent directory
	 */
	protected final String parent_path;
	///read-write database tsk_files fields
	/**
	 * known status in database
	 */
	protected long known;
	/*
	 * md5 hash
	 */
	protected String md5Hash;
	///other members
	/*
	 * Unique path containing image and volume
	 */
	protected String unique_path;
	/**
	 * parent file system
	 */
	protected FileSystem parentFileSystem;
	/**
	 * file Handle
	 */
	protected long fileHandle = 0;

	/**
	 * Constructor to create FsContent object instance from database
	 *
	 * @param db
	 * @param obj_id
	 * @param name
	 * @param fs_obj_id
	 * @param meta_addr
	 * @param attr_type
	 * @param attr_id
	 * @param meta_type
	 * @param dir_type
	 * @param dir_flags
	 * @param meta_flags
	 * @param size
	 * @param ctime
	 * @param crtime
	 * @param atime
	 * @param mtime
	 * @param uid
	 * @param gid
	 * @param mode
	 * @param known
	 * @param parent_path
	 * @param md5Hash
	 */
	FsContent(SleuthkitCase db, long obj_id, String name, long fs_obj_id, long meta_addr,
			long attr_type, long attr_id, long meta_type, long dir_type, long dir_flags,
			long meta_flags, long size, long ctime, long crtime, long atime, long mtime, long uid, long gid, long mode, long known,
			String parent_path, String md5Hash) {
		super(db, obj_id, name, TskData.TSK_DB_FILES_TYPE_ENUM.FS);
		this.fs_obj_id = fs_obj_id;
		this.meta_addr = meta_addr;
		this.attr_type = attr_type;
		this.attr_id = attr_id;
		this.meta_type = meta_type;
		this.dir_type = dir_type;
		this.dir_flags = dir_flags;
		this.meta_flags = meta_flags;
		this.size = size;
		this.ctime = ctime;
		this.crtime = crtime;
		this.atime = atime;
		this.mtime = mtime;
		this.uid = uid;
		this.gid = gid;
		this.mode = mode;
		this.known = known;
		this.parent_path = parent_path;
		this.md5Hash = md5Hash;
	}

	/**
	 * Sets the parent file system, called by parent during object creation
	 *
	 * @param parent parent file system object
	 */
	protected void setFileSystem(FileSystem parent) {
		parentFileSystem = parent;
	}

	/**
	 * Sets md5 hash string
	 * Note: database or other FsContent objects are not updated.
	 * Currently only SleuthkiCase calls it to update the object while updating tsk_files entry
	 * 
	 * @param md5Hash 
	 */
	void setMd5Hash(String md5Hash) {
		this.md5Hash = md5Hash;
	}

	/**
	 * Sets known status
	 * Note: database or other FsContent objects are not updated.
	 * Currently only SleuthkiCase calls it to update the object while updating tsk_files entry
	 * 
	 * @param known 
	 */
	void setKnown(long known) {
		this.known = known;
	}

	@Override
	public int read(byte[] buf, long offset, long len) throws TskCoreException {
		synchronized (this) {
			if (fileHandle == 0) {
				fileHandle = SleuthkitJNI.openFile(parentFileSystem.getFileSystemHandle(), meta_addr);
			}
		}
		return SleuthkitJNI.readFile(fileHandle, buf, offset, len);
	}

	/*
	 * -------------------------------------------------------------------------
	 * Getters to retrieve meta-data attributes values
	 * -------------------------------------------------------------------------
	 */
	public boolean isRoot() {
		return parentFileSystem.getRoot_inum() == this.getMeta_addr();
	}

	/**
	 * Gets parent directory
	 *
	 * @return the parent Directory
	 * @throws TskCoreException exception thrown if error occurred in tsk core
	 */
	public Directory getParentDirectory() throws TskCoreException {
		return getSleuthkitCase().getParentDirectory(this);
	}

	/**
	 * Get the parent file system
	 *
	 * @return the file system object of the parent
	 */
	public FileSystem getFileSystem() {
		return parentFileSystem;
	}

	@Override
	public Image getImage() throws TskCoreException {
		return this.getFileSystem().getImage();
	}

	/**
	 * Get the attribute type
	 *
	 * @return attribute type
	 */
	public long getAttr_type() {
		return attr_type;
	}

	/**
	 * Get the attribute id
	 *
	 * @return attribute id
	 */
	public long getAttr_id() {
		return attr_id;
	}

	/**
	 * Get the meta data type
	 *
	 * @return meta data type
	 */
	public long getMeta_type() {
		return meta_type;
	}

	/**
	 * Get the meta data type as String
	 *
	 * @return meta data type as String
	 */
	public String getMetaTypeAsString() {
		return FsContent.metaTypeToString(meta_type);
	}

	/**
	 * Get the directory type id
	 *
	 * @return directory type id
	 */
	public long getDir_type() {
		return dir_type;
	}

	/**
	 * Get the directory type as String
	 *
	 * @return directory type as String
	 */
	public String getDirTypeAsString() {
		return FsContent.dirTypeToString(dir_type);
	}

	/**
	 * Get the directory flags
	 *
	 * @return directory flags
	 */
	public long getDir_flags() {
		return dir_flags;
	}

	/**
	 * Get the directory flags as String
	 *
	 * @return directory flags as String
	 */
	public String getDirFlagsAsString() {
		return FsContent.dirFlagToString(dir_flags);
	}

	/**
	 * Get the file meta address
	 *
	 * @return Address of the meta data structure
	 */
	public long getMeta_addr() {
		return meta_addr;
	}

	/**
	 * Get the meta data flags
	 *
	 * @return meta data flags
	 */
	public long getMeta_flags() {
		return meta_flags;
	}

	/**
	 * Get the meta data flags as String
	 *
	 * @return meta data flags as String
	 */
	public String getMetaFlagsAsString() {
		return FsContent.metaFlagToString(meta_flags);
	}

	@Override
	public long getSize() {
		return size;
	}

	@Override
	public List<TskFileRange> getRanges() {
		return Collections.<TskFileRange>emptyList();
	}

	/**
	 * Get the change time
	 *
	 * @return change time
	 */
	public long getCtime() {
		return ctime;
	}

	/**
	 * Get the change time as Date
	 *
	 * @return change time as Date
	 */
	public String getCtimeAsDate() {
		return FsContent.epochToTime(ctime);
	}

	/**
	 * Get the creation time
	 *
	 * @return creation time
	 */
	public long getCrtime() {
		return crtime;
	}

	/**
	 * Get the creation time as Date
	 *
	 * @return creation time as Date
	 */
	public String getCrtimeAsDate() {
		return FsContent.epochToTime(crtime);
	}

	/**
	 * Get the access time
	 *
	 * @return access time
	 */
	public long getAtime() {
		return atime;
	}

	/**
	 * Get the access time as Date
	 *
	 * @return access time as Date
	 */
	public String getAtimeAsDate() {
		return FsContent.epochToTime(atime);
	}

	/**
	 * Get the modified time
	 *
	 * @return modified time
	 */
	public long getMtime() {
		return mtime;
	}

	/**
	 * Get the modified time as Date
	 *
	 * @return modified time as Date
	 */
	public String getMtimeAsDate() {
		return FsContent.epochToTime(mtime);
	}

	/**
	 * Get the user id
	 *
	 * @return user id
	 */
	public long getUid() {
		return uid;
	}

	/**
	 * Get the group id
	 *
	 * @return group id
	 */
	public long getGid() {
		return gid;
	}

	/**
	 * Get the mode
	 *
	 * @return mode
	 */
	public long getMode() {
		return mode;
	}

	/**
	 * Get the mode as String
	 *
	 * @return mode as String
	 */
	public String getModeAsString() {
		return FsContent.modeToString(mode, meta_type);
	}

	/**
	 * Get "known" file status - after running a HashDB ingest on it As marked
	 * by a known file database, such as NSRL
	 *
	 * @return file known status enum value
	 */
	public FileKnown getKnown() {
		return FileKnown.valueOf(this.known);
	}

	/**
	 * Get the absolute parent path string of this FsContent
	 *
	 * @return the parent path string
	 */
	public String getParentPath() {
		return this.parent_path;
	}

	/**
	 * Get the absolute unique across all files in the case parent path string
	 * of this FsContent The path contains image and volume-system partition
	 * After first call, every subsequent call returns the cached string
	 *
	 * @return unique absolute file path (cached after first call)
	 * @throws TskCoreException thrown when critical error occurred in Tsk Core
	 * and unique absolute path could not be queried
	 */
	public String getUniquePath() throws TskCoreException {
		if (unique_path != null) {
			return unique_path;
		}

		StringBuilder sb = new StringBuilder();
		//prepend image and volume to file path
		Image image = this.getImage();
		StringTokenizer tok = new StringTokenizer(image.getName(), "/\\");
		String imageName = null;
		while (tok.hasMoreTokens()) {
			imageName = tok.nextToken();
		}
		sb.append("/").append(imageName);
		if (parentFileSystem != null) {
			Content vol = parentFileSystem.getParent();
			if (vol != null
					&& !vol.equals(image)) {
				sb.append("/");
				sb.append(vol.getName());
			}
		}

		sb.append(getParentPath());
		sb.append(getName());

		unique_path = sb.toString();
		return unique_path;
	}

	/**
	 * Get the md5 hash value as calculated, if present
	 *
	 * @return md5 hash string, if it is present
	 */
	public String getMd5Hash() {
		return this.md5Hash;
	}

	@Override
	public void finalize() {
		if (fileHandle != 0) {
			SleuthkitJNI.closeFile(fileHandle);
		}
	}

	/*
	 * -------------------------------------------------------------------------
	 * Util methods to convert / map the data
	 * -------------------------------------------------------------------------
	 */
	/**
	 * Return the epoch into string in ISO 8601 dateTime format
	 *
	 * @param epoch time in seconds
	 * @return formatted date time string as "yyyy-MM-dd HH:mm:ss"
	 */
	public static String epochToTime(long epoch) {
		String time = "0000-00-00 00:00:00";
		if (epoch != 0) {
			time = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new java.util.Date(epoch * 1000));
		}
		return time;
	}

	/**
	 * Convert from ISO 8601 formatted date time string to epoch time in seconds
	 *
	 * @param time formatted date time string as "yyyy-MM-dd HH:mm:ss"
	 * @return epoch time in seconds
	 */
	public static long timeToEpoch(String time) {
		long epoch = 0;
		try {
			epoch = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").parse(time).getTime() / 1000;
		} catch (Exception e) {
		}

		return epoch;
	}

	/*
	 * -------------------------------------------------------------------------
	 * Methods for Directory type conversion / mapping ---
	 * -------------------------------------------------------------------------
	 */
	/**
	 * Get a string value of a directory type from dir type id as defined in
	 * TSK_FS_NAME_TYPE_ENUM
	 *
	 * @param dirType to convert
	 * @return dir type value string representation
	 */
	public static String dirTypeToValue(long dirType) {

		String result = "";

		for (TskData.TSK_FS_NAME_TYPE_ENUM type : TskData.TSK_FS_NAME_TYPE_ENUM.values()) {
			if (type.getDirType() == dirType) {
				result = type.toString();
			}
		}
		return result;
	}

	/**
	 * Get a value type id from value type string
	 *
	 * @param dirType value string to convert
	 * @return directory type id
	 */
	public static long valueToDirType(String dirType) {

		long result = 0;

		for (TskData.TSK_FS_NAME_TYPE_ENUM type : TskData.TSK_FS_NAME_TYPE_ENUM.values()) {
			if (type.toString().equals(dirType)) {
				result = type.getDirType();
			}
		}
		return result;
	}

	/**
	 * Get a dir type label string from dir type id
	 *
	 * @param dirType dir type id to convert
	 * @return dir type label string
	 */
	public static String dirTypeToString(long dirType) {
		return TskData.TSK_FS_NAME_TYPE_ENUM.fromType(dirType).getLabel();
	}

	// -------- Methods for Meta Type conversion / mapping --------
	/**
	 * Convert meta type id to string value
	 *
	 * @param metaType to convert
	 * @return string value representation of meta type
	 */
	public static String metaTypeToValue(long metaType) {

		String result = "";

		for (TskData.TSK_FS_META_TYPE_ENUM type : TskData.TSK_FS_META_TYPE_ENUM.values()) {
			if (type.getMetaType() == metaType) {
				result = type.toString();
			}
		}
		return result;
	}

	/**
	 * Convert meta type string value to meta type id
	 *
	 * @param metaType to convert
	 * @return meta type id
	 */
	public static long valueToMetaType(String metaType) {

		long result = 0;

		for (TskData.TSK_FS_META_TYPE_ENUM type : TskData.TSK_FS_META_TYPE_ENUM.values()) {
			if (type.toString().equals(metaType)) {
				result = type.getMetaType();
			}
		}
		return result;
	}

	/**
	 * Convert meta type id to string representation
	 *
	 * @param metaType to convert
	 * @return string representation of the meta type
	 */
	public static String metaTypeToString(long metaType) {
		return TskData.tsk_fs_meta_type_str[(int) metaType];
	}

// ----- Methods for Directory Flags conversion / mapping -----
	/**
	 * Convert dir flags to string value
	 *
	 * @param dirFlag to convert
	 * @return dir flags string representation
	 */
	public static String dirFlagToValue(long dirFlag) {

		String result = "";

		for (TskData.TSK_FS_NAME_FLAG_ENUM flag : TskData.TSK_FS_NAME_FLAG_ENUM.values()) {
			if (flag.getDirFlag() == dirFlag) {
				result = flag.toString();
			}
		}
		return result;
	}

	/**
	 * Convert string value to dir flag id
	 *
	 * @param dirFlag to convert
	 * @return dir flag id
	 */
	public static long valueToDirFlag(String dirFlag) {

		long result = 0;

		for (TskData.TSK_FS_NAME_FLAG_ENUM flag : TskData.TSK_FS_NAME_FLAG_ENUM.values()) {
			if (flag.toString().equals(dirFlag)) {
				result = flag.getDirFlag();
			}
		}
		return result;
	}

	/**
	 * Convert dir flag to user displayable string
	 *
	 * @param dirFlag dir flags id to convert
	 * @return formatted user-readable string representation of dir flag
	 */
	public static String dirFlagToString(long dirFlag) {

		String result = "";

		long allocFlag = TskData.TSK_FS_NAME_FLAG_ENUM.TSK_FS_NAME_FLAG_ALLOC.getDirFlag();
		long unallocFlag = TskData.TSK_FS_NAME_FLAG_ENUM.TSK_FS_NAME_FLAG_UNALLOC.getDirFlag();

		if ((dirFlag & allocFlag) == allocFlag) {
			result = "Allocated";
		}
		if ((dirFlag & unallocFlag) == unallocFlag) {
			result = "Unallocated";
		}

		return result;
	}

	// ----- Methods for Meta Flags conversion / mapping -----
	/**
	 * Convert meta flags to string value
	 *
	 * @param metaFlag to convert
	 * @return string representation
	 */
	public static String metaFlagToValue(long metaFlag) {

		String result = "";

		for (TskData.TSK_FS_META_FLAG_ENUM flag : TskData.TSK_FS_META_FLAG_ENUM.values()) {
			if (flag.getMetaFlag() == metaFlag) {
				result = flag.toString();
			}
		}
		return result;
	}

	/**
	 * Convert string representation of meta flags to long
	 *
	 * @param metaFlag string to convert
	 * @return long meta flag representation
	 */
	public static long valueToMetaFlag(String metaFlag) {

		long result = 0;

		for (TskData.TSK_FS_META_FLAG_ENUM flag : TskData.TSK_FS_META_FLAG_ENUM.values()) {
			if (flag.toString().equals(metaFlag)) {
				result = flag.getMetaFlag();
			}
		}
		return result;
	}

	/**
	 * Convert meta flag long to user-readable string / label
	 *
	 * @param metaFlag to convert
	 * @return string formatted meta flag representation
	 */
	public static String metaFlagToString(long metaFlag) {

		String result = "";

		long allocFlag = TskData.TSK_FS_META_FLAG_ENUM.ALLOC.getMetaFlag();
		long unallocFlag = TskData.TSK_FS_META_FLAG_ENUM.UNALLOC.getMetaFlag();

		// some variables that might be needed in the future
		long usedFlag = TskData.TSK_FS_META_FLAG_ENUM.USED.getMetaFlag();
		long unusedFlag = TskData.TSK_FS_META_FLAG_ENUM.UNUSED.getMetaFlag();
		long compFlag = TskData.TSK_FS_META_FLAG_ENUM.COMP.getMetaFlag();
		long orphanFlag = TskData.TSK_FS_META_FLAG_ENUM.ORPHAN.getMetaFlag();

		if ((metaFlag & allocFlag) == allocFlag) {
			result = TskData.TSK_FS_META_FLAG_ENUM.ALLOC.getLabel();
		}
		if ((metaFlag & unallocFlag) == unallocFlag) {
			result = TskData.TSK_FS_META_FLAG_ENUM.UNALLOC.getLabel();
		}


		return result;
	}

	/**
	 * Convert mode and meta type to a user-displayable string
	 *
	 * @param mode mode attribute of the file/dir
	 * @param metaType meta type attribute of the file/dir
	 * @return converted, formatted user-displayable string
	 */
	public static String modeToString(long mode, long metaType) {

		String result = "";

		long metaTypeMax = TskData.TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_STR_MAX.getMetaType();

		long isuid = TskData.TSK_FS_META_MODE_ENUM.TSK_FS_META_MODE_ISUID.getMode();
		long isgid = TskData.TSK_FS_META_MODE_ENUM.TSK_FS_META_MODE_ISGID.getMode();
		long isvtx = TskData.TSK_FS_META_MODE_ENUM.TSK_FS_META_MODE_ISVTX.getMode();

		long irusr = TskData.TSK_FS_META_MODE_ENUM.TSK_FS_META_MODE_IRUSR.getMode();
		long iwusr = TskData.TSK_FS_META_MODE_ENUM.TSK_FS_META_MODE_IWUSR.getMode();
		long ixusr = TskData.TSK_FS_META_MODE_ENUM.TSK_FS_META_MODE_IXUSR.getMode();

		long irgrp = TskData.TSK_FS_META_MODE_ENUM.TSK_FS_META_MODE_IRGRP.getMode();
		long iwgrp = TskData.TSK_FS_META_MODE_ENUM.TSK_FS_META_MODE_IWGRP.getMode();
		long ixgrp = TskData.TSK_FS_META_MODE_ENUM.TSK_FS_META_MODE_IXGRP.getMode();

		long iroth = TskData.TSK_FS_META_MODE_ENUM.TSK_FS_META_MODE_IROTH.getMode();
		long iwoth = TskData.TSK_FS_META_MODE_ENUM.TSK_FS_META_MODE_IWOTH.getMode();
		long ixoth = TskData.TSK_FS_META_MODE_ENUM.TSK_FS_META_MODE_IXOTH.getMode();

		// first character = the Meta Type
		if (metaType < metaTypeMax) {
			result += FsContent.metaTypeToString(metaType);
		} else {
			result += "-";
		}

		// second and third characters = user permissions
		if ((mode & irusr) == irusr) {
			result += "r";
		} else {
			result += "-";
		}
		if ((mode & iwusr) == iwusr) {
			result += "w";
		} else {
			result += "-";
		}

		// fourth character = set uid
		if ((mode & isuid) == isuid) {
			if ((mode & ixusr) == ixusr) {
				result += "s";
			} else {
				result += "S";
			}
		} else {
			if ((mode & ixusr) == ixusr) {
				result += "x";
			} else {
				result += "-";
			}
		}

		// fifth and sixth characters = group permissions
		if ((mode & irgrp) == irgrp) {
			result += "r";
		} else {
			result += "-";
		}
		if ((mode & iwgrp) == iwgrp) {
			result += "w";
		} else {
			result += "-";
		}

		// seventh character = set gid
		if ((mode & isgid) == isgid) {
			if ((mode & ixgrp) == ixgrp) {
				result += "s";
			} else {
				result += "S";
			}
		} else {
			if ((mode & ixgrp) == ixgrp) {
				result += "x";
			} else {
				result += "-";
			}
		}

		// eighth and ninth character = other permissions
		if ((mode & iroth) == iroth) {
			result += "r";
		} else {
			result += "-";
		}
		if ((mode & iwoth) == iwoth) {
			result += "w";
		} else {
			result += "-";
		}

		// tenth character = sticky bit
		if ((mode & isvtx) == isvtx) {
			if ((mode & ixoth) == ixoth) {
				result += "t";
			} else {
				result += "T";
			}
		} else {
			if ((mode & ixoth) == ixoth) {
				result += "x";
			} else {
				result += "-";
			}
		}

		// check the result
		if (result.length() != 10) {
			// throw error here
			result = "ERROR";
		}
		return result;
	}
}
