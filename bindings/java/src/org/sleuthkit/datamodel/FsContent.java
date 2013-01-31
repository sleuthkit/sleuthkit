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
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.sleuthkit.datamodel.TskData.FileKnown;
import org.sleuthkit.datamodel.TskData.TSK_FS_META_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_FLAG_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_ATTR_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_META_MODE_ENUM;

/**
 * Generalized class that stores metadata that are common to both File and
 * Directory objects stored in tsk_files table Caches internal tsk file handle
 * and reuses it for reads
 *
 * TODO move common getters to AbstractFile class
 */
public abstract class FsContent extends AbstractFile {

	private static final Logger logger = Logger.getLogger(AbstractFile.class.getName());
	///read only database tsk_files fields
	protected final long metaAddr, ctime, crtime, atime, mtime;
	protected final long fsObjId;
	protected final int uid, gid;
	protected final short attrId;
	protected final TSK_FS_ATTR_TYPE_ENUM attrType;
	protected final Set<TSK_FS_META_MODE_ENUM> modes;
	private String uniquePath;
	///read-write database tsk_files fields
	/**
	 * parent file system
	 */
	private volatile FileSystem parentFileSystem;
	/**
	 * known status in database
	 */
	protected FileKnown known;
	/*
	 * md5 hash
	 */
	protected String md5Hash;
	///other members
	/**
	 * file Handle
	 */
	protected volatile long fileHandle = 0;

	/**
	 * Constructor to create FsContent object instance from database
	 *
	 * @param db
	 * @param objId
	 * @param fsObjId
	 * @param name
	 * @param meta_addr
	 * @param attrType
	 * @param attr_id
	 * @param dirType
	 * @param metaType
	 * @param dirFlag
	 * @param meta_flags
	 * @param size
	 * @param ctime
	 * @param crtime
	 * @param atime
	 * @param mtime
	 * @param uid
	 * @param gid
	 * @param modes
	 * @param known
	 * @param parentPath
	 * @param md5Hash
	 */
	FsContent(SleuthkitCase db, long objId, long fsObjId, String name, long meta_addr,
			TSK_FS_ATTR_TYPE_ENUM attrType, short attr_id,
			TSK_FS_NAME_TYPE_ENUM dirType, TSK_FS_META_TYPE_ENUM metaType, TSK_FS_NAME_FLAG_ENUM dirFlag, short meta_flags,
			long size, long ctime, long crtime, long atime, long mtime, int uid, int gid, short modes, FileKnown known,
			String parentPath, String md5Hash) {
		super(db, objId, name, TskData.TSK_DB_FILES_TYPE_ENUM.FS, dirType, metaType, dirFlag, meta_flags, size, parentPath);
		this.metaAddr = meta_addr;
		this.attrType = attrType;
		this.attrId = attr_id;
		this.ctime = ctime;
		this.crtime = crtime;
		this.atime = atime;
		this.mtime = mtime;
		this.uid = uid;
		this.gid = gid;
		this.modes = TSK_FS_META_MODE_ENUM.valuesOf(modes);
		this.known = known;
		if (md5Hash.equals("NULL")) {
			this.md5Hash = null;
		} else {
			this.md5Hash = md5Hash;
		}
		this.fsObjId = fsObjId;

	}

	/**
	 * Get the parent file system id
	 *
	 * @return the parent file system id
	 */
	public long getFileSystemId() {
		return fsObjId;
	}

	/**
	 * Sets the parent file system, called by parent during object creation
	 *
	 * @param parent parent file system object
	 */
	void setFileSystem(FileSystem parent) {
		parentFileSystem = parent;
	}

	/**
	 * Get the parent file system
	 *
	 * @return the file system object of the parent
	 */
	public synchronized FileSystem getFileSystem() throws TskCoreException {
		if (parentFileSystem == null) {
			parentFileSystem = getSleuthkitCase().getFileSystemById(fsObjId, AbstractContent.UNKNOWN_ID);
		}
		return parentFileSystem;
	}

	/**
	 * Sets md5 hash string Note: database or other FsContent objects are not
	 * updated. Currently only SleuthkiCase calls it to update the object while
	 * updating tsk_files entry
	 *
	 * @param md5Hash
	 */
	void setMd5Hash(String md5Hash) {
		this.md5Hash = md5Hash;
	}

	/**
	 * Sets known status Note: database or other FsContent objects are not
	 * updated. Currently only SleuthkiCase calls it to update the object while
	 * updating tsk_files entry
	 *
	 * @param known
	 */
	void setKnown(FileKnown known) {
		this.known = known;
	}

	@Override
	public int read(byte[] buf, long offset, long len) throws TskCoreException {
		if (offset == 0 && size == 0) {
			//special case for 0-size file
			return 0;
		}
		synchronized (this) {
			if (fileHandle == 0) {
				fileHandle = SleuthkitJNI.openFile(getFileSystem().getFileSystemHandle(), metaAddr, attrType, attrId);
			}
		}
		return SleuthkitJNI.readFile(fileHandle, buf, offset, len);
	}

	@Override
	public boolean isRoot() {
		FileSystem fs = null;
		try {
			fs = getFileSystem();
		} catch (TskCoreException ex) {
			logger.log(Level.SEVERE, "Exception while calling 'getFileSystem' on " + this, ex);
			return false;
		}
		return fs.getRoot_inum() == this.getMetaAddr();
	}

	/*
	 * -------------------------------------------------------------------------
	 * Getters to retrieve meta-data attributes values
	 * -------------------------------------------------------------------------
	 */
	/**
	 * Gets parent directory
	 *
	 * @return the parent Directory
	 * @throws TskCoreException exception thrown if error occurred in tsk core
	 */
	public AbstractFile getParentDirectory() throws TskCoreException {
		return getSleuthkitCase().getParentDirectory(this);
	}

	@Override
	public Image getImage() throws TskCoreException {
		return getFileSystem().getImage();
	}

	/**
	 * Get the attribute type
	 *
	 * @return attribute type
	 */
	public TSK_FS_ATTR_TYPE_ENUM getAttrType() {
		return attrType;
	}

	/**
	 * Get the attribute id
	 *
	 * @return attribute id
	 */
	public short getAttrId() {
		return attrId;
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
	public int getUid() {
		return uid;
	}

	/**
	 * Get the group id
	 *
	 * @return group id
	 */
	public int getGid() {
		return gid;
	}

	/**
	 * Get the file meta address
	 *
	 * @return Address of the meta data structure
	 */
	public long getMetaAddr() {
		return metaAddr;
	}

	/**
	 * Convert mode and meta type to a user-displayable string
	 *
	 * @param mode mode attribute of the file/dir
	 * @param metaType meta type attribute of the file/dir
	 * @return converted, formatted user-displayable string
	 */
	public String getModesAsString() {
		int mode = TSK_FS_META_MODE_ENUM.toInt(modes);
		String result = "";

		short isuid = TskData.TSK_FS_META_MODE_ENUM.TSK_FS_META_MODE_ISUID.getMode();
		short isgid = TskData.TSK_FS_META_MODE_ENUM.TSK_FS_META_MODE_ISGID.getMode();
		short isvtx = TskData.TSK_FS_META_MODE_ENUM.TSK_FS_META_MODE_ISVTX.getMode();

		short irusr = TskData.TSK_FS_META_MODE_ENUM.TSK_FS_META_MODE_IRUSR.getMode();
		short iwusr = TskData.TSK_FS_META_MODE_ENUM.TSK_FS_META_MODE_IWUSR.getMode();
		short ixusr = TskData.TSK_FS_META_MODE_ENUM.TSK_FS_META_MODE_IXUSR.getMode();

		short irgrp = TskData.TSK_FS_META_MODE_ENUM.TSK_FS_META_MODE_IRGRP.getMode();
		short iwgrp = TskData.TSK_FS_META_MODE_ENUM.TSK_FS_META_MODE_IWGRP.getMode();
		short ixgrp = TskData.TSK_FS_META_MODE_ENUM.TSK_FS_META_MODE_IXGRP.getMode();

		short iroth = TskData.TSK_FS_META_MODE_ENUM.TSK_FS_META_MODE_IROTH.getMode();
		short iwoth = TskData.TSK_FS_META_MODE_ENUM.TSK_FS_META_MODE_IWOTH.getMode();
		short ixoth = TskData.TSK_FS_META_MODE_ENUM.TSK_FS_META_MODE_IXOTH.getMode();

		// first character = the Meta Type
		result += metaType.toString();

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

	public boolean isModeSet(TSK_FS_META_MODE_ENUM mode) {
		return modes.contains(mode);
	}

	/**
	 * Get "known" file status - after running a HashDB ingest on it As marked
	 * by a known file database, such as NSRL
	 *
	 * @return file known status enum value
	 */
	public FileKnown getKnown() {
		return known;
	}

	@Override
	public synchronized String getUniquePath() throws TskCoreException {
		if (uniquePath == null) {
			StringBuilder sb = new StringBuilder();
			sb.append(getFileSystem().getUniquePath());
			sb.append(getParentPath());
			sb.append(getName());
			uniquePath = sb.toString();
		}
		return uniquePath;
	}

	/**
	 * Get the md5 hash value as calculated, if present
	 *
	 * @return md5 hash string, if it is present or null if it is not
	 */
	public String getMd5Hash() {
		return this.md5Hash;
	}

	@Override
	public void finalize() throws Throwable {
		try {
			if (fileHandle != 0) {
				SleuthkitJNI.closeFile(fileHandle);
				fileHandle = 0;
			}
		} finally {
			super.finalize();
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
}
