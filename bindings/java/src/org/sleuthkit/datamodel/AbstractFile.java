/*
 * Autopsy Forensic Browser
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

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.sleuthkit.datamodel.TskData.FileKnown;
import org.sleuthkit.datamodel.TskData.TSK_FS_META_FLAG_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_META_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_FLAG_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_TYPE_ENUM;

/**
 * Common fields methods for objects stored in tsk_files table Abstract files
 * are divided into subtypes defined in TSK_DB_FILES_TYPE_ENUM and further
 * divided into files and directories
 */
public abstract class AbstractFile extends AbstractContent {

	protected final TskData.TSK_DB_FILES_TYPE_ENUM fileType;
	protected final TSK_FS_NAME_TYPE_ENUM dirType;
	protected final TSK_FS_META_TYPE_ENUM metaType;
	protected final TSK_FS_NAME_FLAG_ENUM dirFlag;
	protected final Set<TSK_FS_META_FLAG_ENUM> metaFlags;
	protected long size;
	protected final long metaAddr, ctime, crtime, atime, mtime;
	protected final int uid, gid;
	protected final short attrId;
	protected final TskData.TSK_FS_ATTR_TYPE_ENUM attrType;
	protected final Set<TskData.TSK_FS_META_MODE_ENUM> modes;
	
	private List<TskFileRange> ranges;
	
	/*
	 * path of parent directory
	 */
	protected final String parentPath;
	/**
	 * knownState status in database
	 */
	protected TskData.FileKnown knownState;
	/*
	 * md5 hash
	 */
	protected String md5Hash;

	/**
	 * Initializes common fields used by AbstactFile implementations (objects in
	 * tsk_files table)
	 *
	 * @param db case / db handle where this file belongs to
	 * @param objId object id in tsk_objects table
	 * @param attrType
	 * @param attrId
	 * @param name name field of the file
	 * @param fileType type of the file
	 * @param metaAddr
	 * @param dirType
	 * @param metaType
	 * @param dirFlag
	 * @param metaFlags
	 * @param size
	 * @param ctime
	 * @param crtime
	 * @param atime
	 * @param mtime
	 * @param modes
	 * @param uid
	 * @param gid
	 * @param md5Hash md5sum of the file, or null or "NULL" if not present
	 * @param knownState knownState status of the file, or null if unknown
	 * (default)
	 * @param parentPath
	 */
	protected AbstractFile(SleuthkitCase db, long objId, TskData.TSK_FS_ATTR_TYPE_ENUM attrType, short attrId,
			String name, TskData.TSK_DB_FILES_TYPE_ENUM fileType, long metaAddr,
			TSK_FS_NAME_TYPE_ENUM dirType, TSK_FS_META_TYPE_ENUM metaType, TSK_FS_NAME_FLAG_ENUM dirFlag, short metaFlags,
			long size, long ctime, long crtime, long atime, long mtime, short modes, int uid, int gid, String md5Hash, FileKnown knownState,
			String parentPath) {
		super(db, objId, name);
		this.attrType = attrType;
		this.attrId = attrId;
		this.fileType = fileType;
		this.metaAddr = metaAddr;
		this.dirType = dirType;
		this.metaType = metaType;
		this.dirFlag = dirFlag;
		this.metaFlags = TSK_FS_META_FLAG_ENUM.valuesOf(metaFlags);
		this.size = size;
		this.ctime = ctime;
		this.crtime = crtime;
		this.atime = atime;
		this.mtime = mtime;
		this.uid = uid;
		this.gid = gid;
		this.modes = TskData.TSK_FS_META_MODE_ENUM.valuesOf(modes);

		this.md5Hash = md5Hash;
		if (knownState == null) {
			this.knownState = FileKnown.UKNOWN;
		} else {
			this.knownState = knownState;
		}
		this.parentPath = parentPath;
	}

	/**
	 * Gets type of the abstract file as defined in TSK_DB_FILES_TYPE_ENUM
	 *
	 * @return the type of the abstract file
	 */
	public TskData.TSK_DB_FILES_TYPE_ENUM getType() {
		return fileType;
	}

	/**
	 * Get the attribute type
	 *
	 * @return attribute type
	 */
	public TskData.TSK_FS_ATTR_TYPE_ENUM getAttrType() {
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
	 * Get the file's mode as a user-displayable string
	 *
	 * @return formatted user-displayable string for mode
	 */
	public String getModesAsString() {
		int mode = TskData.TSK_FS_META_MODE_ENUM.toInt(modes);
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

	public boolean isModeSet(TskData.TSK_FS_META_MODE_ENUM mode) {
		return modes.contains(mode);
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
	 * Get the md5 hash value as calculated, if present
	 *
	 * @return md5 hash string, if it is present or null if it is not
	 */
	public String getMd5Hash() {
		return this.md5Hash;
	}

	/**
	 * Sets knownState status Note: database or other file objects are not
	 * updated. Currently only SleuthkiCase calls it to update the object while
	 * updating tsk_files entry
	 *
	 * @param knownState
	 */
	void setKnown(TskData.FileKnown known) {
		this.knownState = known;
	}

	/**
	 * Get "knownState" file status - after running a HashDB ingest on it As
	 * marked by a knownState file database, such as NSRL
	 *
	 * @return file knownState status enum value
	 */
	public TskData.FileKnown getKnown() {
		return knownState;
	}

	/**
	 * Get size of the file
	 *
	 * @return file size in bytes
	 */
	@Override
	public long getSize() {
		return size;
	}

	/**
	 * Get path of the parent of this file
	 *
	 * @return path string of the parent
	 */
	public String getParentPath() {
		return parentPath;
	}

	/**
	 * Gets file ranges associated with the file. File ranges are objects in
	 * tsk_file_layout table Any file type (especially unallocated) may have 1
	 * or more block ranges associated with it
	 *
	 * @return list of file layout ranges
	 * @throws TskCoreException exception thrown if critical error occurred
	 * within tsk core
	 */
	public List<TskFileRange> getRanges() throws TskCoreException {
		if(ranges == null) {
            ranges = getSleuthkitCase().getFileRanges(this.getId());
        }
        return ranges;
	}
	
	/**
	 * Convert an internal offset to an image offset
	 * @param fileOffset the byte offset in this layout file to map
	 * @return the corresponding byte offset in the image where the file offset is located,
	 * or -1 if the file has no range layout information or if the fileOffset is larger than file size
	 * @throws TskCoreException exception thrown if critical error occurred within tsk core and offset could not be converted
	 */
	public long convertToImgOffset(long fileOffset) throws TskCoreException {
		long imgOffset = -1;
		for (TskFileRange byteRange : getRanges()) {
			
			// if fileOffset is within the current byteRange, calcuate the image
			// offset and break
			long rangeLength = byteRange.getByteLen();
			if (fileOffset < rangeLength) {
				imgOffset = byteRange.getByteStart() + fileOffset;
				break;
			}
			
			// otherwise, decrement fileOffset by the length of the current
			// byte range and continue
			fileOffset -= rangeLength;
		}
		return imgOffset;
	}

	/**
	 * is this a virtual file or directory
	 *
	 * @return true if it's virtual, false otherwise
	 */
	public boolean isVirtual() {
		return fileType.equals(TskData.TSK_DB_FILES_TYPE_ENUM.VIRTUAL_DIR)
				|| dirType.equals(TskData.TSK_FS_NAME_TYPE_ENUM.VIRT)
				|| metaType.equals(TskData.TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_VIRT);
	}

	/**
	 * Is this object a file
	 *
	 * @return true if a file, false otherwise
	 */
	public boolean isFile() {
		return metaType.equals(TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_REG);

	}

	/**
	 * Is this object a directory
	 *
	 * @return true if directory, false otherwise
	 */
	public boolean isDir() {
		return metaType.equals(TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_DIR);
	}

	/**
	 * Is this a root of a file system
	 *
	 * @return true if root of a file system, false otherwise
	 */
	public abstract boolean isRoot();

	/**
	 * @param uniquePath the unique path to an AbstractFile (or subclass)
	 * usually obtained by a call to AbstractFile.getUniquePath.
	 * @return the path to to an AbstractFile (or subclass) with the image and
	 * volume path segments removed.
	 */
	public static String createNonUniquePath(String uniquePath) {

		// split the path into parts
		String[] pathSegments = uniquePath.split("/\\");

		// see if uniquePath had an image and/or volume name
		int index = 0;
		if (pathSegments[0].startsWith("img_")) {
			++index;
		}
		if (pathSegments[1].startsWith("vol_")) {
			++index;
		}

		// Assemble the non-unique path (skipping over the image and volume
		// name, if they exist).
		StringBuilder strbuf = new StringBuilder();
		for (; index < pathSegments.length; ++index) {
			strbuf.append("/").append(pathSegments[index]);
		}

		return strbuf.toString();
	}

	/**
	 * @return a list of AbstractFiles that are the children of this Directory.
	 * Only returns children of type TskData.TSK_DB_FILES_TYPE_ENUM.FS.
	 */
	public List<AbstractFile> listFiles() throws TskCoreException {
		// first, get all children
		List<Content> children = getChildren();

		// only keep those that are of type AbstractFile
		List<AbstractFile> files = new ArrayList<AbstractFile>();
		for (Content child : children) {
			if (child instanceof AbstractFile) {
				AbstractFile afChild = (AbstractFile) child;
				files.add(afChild);
			}
		}
		return files;
	}

	/**
	 * Get the meta data type
	 *
	 * @return meta data type
	 */
	public TSK_FS_META_TYPE_ENUM getMetaType() {
		return metaType;
	}

	public String getMetaTypeAsString() {
		return metaType.toString();
	}

	/**
	 * Get the directory type id
	 *
	 * @return directory type id
	 */
	public TSK_FS_NAME_TYPE_ENUM getDirType() {
		return dirType;
	}

	public String getDirTypeAsString() {
		return dirType.toString();
	}

	/**
	 * @param flag the TSK_FS_NAME_FLAG_ENUM to check
	 * @return true if the given flag is set in this FsContent object.
	 */
	public boolean isDirNameFlagSet(TSK_FS_NAME_FLAG_ENUM flag) {
		return dirFlag == flag;
	}

	/**
	 * @return a string representation of the directory name flag (type
	 * TSK_FS_NAME_FLAG_ENUM)
	 */
	public String getDirFlagAsString() {
		return dirFlag.toString();
	}

	/**
	 * @return a string representation of the meta flags
	 */
	public String getMetaFlagsAsString() {
		String str = "";
		if (metaFlags.contains(TSK_FS_META_FLAG_ENUM.ALLOC)) {
			str = TSK_FS_META_FLAG_ENUM.ALLOC.toString();
		} else if (metaFlags.contains(TSK_FS_META_FLAG_ENUM.ALLOC)) {
			str = TSK_FS_META_FLAG_ENUM.UNALLOC.toString();
		}
		return str;
	}

	/**
	 * @param metaFlag the TSK_FS_META_FLAG_ENUM to check
	 * @return true if the given meta flag is set in this FsContent object.
	 */
	public boolean isMetaFlagSet(TSK_FS_META_FLAG_ENUM metaFlag) {
		return metaFlags.contains(metaFlag);
	}

		
	@Override
	public String toString(boolean preserveState) {
		return super.toString(preserveState) + "AbstractFile [\t" 
				+ "\t" + "fileType " + fileType
				+ "\tctime " + ctime 
				+ "\tcrtime " + crtime 
				+ "\t" + "mtime " + mtime + "\t" + "atime " + atime 
				+ "\t" + "attrId " + attrId 
				+ "\t" + "attrType " + attrType
				+ "\t" + "dirFlag " + dirFlag + "\t" + "dirType " + dirType 
				+ "\t" + "uid " + uid
				+ "\t" + "gid " + gid 
				+ "\t" + "metaAddr " + metaAddr + "\t" + "metaFlags " + metaFlags 
				+ "\t" + "metaType " + metaType + "\t" + "modes " + modes 
				+ "\t" + "parentPath " + parentPath + "\t" + "size " + size 
				+ "\t" + "knownState " + knownState + "\t" + "md5Hash " + md5Hash 
				+ "]\t";
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
