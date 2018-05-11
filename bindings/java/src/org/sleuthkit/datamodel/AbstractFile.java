/*
 * SleuthKit Java Bindings
 *
 * Copyright 2011-2018 Basis Technology Corp.
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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.SortedSet;
import java.util.TimeZone;
import java.util.logging.Level;
import java.util.logging.Logger;
import static org.sleuthkit.datamodel.SleuthkitCase.closeStatement;
import org.sleuthkit.datamodel.TskData.FileKnown;
import org.sleuthkit.datamodel.TskData.TSK_FS_META_FLAG_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_META_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_FLAG_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_TYPE_ENUM;

/**
 * An abstract base class for classes that represent files that have been added
 * to the case.
 */
public abstract class AbstractFile extends AbstractContent {

	protected final TskData.TSK_DB_FILES_TYPE_ENUM fileType;
	protected final TSK_FS_NAME_TYPE_ENUM dirType;
	protected final TSK_FS_META_TYPE_ENUM metaType;
	protected final TSK_FS_NAME_FLAG_ENUM dirFlag;
	protected final Set<TSK_FS_META_FLAG_ENUM> metaFlags;
	protected long size;
	protected final long metaAddr, ctime, crtime, atime, mtime;
	protected final int metaSeq;
	protected final int uid, gid;
	protected final int attrId;
	protected final TskData.TSK_FS_ATTR_TYPE_ENUM attrType;
	protected final Set<TskData.TSK_FS_META_MODE_ENUM> modes;
	//local file support
	private boolean localPathSet = false; ///< if set by setLocalPath(), reads are done on local file 
	private String localPath; ///< local path as stored in db tsk_files_path, is relative to the db, 
	private String localAbsPath; ///< absolute path representation of the local path
	private volatile RandomAccessFile localFileHandle;
	private volatile java.io.File localFile;
	private TskData.EncodingType encodingType;
	//range support
	private List<TskFileRange> ranges;
	/*
	 * path of parent directory
	 */
	protected final String parentPath;
	/**
	 * knownState status in database
	 */
	protected TskData.FileKnown knownState;
	private boolean knownStateDirty = false;
	/*
	 * md5 hash
	 */
	protected String md5Hash;
	private boolean md5HashDirty = false;
	private String mimeType;
	private boolean mimeTypeDirty = false;
	private static final Logger LOGGER = Logger.getLogger(AbstractFile.class.getName());
	private static final ResourceBundle BUNDLE = ResourceBundle.getBundle("org.sleuthkit.datamodel.Bundle");
	private long dataSourceObjectId;
	private final String extension;

	/**
	 * Initializes common fields used by AbstactFile implementations (objects in
	 * tsk_files table)
	 *
	 * @param db                 case / db handle where this file belongs to
	 * @param objId              object id in tsk_objects table
	 * @param dataSourceObjectId The object id of the root data source of this
	 *                           file.
	 * @param attrType
	 * @param attrId
	 * @param name               name field of the file
	 * @param fileType           type of the file
	 * @param metaAddr
	 * @param metaSeq
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
	 * @param md5Hash            md5sum of the file, or null or "NULL" if not
	 *                           present
	 * @param knownState         knownState status of the file, or null if
	 *                           unknown (default)
	 * @param parentPath
	 * @param mimeType           The MIME type of the file, can be null.
	 * @param extension		        The extension part of the file name (not
	 *                           including the '.'), can be null.
	 */
	AbstractFile(SleuthkitCase db,
			long objId,
			long dataSourceObjectId,
			TskData.TSK_FS_ATTR_TYPE_ENUM attrType, int attrId,
			String name,
			TskData.TSK_DB_FILES_TYPE_ENUM fileType,
			long metaAddr, int metaSeq,
			TSK_FS_NAME_TYPE_ENUM dirType, TSK_FS_META_TYPE_ENUM metaType,
			TSK_FS_NAME_FLAG_ENUM dirFlag, short metaFlags,
			long size,
			long ctime, long crtime, long atime, long mtime,
			short modes,
			int uid, int gid,
			String md5Hash, FileKnown knownState,
			String parentPath,
			String mimeType,
			String extension) {
		super(db, objId, name);
		this.dataSourceObjectId = dataSourceObjectId;
		this.attrType = attrType;
		this.attrId = attrId;
		this.fileType = fileType;
		this.metaAddr = metaAddr;
		this.metaSeq = metaSeq;
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
			this.knownState = FileKnown.UNKNOWN;
		} else {
			this.knownState = knownState;
		}
		this.parentPath = parentPath;
		this.mimeType = mimeType;
		this.extension = extension == null ? "" : extension;
		this.encodingType = TskData.EncodingType.NONE;
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
	public int getAttributeId() {
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
	 * Get the change time as Date (in local timezone)
	 *
	 * @return change time as Date
	 */
	public String getCtimeAsDate() {
		return epochToTime(ctime);
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
	 * Get the creation time as Date (in local timezone)
	 *
	 * @return creation time as Date
	 */
	public String getCrtimeAsDate() {
		return epochToTime(crtime);
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
	 * Get the access time as Date (in local timezone)
	 *
	 * @return access time as Date
	 */
	public String getAtimeAsDate() {
		return epochToTime(atime);
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
	 * Get the modified time as Date (in local timezone)
	 *
	 * @return modified time as Date
	 */
	public String getMtimeAsDate() {
		return epochToTime(mtime);
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
	 * Get the file meta address sequence. Only useful with NTFS. Incremented
	 * each time a structure is re-allocated.
	 *
	 * @return Address of the meta data structure sequence.
	 */
	public long getMetaSeq() {
		return metaSeq;
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
			result += "r"; //NON-NLS
		} else {
			result += "-"; //NON-NLS
		}
		if ((mode & iwusr) == iwusr) {
			result += "w"; //NON-NLS
		} else {
			result += "-"; //NON-NLS
		}

		// fourth character = set uid
		if ((mode & isuid) == isuid) {
			if ((mode & ixusr) == ixusr) {
				result += "s"; //NON-NLS
			} else {
				result += "S"; //NON-NLS
			}
		} else {
			if ((mode & ixusr) == ixusr) {
				result += "x"; //NON-NLS
			} else {
				result += "-"; //NON-NLS
			}
		}

		// fifth and sixth characters = group permissions
		if ((mode & irgrp) == irgrp) {
			result += "r"; //NON-NLS
		} else {
			result += "-"; //NON-NLS
		}
		if ((mode & iwgrp) == iwgrp) {
			result += "w"; //NON-NLS
		} else {
			result += "-"; //NON-NLS
		}

		// seventh character = set gid
		if ((mode & isgid) == isgid) {
			if ((mode & ixgrp) == ixgrp) {
				result += "s"; //NON-NLS
			} else {
				result += "S"; //NON-NLS
			}
		} else {
			if ((mode & ixgrp) == ixgrp) {
				result += "x"; //NON-NLS
			} else {
				result += "-"; //NON-NLS
			}
		}

		// eighth and ninth character = other permissions
		if ((mode & iroth) == iroth) {
			result += "r"; //NON-NLS
		} else {
			result += "-"; //NON-NLS
		}
		if ((mode & iwoth) == iwoth) {
			result += "w"; //NON-NLS
		} else {
			result += "-"; //NON-NLS
		}

		// tenth character = sticky bit
		if ((mode & isvtx) == isvtx) {
			if ((mode & ixoth) == ixoth) {
				result += "t"; //NON-NLS
			} else {
				result += "T"; //NON-NLS
			}
		} else {
			if ((mode & ixoth) == ixoth) {
				result += "x"; //NON-NLS
			} else {
				result += "-"; //NON-NLS
			}
		}

		// check the result
		if (result.length() != 10) {
			// throw error here
			result = "ERROR"; //NON-NLS
		}
		return result;
	}

	/**
	 * Gets the MIME type of this file.
	 *
	 * @return The MIME type name or null if the MIME type has not been set.
	 */
	public String getMIMEType() {
		return mimeType;
	}

	/**
	 * Sets the MIME type for this file.
	 *
	 * IMPORTANT: The MIME type is set for this AbstractFile object, but it is
	 * not saved to the case database until AbstractFile.save is called.
	 *
	 * @param mimeType The MIME type of this file.
	 */
	public void setMIMEType(String mimeType) {
		this.mimeType = mimeType;
		this.mimeTypeDirty = true;
	}

	public boolean isModeSet(TskData.TSK_FS_META_MODE_ENUM mode) {
		return modes.contains(mode);
	}

	/**
	 * Sets the MD5 hash for this file.
	 *
	 * IMPORTANT: The MD5 hash is set for this AbstractFile object, but it is
	 * not saved to the case database until AbstractFile.save is called.
	 *
	 * @param md5Hash The MD5 hash of the file.
	 */
	public void setMd5Hash(String md5Hash) {
		this.md5Hash = md5Hash;
		this.md5HashDirty = true;
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
	 * Sets the known state for this file.
	 *
	 * IMPORTANT: The known state is set for this AbstractFile object, but it is
	 * not saved to the case database until AbstractFile.save is called.
	 *
	 * @param knownState The known state of the file.
	 */
	public void setKnown(TskData.FileKnown knownState) {
		this.knownState = knownState;
		this.knownStateDirty = true;
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
	 * Get the extension part of the filename, if there is one. We assume that
	 * extensions only have ASCII alphanumeric chars
	 *
	 * @return The filename extension in lowercase (not including the period) or
	 *         empty string if there is no extension
	 */
	public String getNameExtension() {
		return extension;
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
	 * Gets the data source for this file.
	 *
	 * @return The data source.
	 *
	 * @throws TskCoreException if there was an error querying the case
	 *                          database.
	 */
	@Override
	public Content getDataSource() throws TskCoreException {
		return getSleuthkitCase().getContentById(this.dataSourceObjectId);
	}

	/**
	 * Gets the object id of the data source for this file.
	 *
	 * @return The object id of the data source.
	 */
	long getDataSourceObjectId() {
		return dataSourceObjectId;
	}

	/**
	 * Gets file ranges associated with the file. File ranges are objects in
	 * tsk_file_layout table Any file type (especially unallocated) may have 1
	 * or more block ranges associated with it
	 *
	 * @return list of file layout ranges
	 *
	 * @throws TskCoreException exception thrown if critical error occurred
	 *                          within tsk core
	 */
	public List<TskFileRange> getRanges() throws TskCoreException {
		if (ranges == null) {
			ranges = getSleuthkitCase().getFileRanges(this.getId());
		}
		return ranges;
	}

	/**
	 * Convert an internal offset to an image offset
	 *
	 * @param fileOffset the byte offset in this layout file to map
	 *
	 * @return the corresponding byte offset in the image where the file offset
	 *         is located, or -1 if the file has no range layout information or
	 *         if the fileOffset is larger than file size
	 *
	 * @throws TskCoreException exception thrown if critical error occurred
	 *                          within tsk core and offset could not be
	 *                          converted
	 */
	public long convertToImgOffset(long fileOffset) throws TskCoreException {
		long imgOffset = -1;
		for (TskFileRange byteRange : getRanges()) {

			// if fileOffset is within the current byteRange, calculate the image
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
	 * is this a virtual file or directory that was created by The Sleuth Kit or
	 * Autopsy for general structure and organization.
	 *
	 * @return true if it's virtual, false otherwise
	 */
	public boolean isVirtual() {
		return fileType.equals(TskData.TSK_DB_FILES_TYPE_ENUM.VIRTUAL_DIR)
				|| dirType.equals(TskData.TSK_FS_NAME_TYPE_ENUM.VIRT)
				|| metaType.equals(TskData.TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_VIRT);
	}

	/**
	 * Is this object a file. Should return true for all types of files,
	 * including file system, logical, derived, layout, and slack space for
	 * files.
	 *
	 * @return true if a file, false otherwise
	 */
	public boolean isFile() {
		return metaType.equals(TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_REG)
				|| (metaType.equals(TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_UNDEF)
				&& dirType.equals(TSK_FS_NAME_TYPE_ENUM.REG));

	}

	/**
	 * Is this object a directory. Should return true for file system folders
	 * and virtual folders.
	 *
	 * @return true if directory, false otherwise
	 */
	public boolean isDir() {
		return (metaType.equals(TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_DIR)
				|| metaType.equals(TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_VIRT_DIR));
	}

	/**
	 * Is this a root of a file system
	 *
	 * @return true if root of a file system, false otherwise
	 */
	public abstract boolean isRoot();

	/**
	 * @param uniquePath the unique path to an AbstractFile (or subclass)
	 *                   usually obtained by a call to
	 *                   AbstractFile.getUniquePath.
	 *
	 * @return the path to to an AbstractFile (or subclass) with the image and
	 *         volume path segments removed.
	 */
	public static String createNonUniquePath(String uniquePath) {

		// split the path into parts
		String[] pathSegments = uniquePath.split("/");

		// see if uniquePath had an image and/or volume name
		int index = 0;
		if (pathSegments[0].startsWith("img_")) { //NON-NLS
			++index;
		}
		if (pathSegments[1].startsWith("vol_")) { //NON-NLS
			++index;
		}

		// Assemble the non-unique path (skipping over the image and volume
		// name, if they exist).
		StringBuilder strbuf = new StringBuilder();
		for (; index < pathSegments.length; ++index) {
			if (!pathSegments[index].isEmpty()) {
				strbuf.append("/").append(pathSegments[index]);
			}
		}

		return strbuf.toString();
	}

	/**
	 * @return a list of AbstractFiles that are the children of this Directory.
	 *         Only returns children of type TskData.TSK_DB_FILES_TYPE_ENUM.FS.
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException
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
	 *
	 * @return true if the given flag is set in this FsContent object.
	 */
	public boolean isDirNameFlagSet(TSK_FS_NAME_FLAG_ENUM flag) {
		return dirFlag == flag;
	}

	/**
	 * @return a string representation of the directory name flag (type
	 *         TSK_FS_NAME_FLAG_ENUM)
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
		} else if (metaFlags.contains(TSK_FS_META_FLAG_ENUM.UNALLOC)) {
			str = TSK_FS_META_FLAG_ENUM.UNALLOC.toString();
		}
		return str;
	}

	/**
	 * @param metaFlag the TSK_FS_META_FLAG_ENUM to check
	 *
	 * @return true if the given meta flag is set in this FsContent object.
	 */
	public boolean isMetaFlagSet(TSK_FS_META_FLAG_ENUM metaFlag) {
		return metaFlags.contains(metaFlag);
	}

	@Override
	public final int read(byte[] buf, long offset, long len) throws TskCoreException {
		//template method
		//if localPath is set, use local, otherwise, use readCustom() supplied by derived class
		if (localPathSet) {
			return readLocal(buf, offset, len);
		} else {
			return readInt(buf, offset, len);
		}

	}

	/**
	 * Internal custom read (non-local) method that child classes can implement
	 *
	 * @param buf    buffer to read into
	 * @param offset start reading position in the file
	 * @param len    number of bytes to read
	 *
	 * @return number of bytes read
	 *
	 * @throws TskCoreException exception thrown when file could not be read
	 */
	protected int readInt(byte[] buf, long offset, long len) throws TskCoreException {
		return 0;
	}

	/**
	 * Local file path read support
	 *
	 * @param buf    buffer to read into
	 * @param offset start reading position in the file
	 * @param len    number of bytes to read
	 *
	 * @return number of bytes read
	 *
	 * @throws TskCoreException exception thrown when file could not be read
	 */
	protected final int readLocal(byte[] buf, long offset, long len) throws TskCoreException {
		if (!localPathSet) {
			throw new TskCoreException(
					BUNDLE.getString("AbstractFile.readLocal.exception.msg1.text"));
		}

		if (isDir()) {
			return 0;
		}

		loadLocalFile();
		if (!localFile.exists()) {
			throw new TskCoreException(
					MessageFormat.format(BUNDLE.getString("AbstractFile.readLocal.exception.msg2.text"), localAbsPath));
		}
		if (!localFile.canRead()) {
			throw new TskCoreException(
					MessageFormat.format(BUNDLE.getString("AbstractFile.readLocal.exception.msg3.text"), localAbsPath));
		}

		int bytesRead = 0;

		if (localFileHandle == null) {
			synchronized (this) {
				if (localFileHandle == null) {
					try {
						localFileHandle = new RandomAccessFile(localFile, "r");
					} catch (FileNotFoundException ex) {
						final String msg = MessageFormat.format(BUNDLE.getString(
								"AbstractFile.readLocal.exception.msg4.text"),
								localAbsPath);
						LOGGER.log(Level.SEVERE, msg, ex);
						//file could have been deleted or moved
						throw new TskCoreException(msg, ex);
					}
				}
			}
		}

		try {
			if (!encodingType.equals(TskData.EncodingType.NONE)) {
				// The file is encoded, so we need to alter the offset to read (since there's
				// a header on the encoded file) and then decode each byte
				long encodedOffset = offset + EncodedFileUtil.getHeaderLength();

				//move to the user request offset in the stream
				long curOffset = localFileHandle.getFilePointer();
				if (curOffset != encodedOffset) {
					localFileHandle.seek(encodedOffset);
				}
				bytesRead = localFileHandle.read(buf, 0, (int) len);
				for (int i = 0; i < bytesRead; i++) {
					buf[i] = EncodedFileUtil.decodeByte(buf[i], encodingType);
				}
				return bytesRead;
			} else {
				//move to the user request offset in the stream
				long curOffset = localFileHandle.getFilePointer();
				if (curOffset != offset) {
					localFileHandle.seek(offset);
				}
				//note, we are always writing at 0 offset of user buffer
				return localFileHandle.read(buf, 0, (int) len);
			}
		} catch (IOException ex) {
			final String msg = MessageFormat.format(BUNDLE.getString("AbstractFile.readLocal.exception.msg5.text"), localAbsPath);
			LOGGER.log(Level.SEVERE, msg, ex);
			//local file could have been deleted / moved
			throw new TskCoreException(msg, ex);
		}
	}

	/**
	 * Set local path for the file, as stored in db tsk_files_path, relative to
	 * the case db path or an absolute path. When set, subsequent invocations of
	 * read() will read the file in the local path.
	 *
	 * @param localPath  local path to be set
	 * @param isAbsolute true if the path is absolute, false if relative to the
	 *                   case db
	 */
	void setLocalFilePath(String localPath, boolean isAbsolute) {

		if (localPath == null || localPath.equals("")) {
			this.localPath = "";
			localAbsPath = null;
			localPathSet = false;
		} else {
			this.localPath = localPath;
			if (isAbsolute) {
				this.localAbsPath = localPath;
			} else {
				this.localAbsPath = getSleuthkitCase().getDbDirPath() + java.io.File.separator + this.localPath;
			}
			this.localPathSet = true;
		}
	}

	/**
	 * Get local relative to case db path of the file
	 *
	 * @return local file path if set
	 */
	public String getLocalPath() {
		return localPath;
	}

	/**
	 * Get local absolute path of the file, if localPath has been set
	 *
	 * @return local absolute file path if local path has been set, or null
	 */
	public String getLocalAbsPath() {
		return localAbsPath;
	}

	/**
	 * Set the type of encoding used on the file (for local/derived files only)
	 *
	 * @param encodingType
	 */
	final void setEncodingType(TskData.EncodingType encodingType) {
		this.encodingType = encodingType;
	}

	/**
	 * Check if the file exists. If non-local always true, if local, checks if
	 * actual local path exists
	 *
	 * @return true if the file exists, false otherwise
	 */
	public boolean exists() {
		if (!localPathSet) {
			return true;
		} else {
			try {
				loadLocalFile();
				return localFile.exists();
			} catch (TskCoreException ex) {
				LOGGER.log(Level.SEVERE, ex.getMessage());
				return false;
			}
		}
	}

	/**
	 * Check if the file exists and is readable. If non-local (e.g. within an
	 * image), always true, if local, checks if actual local path exists and is
	 * readable
	 *
	 * @return true if the file is readable
	 */
	public boolean canRead() {
		if (!localPathSet) {
			return true;
		} else {
			try {
				loadLocalFile();
				return localFile.canRead();
			} catch (TskCoreException ex) {
				LOGGER.log(Level.SEVERE, ex.getMessage());
				return false;
			}
		}
	}

	/**
	 * Lazy load local file handle
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException If the local path is not
	 *                                                  set.
	 */
	private void loadLocalFile() throws TskCoreException {
		if (!localPathSet) {
			throw new TskCoreException(
					BUNDLE.getString("AbstractFile.readLocal.exception.msg1.text"));
		}

		// already been set
		if (localFile != null) {
			return;
		}

		synchronized (this) {
			if (localFile == null) {
				localFile = new java.io.File(localAbsPath);
			}
		}
	}

	@Override
	public void close() {

		//close local file handle if set
		if (localFileHandle != null) {
			synchronized (this) {
				if (localFileHandle != null) {
					try {
						localFileHandle.close();
					} catch (IOException ex) {
						LOGGER.log(Level.SEVERE, "Could not close file handle for file: " + getParentPath() + getName(), ex); //NON-NLS
					}
					localFileHandle = null;
				}
			}
		}

	}

	@Override
	protected void finalize() throws Throwable {
		try {
			close();
		} finally {
			super.finalize();
		}
	}

	@Override
	public String toString(boolean preserveState) {
		return super.toString(preserveState) + "AbstractFile [\t" //NON-NLS
				+ "\t" + "fileType " + fileType //NON-NLS
				+ "\tctime " + ctime //NON-NLS
				+ "\tcrtime " + crtime //NON-NLS
				+ "\t" + "mtime " + mtime + "\t" + "atime " + atime //NON-NLS
				+ "\t" + "attrId " + attrId //NON-NLS
				+ "\t" + "attrType " + attrType //NON-NLS
				+ "\t" + "dirFlag " + dirFlag + "\t" + "dirType " + dirType //NON-NLS
				+ "\t" + "uid " + uid //NON-NLS
				+ "\t" + "gid " + gid //NON-NLS
				+ "\t" + "metaAddr " + metaAddr + "\t" + "metaSeq " + metaSeq + "\t" + "metaFlags " + metaFlags //NON-NLS
				+ "\t" + "metaType " + metaType + "\t" + "modes " + modes //NON-NLS
				+ "\t" + "parentPath " + parentPath + "\t" + "size " + size //NON-NLS
				+ "\t" + "knownState " + knownState + "\t" + "md5Hash " + md5Hash //NON-NLS
				+ "\t" + "localPathSet " + localPathSet + "\t" + "localPath " + localPath //NON-NLS
				+ "\t" + "localAbsPath " + localAbsPath + "\t" + "localFile " + localFile //NON-NLS
				+ "]\t";
	}

	/**
	 * Possible return values for comparing a file to a list of mime types
	 */
	public enum MimeMatchEnum {

		UNDEFINED, /// file does not have a defined mime time in blackboard
		TRUE, /// file has a defined mime type and it is one of the given ones
		FALSE /// file has a defined mime type and it is not one of the given ones.
	}

	/**
	 * Determines if this file's type is one of the ones passed in. Uses the
	 * blackboard attribute for file type.
	 *
	 * @param mimeTypes Set of file types to compare against
	 *
	 * @return
	 */
	public MimeMatchEnum isMimeType(SortedSet<String> mimeTypes) {
		if (this.mimeType == null) {
			return MimeMatchEnum.UNDEFINED;
		}
		if (mimeTypes.contains(this.mimeType)) {
			return MimeMatchEnum.TRUE;
		}
		return MimeMatchEnum.FALSE;
	}

	/**
	 * Saves the editable file properties of this file to the case database,
	 * e.g., the MIME type, MD5 hash, and known state.
	 *
	 * @throws TskCoreException if there is an error saving the editable file
	 *                          properties to the case database.
	 */
	public void save() throws TskCoreException {

		// No fields have been updated
		if (!(md5HashDirty || mimeTypeDirty || knownStateDirty)) {
			return;
		}

		String queryStr = "";
		if (mimeTypeDirty) {
			queryStr = "mime_type = '" + this.getMIMEType() + "'";
		}
		if (md5HashDirty) {
			if (!queryStr.isEmpty()) {
				queryStr += ", ";
			}
			queryStr += "md5 = '" + this.getMd5Hash() + "'";
		}
		if (knownStateDirty) {
			if (!queryStr.isEmpty()) {
				queryStr += ", ";
			}
			queryStr += "known = '" + this.getKnown().getFileKnownValue() + "'";
		}

		queryStr = "UPDATE tsk_files SET " + queryStr + " WHERE obj_id = " + this.getId();

		SleuthkitCase.CaseDbConnection connection = getSleuthkitCase().getConnection();
		Statement statement = null;

		getSleuthkitCase().acquireSingleUserCaseWriteLock();
		try {
			statement = connection.createStatement();
			connection.executeUpdate(statement, queryStr);
			getSleuthkitCase().getTimelineManager().setFileStatus(this);
			md5HashDirty = false;
			mimeTypeDirty = false;
			knownStateDirty = false;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error saving properties for file (obj_id = %s)", this.getId()), ex);
		} finally {
			closeStatement(statement);
			connection.close();
			getSleuthkitCase().releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Initializes common fields used by AbstactFile implementations (objects in
	 * tsk_files table)
	 *
	 * @param db         case / db handle where this file belongs to
	 * @param objId      object id in tsk_objects table
	 * @param attrType
	 * @param attrId
	 * @param name       name field of the file
	 * @param fileType   type of the file
	 * @param metaAddr
	 * @param metaSeq
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
	 * @param md5Hash    md5sum of the file, or null or "NULL" if not present
	 * @param knownState knownState status of the file, or null if unknown
	 *                   (default)
	 * @param parentPath
	 *
	 * @deprecated Do not make subclasses outside of this package.
	 */
	@Deprecated
	@SuppressWarnings("deprecation")
	protected AbstractFile(SleuthkitCase db, long objId, TskData.TSK_FS_ATTR_TYPE_ENUM attrType, short attrId,
			String name, TskData.TSK_DB_FILES_TYPE_ENUM fileType, long metaAddr, int metaSeq,
			TSK_FS_NAME_TYPE_ENUM dirType, TSK_FS_META_TYPE_ENUM metaType, TSK_FS_NAME_FLAG_ENUM dirFlag, short metaFlags,
			long size, long ctime, long crtime, long atime, long mtime, short modes, int uid, int gid, String md5Hash, FileKnown knownState,
			String parentPath) {
		this(db, objId, db.getDataSourceObjectId(objId), attrType, (int) attrId, name, fileType, metaAddr, metaSeq, dirType, metaType, dirFlag, metaFlags, size, ctime, crtime, atime, mtime, modes, uid, gid, md5Hash, knownState, parentPath, null, null);
	}

	/**
	 * Initializes common fields used by AbstactFile implementations (objects in
	 * tsk_files table). This deprecated version has attrId filed defined as a
	 * short which has since been changed to an int.
	 *
	 * @param db                 case / db handle where this file belongs to
	 * @param objId              object id in tsk_objects table
	 * @param dataSourceObjectId The object id of the root data source of this
	 *                           file.
	 * @param attrType
	 * @param attrId
	 * @param name               name field of the file
	 * @param fileType           type of the file
	 * @param metaAddr
	 * @param metaSeq
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
	 * @param md5Hash            md5sum of the file, or null or "NULL" if not
	 *                           present
	 * @param knownState         knownState status of the file, or null if
	 *                           unknown (default)
	 * @param parentPath
	 * @param mimeType           The MIME type of the file, can be null
	 *
	 * @deprecated Do not make subclasses outside of this package.
	 */
	@Deprecated
	@SuppressWarnings("deprecation")
	AbstractFile(SleuthkitCase db, long objId, long dataSourceObjectId, TskData.TSK_FS_ATTR_TYPE_ENUM attrType, short attrId,
			String name, TskData.TSK_DB_FILES_TYPE_ENUM fileType, long metaAddr, int metaSeq, TSK_FS_NAME_TYPE_ENUM dirType, TSK_FS_META_TYPE_ENUM metaType,
			TSK_FS_NAME_FLAG_ENUM dirFlag, short metaFlags, long size, long ctime, long crtime, long atime, long mtime, short modes,
			int uid, int gid, String md5Hash, FileKnown knownState, String parentPath, String mimeType) {
		this(db, objId, dataSourceObjectId, attrType, (int) attrId, name, fileType, metaAddr, metaSeq, dirType, metaType, dirFlag, metaFlags, size, ctime, crtime, atime, mtime, modes, uid, gid, md5Hash, knownState, parentPath, null, null);
	}

	/**
	 * Get the attribute id
	 *
	 * @return attribute id
	 *
	 * @deprecated Use getAttributeId() method instead as it returns integer
	 * instead of short.
	 */
	@Deprecated
	@SuppressWarnings("deprecation")
	public short getAttrId() {
		/*
		 * NOTE: previously attrId used to be stored in AbstractFile as (signed)
		 * short even though it is stored as uint16 in TSK. In extremely rare
		 * occurrences attrId can be larger than what a signed short can hold
		 * (2^15). Changes were made to AbstractFile to store attrId as integer.
		 * Therefore this method has been deprecated. For backwards
		 * compatibility, attribute ids that are larger than 32K are converted
		 * to a negative number.
		 */
		return (short) attrId;	// casting to signed short converts values over 32K to negative values
	}

	/**
	 * Set local path for the file, as stored in db tsk_files_path, relative to
	 * the case db path or an absolute path. When set, subsequent invocations of
	 * read() will read the file in the local path.
	 *
	 * @param localPath  local path to be set
	 * @param isAbsolute true if the path is absolute, false if relative to the
	 *                   case db
	 *
	 * @deprecated Do not make subclasses outside of this package.
	 */
	@Deprecated
	protected void setLocalPath(String localPath, boolean isAbsolute) {
		setLocalFilePath(localPath, isAbsolute);
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
	 *
	 * @return formatted date time string as "yyyy-MM-dd HH:mm:ss"
	 *
	 * @deprecated
	 */
	@Deprecated
	public static String epochToTime(long epoch) {
		return TimeUtilities.epochToTime(epoch);
	}

	/**
	 * Return the epoch into string in ISO 8601 dateTime format, in the given
	 * timezone
	 *
	 * @param epoch time in seconds
	 * @param tzone time zone
	 *
	 * @return formatted date time string as "yyyy-MM-dd HH:mm:ss"
	 *
	 * @deprecated
	 */
	@Deprecated
	public static String epochToTime(long epoch, TimeZone tzone) {
		return TimeUtilities.epochToTime(epoch, tzone);
	}

	/**
	 * Convert from ISO 8601 formatted date time string to epoch time in seconds
	 *
	 * @param time formatted date time string as "yyyy-MM-dd HH:mm:ss"
	 *
	 * @return epoch time in seconds
	 */
	@Deprecated
	public static long timeToEpoch(String time) {
		return TimeUtilities.timeToEpoch(time);
	}
}
