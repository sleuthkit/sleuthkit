/*
 * SleuthKit Java Bindings
 *
 * Copyright 2011-2022 Basis Technology Corp.
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
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.SortedSet;
import java.util.TimeZone;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbTransaction;
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
	protected TSK_FS_NAME_FLAG_ENUM dirFlag;
	protected Set<TSK_FS_META_FLAG_ENUM> metaFlags;
	protected final Long fileSystemObjectId;  // File system object ID; may be null
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
	/*
	 * SHA-256 hash
	 */
	protected String sha256Hash;
	private boolean sha256HashDirty = false;
	
	/*
	 * SHA-1 hash
	 */
	protected String sha1Hash;
	private boolean sha1HashDirty = false;
	
	private String mimeType;
	private boolean mimeTypeDirty = false;
	private static final Logger LOGGER = Logger.getLogger(AbstractFile.class.getName());
	private static final ResourceBundle BUNDLE = ResourceBundle.getBundle("org.sleuthkit.datamodel.Bundle");
	private long dataSourceObjectId;
	private final String extension;
	private final List<Attribute> fileAttributesCache = new ArrayList<Attribute>();
	private boolean loadedAttributesCacheFromDb = false;

	private final String ownerUid;	// string owner uid, for example a Windows SID.
	// different from the numeric uid which is more commonly found 
	// on Unix based file systems.
	private final Long osAccountObjId; // obj id of the owner's OS account, may be null
	
	private volatile String uniquePath;
	private volatile FileSystem parentFileSystem;

	/**
	 * Initializes common fields used by AbstactFile implementations (objects in
	 * tsk_files table)
	 *
	 * @param db                 case / db handle where this file belongs to
	 * @param objId              object id in tsk_objects table
	 * @param dataSourceObjectId The object id of the root data source of this
	 *                           file.
	 * @param fileSystemObjectId The object id of the file system. Can be null (or 0 representing null)
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
	 * @param md5Hash            md5sum of the file, or null if not present
	 * @param sha256Hash         sha256 hash of the file, or null if not present
	 * @param sha1Hash           SHA-1 hash of the file, or null if not present
	 * @param knownState         knownState status of the file, or null if
	 *                           unknown (default)
	 * @param parentPath
	 * @param mimeType           The MIME type of the file, can be null.
	 * @param extension          The extension part of the file name (not
	 *                           including the '.'), can be null.
	 * @param ownerUid           Owner uid/SID, can be null if not available.
	 * @param osAccountObjectId	 Object Id of the owner OsAccount, may be null.
	 *
	 */
	AbstractFile(SleuthkitCase db,
			long objId,
			long dataSourceObjectId,
			Long fileSystemObjectId,
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
			String md5Hash, String sha256Hash, String sha1Hash, 
			FileKnown knownState,
			String parentPath,
			String mimeType,
			String extension,
			String ownerUid,
			Long osAccountObjectId,
			List<Attribute> fileAttributes) {
		super(db, objId, name);
		this.dataSourceObjectId = dataSourceObjectId;
		if (fileSystemObjectId != null) {
			// When reading from the result set, nulls are converted to zeros.
			// Switch it to null.
			if (fileSystemObjectId > 0) {
				this.fileSystemObjectId = fileSystemObjectId;
			} else {
				this.fileSystemObjectId = null;
			}
		} else {
			this.fileSystemObjectId = null;
		}
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
		this.sha256Hash = sha256Hash;
		this.sha1Hash = sha1Hash;
		if (knownState == null) {
			this.knownState = FileKnown.UNKNOWN;
		} else {
			this.knownState = knownState;
		}
		this.parentPath = parentPath;
		this.mimeType = mimeType;
		this.extension = extension == null ? "" : extension;
		this.encodingType = TskData.EncodingType.NONE;
		this.ownerUid = ownerUid;
		this.osAccountObjId = osAccountObjectId;
		if (Objects.nonNull(fileAttributes) && !fileAttributes.isEmpty()) {
			this.fileAttributesCache.addAll(fileAttributes);
			loadedAttributesCacheFromDb = true;
		}
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
	 * Sets the SHA-256 hash for this file.
	 *
	 * IMPORTANT: The SHA-256 hash is set for this AbstractFile object, but it
	 * is not saved to the case database until AbstractFile.save is called.
	 *
	 * @param sha256Hash The SHA-256 hash of the file.
	 */
	public void setSha256Hash(String sha256Hash) {
		this.sha256Hash = sha256Hash;
		this.sha256HashDirty = true;
	}

	/**
	 * Get the SHA-256 hash value as calculated, if present
	 *
	 * @return SHA-256 hash string, if it is present or null if it is not
	 */
	public String getSha256Hash() {
		return this.sha256Hash;
	}

	/**
	 * Sets the SHA-1 hash for this file.
	 *
	 * IMPORTANT: The SHA-1 hash is set for this AbstractFile object, but it
	 * is not saved to the case database until AbstractFile.save is called.
	 *
	 * @param sha1Hash The SHA-1 hash of the file.
	 */
	public void setSha1Hash(String sha1Hash) {
		this.sha1Hash = sha1Hash;
		this.sha1HashDirty = true;
	}

	/**
	 * Get the SHA-1 hash value as calculated, if present
	 *
	 * @return SHA-1 hash string, if it is present or null if it is not
	 */
	public String getSha1Hash() {
		return this.sha1Hash;
	}
	
	/**
	 * Gets the attributes of this File
	 *
	 * @return
	 *
	 * @throws TskCoreException
	 */
	public List<Attribute> getAttributes() throws TskCoreException {
		synchronized (this) {
			if (!loadedAttributesCacheFromDb) {
				ArrayList<Attribute> attributes = getSleuthkitCase().getBlackboard().getFileAttributes(this);
				fileAttributesCache.clear();
				fileAttributesCache.addAll(attributes);
				loadedAttributesCacheFromDb = true;
			}
			return Collections.unmodifiableList(fileAttributesCache);
		}
	}

	/**
	 * Adds a collection of attributes to this file in a single operation within
	 * a transaction supplied by the caller.
	 *
	 * @param attributes        The collection of attributes.
	 * @param caseDbTransaction The transaction in the scope of which the
	 *                          operation is to be performed, managed by the
	 *                          caller. if Null is passed in a local transaction
	 *                          will be created and used.
	 *
	 * @throws TskCoreException If an error occurs and the attributes were not
	 *                          added to the artifact.
	 */
	public void addAttributes(Collection<Attribute> attributes, final SleuthkitCase.CaseDbTransaction caseDbTransaction) throws TskCoreException {

		if (Objects.isNull(attributes) || attributes.isEmpty()) {
			throw new TskCoreException("Illegal Argument passed to addAttributes: null or empty attributes passed to addAttributes");
		}
		boolean isLocalTransaction = Objects.isNull(caseDbTransaction);
		SleuthkitCase.CaseDbTransaction localTransaction = isLocalTransaction ? getSleuthkitCase().beginTransaction() : null;
		SleuthkitCase.CaseDbConnection connection = isLocalTransaction ? localTransaction.getConnection() : caseDbTransaction.getConnection();

		try {
			for (final Attribute attribute : attributes) {
				attribute.setAttributeParentId(getId());
				attribute.setCaseDatabase(getSleuthkitCase());
				getSleuthkitCase().addFileAttribute(attribute, connection);
			}

			if (isLocalTransaction) {
				localTransaction.commit();
				localTransaction = null;
			}
			// append the new attributes if cache is already loaded.
			synchronized (this) {
				if (loadedAttributesCacheFromDb) {
					fileAttributesCache.addAll(attributes);
				}
			}
		} catch (SQLException ex) {
			if (isLocalTransaction && null != localTransaction) {
				try {
					localTransaction.rollback();
				} catch (TskCoreException ex2) {
					LOGGER.log(Level.SEVERE, "Failed to rollback transaction after exception", ex2);
				}
			}
			throw new TskCoreException("Error adding file attributes", ex);
		}
	}

	/**
	 * Sets the known state for this file. Passed in value will be ignored if it
	 * is "less" than the current state. A NOTABLE file cannot be downgraded to
	 * KNOWN.
	 *
	 * IMPORTANT: The known state is set for this AbstractFile object, but it is
	 * not saved to the case database until AbstractFile.save is called.
	 *
	 * @param knownState The known state of the file.
	 */
	public void setKnown(TskData.FileKnown knownState) {
		// don't allow them to downgrade the known state
		if (this.knownState.compareTo(knownState) > 0) {
			// ideally we'd return some kind of error, but 
			// the API doesn't allow it
			return;
		}
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
	 *
	 * To obtain the data source as a DataSource object, use:
	 * getSleuthkitCase().getDataSource(getDataSourceObjectId());
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
	public long getDataSourceObjectId() {
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
	 * Converts a file offset and length into a series of TskFileRange objects
	 * whose offsets are relative to the image. This method will only work on
	 * files with layout ranges.
	 *
	 * @param fileOffset The byte offset in this file to map.
	 * @param length     The length of bytes starting at fileOffset requested.
	 *
	 * @return The TskFileRange objects whose offsets are relative to the image.
	 *         The sum total of lengths in these ranges will equal the length
	 *         requested or will run until the end of this file.
	 *
	 * @throws TskCoreException
	 */
	public List<TskFileRange> convertToImgRanges(long fileOffset, long length) throws TskCoreException {
		if (fileOffset < 0 || length < 0) {
			throw new TskCoreException("fileOffset and length must be non-negative");
		}

		List<TskFileRange> thisRanges = getRanges();
		List<TskFileRange> toRet = new ArrayList<>();

		long requestedEnd = fileOffset + length;

		// the number of bytes counted from the beginning of this file
		long bytesCounted = 0;

		for (int curRangeIdx = 0; curRangeIdx < thisRanges.size(); curRangeIdx++) {
			// if we exceeded length of requested, then we are done
			if (bytesCounted >= requestedEnd) {
				break;
			}

			TskFileRange curRange = thisRanges.get(curRangeIdx);
			long curRangeLen = curRange.getByteLen();
			// the bytes counted when we reach the end of this range
			long curRangeEnd = bytesCounted + curRangeLen;

			// if fileOffset is less than current range's end and we have not 
			// gone past the end we requested, then grab at least part of this 
			// range.
			if (fileOffset < curRangeEnd) {
				// offset into range to be returned to user (0 if fileOffset <= bytesCounted)
				long rangeOffset = Math.max(0, fileOffset - bytesCounted);

				// calculate the new TskFileRange start by adding on the offset into the current range
				long newRangeStart = curRange.getByteStart() + rangeOffset;

				// how much this current range exceeds the length requested (or 0 if within the length requested)
				long rangeOvershoot = Math.max(0, curRangeEnd - requestedEnd);

				long newRangeLen = curRangeLen - rangeOffset - rangeOvershoot;
				toRet.add(new TskFileRange(newRangeStart, newRangeLen, toRet.size()));
			}

			bytesCounted = curRangeEnd;
		}

		return toRet;
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
	 * Set the directory name flag.
	 *
	 * @param flag Flag to set to.
	 */
	void setDirFlag(TSK_FS_NAME_FLAG_ENUM flag) {
		dirFlag = flag;
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

	/**
	 * Set the specified meta flag.
	 *
	 * @param metaFlag Meta flag to set
	 */
	void setMetaFlag(TSK_FS_META_FLAG_ENUM metaFlag) {
		metaFlags.add(metaFlag);
	}

	/**
	 * Remove the specified meta flag.
	 *
	 * @param metaFlag Meta flag to remove.
	 */
	void removeMetaFlag(TSK_FS_META_FLAG_ENUM metaFlag) {
		metaFlags.remove(metaFlag);
	}

	/**
	 * Get meta flags as an integer.
	 *
	 * @return Integer representation of the meta flags.
	 */
	short getMetaFlagsAsInt() {
		return TSK_FS_META_FLAG_ENUM.toInt(metaFlags);
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

		// If the file is empty, just return that zero bytes were read.
		if (getSize() == 0) {
			return 0;
		}

		loadLocalFile();

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
	 * @param localPath local path to be set
	 */
	void setLocalFilePath(String localPath) {

		if (localPath == null || localPath.equals("")) {
			this.localPath = "";
			localAbsPath = null;
			localPathSet = false;
		} else {
			// It should always be the case that absolute paths start with slashes or a windows drive letter
			// and relative paths do not, but some older versions of modules created derived file paths
			// starting with slashes. So we first check if this file is a DerivedFile before looking at the path.
			this.localPath = localPath;
			if (this instanceof DerivedFile) {
				// DerivedFiles always have relative paths
				this.localAbsPath = getSleuthkitCase().getDbDirPath() + java.io.File.separator + localPath;
			} else {
				// If a path starts with a slash or with a Windows drive letter, then it is
				// absolute. Otherwise it is relative.
				if (localPath.startsWith("/") || localPath.startsWith("\\")
						|| localPath.matches("[A-Za-z]:[/\\\\].*")) {
					this.localAbsPath = localPath;
				} else {
					this.localAbsPath = getSleuthkitCase().getDbDirPath() + java.io.File.separator + localPath;
				}
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

	@SuppressWarnings("deprecation")
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
				+ "\t" + "knownState " + knownState + "\t" + "md5Hash " + md5Hash + "\t" + "sha256Hash " + sha256Hash + "\t" + "sha1Hash " + sha1Hash//NON-NLS
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
	 * Saves the editable properties of this file to the case database, e.g.,
	 * the MIME type, MD5 hash, and known state.
	 *
	 * @throws TskCoreException if there is an error saving the editable file
	 *                          properties to the case database.
	 */
	public void save() throws TskCoreException {
		CaseDbTransaction transaction = null;
		try {
			transaction = getSleuthkitCase().beginTransaction();
			save(transaction);
			transaction.commit();
		} catch (TskCoreException ex) {
			if (transaction != null) {
				transaction.rollback();
			}
			throw ex;
		}
	}

	/**
	 * Saves the editable properties of this file to the case database, e.g.,
	 * the MIME type, MD5 hash, and known state, in the context of a given case
	 * database transaction.
	 *
	 * @param transaction The transaction.
	 *
	 * @throws TskCoreException if there is an error saving the editable file
	 *                          properties to the case database.
	 */
	public void save(CaseDbTransaction transaction) throws TskCoreException {
		if (!(md5HashDirty || sha256HashDirty || sha1HashDirty || mimeTypeDirty || knownStateDirty)) {
			return;
		}

		String updateSql = "";
		if (mimeTypeDirty) {
			updateSql = "mime_type = '" + this.getMIMEType() + "'";
		}
		if (md5HashDirty) {
			if (!updateSql.isEmpty()) {
				updateSql += ", ";
			}
			updateSql += "md5 = '" + this.getMd5Hash() + "'";
		}
		if (sha256HashDirty) {
			if (!updateSql.isEmpty()) {
				updateSql += ", ";
			}
			updateSql += "sha256 = '" + this.getSha256Hash() + "'";
		}
		if (sha1HashDirty) {
			if (!updateSql.isEmpty()) {
				updateSql += ", ";
			}
			updateSql += "sha1 = '" + this.getSha1Hash() + "'";
		}
		if (knownStateDirty) {
			if (!updateSql.isEmpty()) {
				updateSql += ", ";
			}
			updateSql += "known = '" + this.getKnown().getFileKnownValue() + "'";
		}
		updateSql = "UPDATE tsk_files SET " + updateSql + " WHERE obj_id = " + this.getId();

		SleuthkitCase.CaseDbConnection connection = transaction.getConnection();
		try (Statement statement = connection.createStatement()) {
			connection.executeUpdate(statement, updateSql);
			md5HashDirty = false;
			sha256HashDirty = false;
			sha1HashDirty = false;
			mimeTypeDirty = false;
			knownStateDirty = false;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error updating properties of file %s (obj_id = %s)", getName(), getId()), ex);
		}
	}

	/**
	 * Get the owner uid.
	 *
	 * Note this is a string uid, typically a Windows SID. This is different
	 * from the numeric uid commonly found on Unix based file systems.
	 *
	 * @return Optional with owner uid.
	 */
	public Optional<String> getOwnerUid() {
		return Optional.ofNullable(ownerUid);
	}

	/**
	 * Get the Object Id of the owner account.
	 *
	 * @return Optional with Object Id of the OsAccount, or Optional.empty.
	 */
	public Optional<Long> getOsAccountObjectId() {
		return Optional.ofNullable(osAccountObjId);
	}
	
	/**
	 * Sets the parent file system of this file or directory.
	 *
	 * @param parent The parent file system object.
	 */
	void setFileSystem(FileSystem parent) {
		parentFileSystem = parent;
	}
	
	/**
	 * Get the object id of the parent file system of this file or directory if it exists.
	 *
	 * @return The parent file system id.
	 */
	public Optional<Long> getFileSystemObjectId() {
		return Optional.ofNullable(fileSystemObjectId);
	}
	
	/**
	 * Check if this AbstractFile belongs to a file system.
	 * 
	 * @return True if the file belongs to a file system, false otherwise.
	 */
	public boolean hasFileSystem() {
		return fileSystemObjectId != null;
	}
	
	/**
	 * Gets the parent file system of this file or directory.
	 * If the AbstractFile object is not FsContent, hasFileSystem() should
	 * be called before this method to ensure the file belongs to a file
	 * system.
	 *
	 * @return The file system object of the parent.
	 *
	 * @throws org.sleuthkit.datamodel.TskCoreException If the file does not belong to a file system or
	 *     another error occurs.
	 */
	public FileSystem getFileSystem() throws TskCoreException {
		if (fileSystemObjectId == null) {
			throw new TskCoreException("File with ID: " + this.getId() + " does not belong to a file system");
		}
		if (parentFileSystem == null) {
			synchronized (this) {
				if (parentFileSystem == null) {
					parentFileSystem = getSleuthkitCase().getFileSystemById(fileSystemObjectId, AbstractContent.UNKNOWN_ID);
				}
			}
		}
		return parentFileSystem;
	}
	
	/**
	 * Get the full path to this file or directory, starting with a "/" and the
	 * data source name and then all the other segments in the path.
	 *
	 * @return A unique path for this object.
	 *
	 * @throws TskCoreException if there is an error querying the case database.
	 */
	@Override
	public String getUniquePath() throws TskCoreException {

		if (uniquePath == null) {
			if (getFileSystemObjectId().isPresent()) {
				// For file system files, construct the path using the path to
				// the file system, the parent path, and the file name. FileSystem
				// objects are cached so this is unlikely to perform any
				// database operations.
				StringBuilder sb = new StringBuilder();
				sb.append(getFileSystem().getUniquePath());
				if (! parentPath.isEmpty()) {
					sb.append(parentPath);
				} else {
					// The parent path may not be set in older cases.
					sb.append("/");
				}
				sb.append(getName());
				uniquePath = sb.toString();
			} else {
				if ((this instanceof LayoutFile) && (parentPath.equals("/"))) {
					// This may be the case where the layout file is a direct child of a 
					// volume. We want to make sure to include the volume information if present,
					// so go up the directory structure instead of using the optimized code.
					uniquePath = super.getUniquePath();
				} else if (getName().equals(VirtualDirectory.NAME_CARVED) || getName().equals(VirtualDirectory.NAME_UNALLOC) || 
						parentPath.startsWith("/" + VirtualDirectory.NAME_CARVED) || parentPath.startsWith("/" + VirtualDirectory.NAME_UNALLOC)) {
					// We can make $Unalloc and $CarvedFiles under volumes without being part of a file system.
					// As above, we want to make sure to include the volume information if present,
					// so go up the directory structure instead of using the optimized code.
					uniquePath = super.getUniquePath();
				} else {
					// Optimized code to use for most files. Construct the path
					// using the data source name, the parent path, and the file name.
					// DataSource objects are cached so this is unlikely to perform any
				    // database operations.
					String dataSourceName = "";
					Content dataSource = getDataSource();
					if (dataSource != null) {
					  dataSourceName = dataSource.getUniquePath(); 
					}
					if (! parentPath.isEmpty()) {
						uniquePath = dataSourceName + parentPath + getName();
					} else {
						// The parent path may not be set in older cases.
						uniquePath = dataSourceName + "/" + getName();
					}
				}
			}
		}
		return uniquePath;
	}

	@Deprecated
	@SuppressWarnings("deprecation")
	@Override
	public BlackboardArtifact newArtifact(int artifactTypeID) throws TskCoreException {
		return super.newArtifact(artifactTypeID);
	}

	/**
	 * Create and add a data artifact associated with this abstract file. This
	 * method creates the data artifact with the os account id associated with
	 * this abstract file if one exists.
	 *
	 * @param artifactType   Type of data artifact to create.
	 * @param attributesList Additional attributes to attach to this data
	 *                       artifact.
	 *
	 * @return DataArtifact New data artifact.
	 *
	 * @throws TskCoreException If a critical error occurred within tsk core.
	 */
	@Override
	public DataArtifact newDataArtifact(BlackboardArtifact.Type artifactType, Collection<BlackboardAttribute> attributesList) throws TskCoreException {
		return super.newDataArtifact(artifactType, attributesList, getOsAccountObjectId().orElse(null));
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
		setLocalFilePath(localPath);
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
