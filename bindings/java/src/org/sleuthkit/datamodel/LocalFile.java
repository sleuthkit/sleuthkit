/*
 * Sleuth Kit Data Model
 * 
 * Copyright 2013 Basis Technology Corp.
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
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.sleuthkit.datamodel.TskData.FileKnown;
import org.sleuthkit.datamodel.TskData.TSK_DB_FILES_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_ATTR_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_META_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_FLAG_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_TYPE_ENUM;

/**
 * Represents a local file (on user's machine) that has been added to the case
 */
public class LocalFile extends AbstractFile {

	private String localPath; ///< local path as stored in db tsk_files_path, is relative to the db
	private String localAbsPath; ///< absolute path representation of the local path
	private volatile RandomAccessFile fileHandle;
	private volatile java.io.File localFile;
	private static final Logger logger = Logger.getLogger(LocalFile.class.getName());

	/**
	 * Create a db representation of a local file, passing a more specific file type
	 *
	 * @param db
	 * @param objId object if of this file already in database
	 * @param name name of this local file
	 * @param type TSK_DB_FILES_TYPE_ENUM type of the file (local of more specific)
	 * @param dirType
	 * @param metaType
	 * @param dirFlag
	 * @param metaFlags
	 * @param size size of the file
	 * @param ctime
	 * @param crtime
	 * @param atime
	 * @param mtime
	 * @param md5Hash
	 * @param knownState
	 * @param parentPath path of the parent of this local file (e.g. fs zip
	 * file, or another local file path)
	 * @param localPath local path of this local file, relative to the db path
	 */
	protected LocalFile(SleuthkitCase db, long objId, String name, TSK_DB_FILES_TYPE_ENUM fileType, 
			TSK_FS_NAME_TYPE_ENUM dirType, TSK_FS_META_TYPE_ENUM metaType, TSK_FS_NAME_FLAG_ENUM dirFlag,
			short metaFlags, long size,
			long ctime, long crtime, long atime, long mtime,
			String md5Hash,
			FileKnown knownState, String parentPath, String localPath) {
		super(db, objId, TSK_FS_ATTR_TYPE_ENUM.TSK_FS_ATTR_TYPE_DEFAULT, (short) 0,
				name, fileType, 0L, dirType, metaType, dirFlag,
				metaFlags, size, ctime, crtime, atime, mtime, (short) 0, 0, 0, md5Hash, knownState, parentPath);

		this.localPath = localPath;

		if (this.localPath == null) {
			this.localPath = "";
		} else {
			localAbsPath = db.getDbDirPath() + java.io.File.separator + this.localPath;
		}
	}

	/**
	 * Create a db representation of a local file, passing a more specific file type
	 *
	 * @param db
	 * @param objId object if of this file already in database
	 * @param name name of this local file
	 * @param fileType TSK_DB_FILES_TYPE_ENUM type of the file (LOCAL or more specific)
	 * @param dirType
	 * @param metaType
	 * @param dirFlag
	 * @param metaFlags
	 * @param size size of the file
	 * @param ctime
	 * @param crtime
	 * @param atime
	 * @param mtime
	 * @param md5Hash
	 * @param knownState
	 * @param parentPath path of the parent of this local file (e.g. virtual dir or another local file path)
	 * @param localPath local path of this derived file, relative to the db path
	 * @param parentId parent id of this derived file to set if available
	 */
	protected LocalFile(SleuthkitCase db, long objId, String name, TSK_DB_FILES_TYPE_ENUM fileType, TSK_FS_NAME_TYPE_ENUM dirType, TSK_FS_META_TYPE_ENUM metaType, TSK_FS_NAME_FLAG_ENUM dirFlag, short metaFlags, long size,
			long ctime, long crtime, long atime, long mtime,
			String md5Hash, FileKnown knownState, String parentPath, String localPath, long parentId) {
		this(db, objId, name, fileType, dirType, metaType, dirFlag, metaFlags, size, ctime, crtime, atime, mtime, md5Hash, knownState, parentPath, localPath);

		if (parentId > 0) {
			setParentId(parentId);
		}

	}
	
	/**
	 * Create a db representation of a local file
	 *
	 * @param db
	 * @param objId object if of this file already in database
	 * @param name name of this local file
	 * @param dirType
	 * @param metaType
	 * @param dirFlag
	 * @param metaFlags
	 * @param size size of the file
	 * @param ctime
	 * @param crtime
	 * @param atime
	 * @param mtime
	 * @param md5Hash
	 * @param knownState
	 * @param parentPath path of the parent of this local file (e.g. virtual dir or another local file path)
	 * @param localPath local path of this derived file, relative to the db path
	 * @param parentId parent id of this derived file to set if available
	 */
	protected LocalFile(SleuthkitCase db, long objId, String name, TSK_FS_NAME_TYPE_ENUM dirType, TSK_FS_META_TYPE_ENUM metaType, TSK_FS_NAME_FLAG_ENUM dirFlag, short metaFlags, long size,
			long ctime, long crtime, long atime, long mtime,
			String md5Hash, FileKnown knownState, String parentPath, String localPath, long parentId) {
		this(db, objId, name, TSK_DB_FILES_TYPE_ENUM.LOCAL, dirType, metaType, dirFlag, metaFlags, size, ctime, crtime, atime, mtime, md5Hash, knownState, parentPath, localPath);


	}

	protected RandomAccessFile getFileHandle() {
		return fileHandle;
	}
	
	

	/**
	 * Get local path of the file relative to database dir
	 *
	 * @return local relative file path
	 */
	public String getLocalPath() {
		return localPath;
	}

	/**
	 * Get local absolute path of the file
	 *
	 * @return local absolute file path
	 */
	public String getLocalAbsPath() {
		return localAbsPath;
	}

	@Override
	public Image getImage() throws TskCoreException {
		return null;
	}

	@Override
	public List<TskFileRange> getRanges() throws TskCoreException {
		return Collections.<TskFileRange>emptyList();
	}

	@Override
	public boolean isRoot() {
		//not a root of a fs, since it always has a parent
		return false;
	}

	@Override
	public <T> T accept(ContentVisitor<T> v) {
		return v.visit(this);
	}

	@Override
	public List<Content> getChildren() throws TskCoreException {
		//local file/dir children, can only be other local or derived files
		final SleuthkitCase tskCase = getSleuthkitCase();
		final List<Content> ret = tskCase.getAbstractFileChildren(this, TSK_DB_FILES_TYPE_ENUM.DERIVED);
		ret.addAll(tskCase.getAbstractFileChildren(this, TSK_DB_FILES_TYPE_ENUM.LOCAL));

		return ret;
	}

	@Override
	public List<Long> getChildrenIds() throws TskCoreException {
		//local file/dir children, can only be other local or derived files
		final SleuthkitCase tskCase = getSleuthkitCase();	
		final List<Long> ret = tskCase.getAbstractFileChildrenIds(this, TSK_DB_FILES_TYPE_ENUM.DERIVED);
		ret.addAll(tskCase.getAbstractFileChildrenIds(this, TSK_DB_FILES_TYPE_ENUM.LOCAL));

		return ret;
	}

	@Override
	public <T> T accept(SleuthkitItemVisitor<T> v) {
		return v.visit(this);
	}

	public boolean exists() {
		getLocalFile();
		return localFile.exists();
	}

	public boolean canRead() {
		getLocalFile();
		return localFile.canRead();
	}

	/**
	 * lazy load local file
	 *
	 * @return
	 */
	private java.io.File getLocalFile() {
		if (localFile == null) {
			synchronized (this) {
				localFile = new java.io.File(localAbsPath);
			}
		}
		return localFile;
	}

	@Override
	public void close() {
		if (fileHandle != null) {
			synchronized (this) {
				if (fileHandle != null) {
					try {
						fileHandle.close();
					} catch (IOException ex) {
						logger.log(Level.SEVERE, "Could not close file handle for file: " + this.toString(), ex);
					}
					fileHandle = null;
				}
			}
		}
	}

	@Override
	public int read(byte[] buf, long offset, long len) throws TskCoreException {
		if (isDir()) {
			return 0;
		}

		getLocalFile();
		if (!localFile.exists()) {
			throw new TskCoreException("Error reading derived file, it does not exist at local path: " + localAbsPath);
		}
		if (!localFile.canRead()) {
			throw new TskCoreException("Error reading derived file, file not readable at local path: " + localAbsPath);
		}

		int bytesRead = 0;

		if (fileHandle == null) {
			synchronized (this) {
				if (fileHandle == null) {
					try {
						fileHandle = new RandomAccessFile(localFile, "r");
					} catch (FileNotFoundException ex) {
						final String msg = "Error reading derived file: " + this.toString();
						logger.log(Level.SEVERE, msg, ex);
						//TODO decide if to swallow exception in this case, file could have been deleted or moved
						throw new TskCoreException(msg, ex);
					}
				}
			}
		}

		try {
			//move to the user request offset in the stream
			long curOffset = fileHandle.getFilePointer();
			if (curOffset != offset) {
				fileHandle.seek(offset);
			}
			//note, we are always writing at 0 offset of user buffer
			bytesRead = fileHandle.read(buf, 0, (int) len);
		} catch (IOException ex) {
			final String msg = "Cannot read derived file: " + this.toString();
			logger.log(Level.SEVERE, msg, ex);
			//TODO decide if to swallow exception in this case, file could have been deleted or moved
			throw new TskCoreException(msg, ex);
		}

		return bytesRead;
	}

	@Override
	protected void finalize() throws Throwable {
		try {
			close();
		} finally {
			super.finalize(); //To change body of generated methods, choose Tools | Templates.
		}
	}

	@Override
	public String toString() {
		return "LocalFile{" + "localPath=" + localPath + ", localAbsPath=" + localAbsPath + ", fileHandle=" + fileHandle + '}';
	}
}
