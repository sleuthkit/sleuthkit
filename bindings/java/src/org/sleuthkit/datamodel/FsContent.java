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

import java.util.logging.Level;
import java.util.logging.Logger;
import org.sleuthkit.datamodel.TskData.FileKnown;
import org.sleuthkit.datamodel.TskData.TSK_FS_ATTR_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_META_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_FLAG_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_TYPE_ENUM;

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
	protected final long fsObjId;
	private String uniquePath;
	///read-write database tsk_files fields
	private final SleuthkitCase tskCase;
	
	/**
	 * parent file system
	 */
	private volatile FileSystem parentFileSystem;
	///other members
	/**
	 * file Handle
	 */
	protected volatile long fileHandle = 0;

	/**
	 * Create an FsContent object from a database object
	 *
	 * @param db
	 * @param objId
	 * @param fsObjId
	 * @param attrType
	 * @param attrId
	 * @param name
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
	 * @param md5Hash String of MD5 hash of content or null if not known
	 * @param knownState
	 * @param parentPath
	 */
	FsContent(SleuthkitCase db, long objId, long fsObjId, TSK_FS_ATTR_TYPE_ENUM attrType, short attrId,
			String name, long metaAddr,
			TSK_FS_NAME_TYPE_ENUM dirType, TSK_FS_META_TYPE_ENUM metaType, TSK_FS_NAME_FLAG_ENUM dirFlag, short metaFlags,
			long size, long ctime, long crtime, long atime, long mtime, short modes, int uid, int gid, String md5Hash, FileKnown knownState,
			String parentPath) {
		super(db, objId, attrType, attrId, name, TskData.TSK_DB_FILES_TYPE_ENUM.FS, metaAddr, dirType, metaType, dirFlag, metaFlags, size, ctime, crtime, atime, mtime, modes, uid, gid, md5Hash, knownState, parentPath);
		this.tskCase = db;
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
	public FileSystem getFileSystem() throws TskCoreException {
		if (parentFileSystem == null) {
			synchronized(this) {
				if (parentFileSystem == null) {
					parentFileSystem = getSleuthkitCase().getFileSystemById(fsObjId, AbstractContent.UNKNOWN_ID);
				}
			}
		}
		return parentFileSystem;
	}

	@Override
	protected int readInt(byte[] buf, long offset, long len) throws TskCoreException {
		try {
			if (offset == 0 && size == 0) {
				//special case for 0-size file
				return 0;
			}
			if (fileHandle == 0) {
				synchronized (this) {
					if (fileHandle == 0) {
						fileHandle = SleuthkitJNI.openFile(getFileSystem().getFileSystemHandle(), metaAddr, attrType, attrId);
					}
				}
			}
			return SleuthkitJNI.readFile(fileHandle, buf, offset, len);
		}
		catch (TskCoreException ex) {
			if (!getImage().imageFileExists()) {
				tskCase.submitError("Image File Read Error", "Image file is does not exist or is inaccessible.");
			}
			throw ex;
		}
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

	@Override
	public void close() {
		if (fileHandle != 0) {
			synchronized (this) {
				//need to recheck the handle after unlock
				if (fileHandle != 0) {
					SleuthkitJNI.closeFile(fileHandle);
					fileHandle = 0;
				}
			}
		}
	}

	@Override
	public void finalize() throws Throwable {
		try {
			close();
		} finally {
			super.finalize();
		}
	}

	@Override
	public String toString(boolean preserveState) {
		return super.toString(preserveState)
				+ "FsContent [\t"
				+ "fsObjId " + fsObjId
				+ "\t" + "uniquePath " + uniquePath
				+ "\t" + "fileHandle " + fileHandle
				+ "]\t";
	}
}
