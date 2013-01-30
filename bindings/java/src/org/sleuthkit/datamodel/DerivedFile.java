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
import org.sleuthkit.datamodel.TskData.TSK_DB_FILES_TYPE_ENUM;

/**
 * Represents a file or directory that has been derived from another file.
 *
 * The file extends AbstractFile by adding derived method used and information
 * needed to rederive it.
 *
 * Use case example is an extracted file from an archive.
 */
public class DerivedFile extends AbstractFile {

	private String localPath; ///< local path as stored in db tsk_files_path, is relative to the db
	private String localAbsPath; ///< absolute path representation of the local path
	private boolean isFile;
	private volatile DerivedMethod derivedMethod;
	private java.io.File localFile;
	private volatile RandomAccessFile fileHandle;
	private static final Logger logger = Logger.getLogger(DerivedFile.class.getName());
	
	private boolean hasDerivedMethod = true; ///< whether it has the derived method to lazy load or not

	/**
	 * Create a db representation of a derived file
	 * @param db sleuthkit case handle
	 * @param objId object if of this file already in database
	 * @param name name of this derived file
	 * @param dirType
	 * @param metaType 
	 * @param dirFlag 
	 * @param metaType 
	 * @param size size of the file
	 * @param parentPath path of the parent of this derived file (e.g. fs zip file, or another derived file path)
	 * @param localPath local path of this derived file, relative to the db path
	 */
	DerivedFile(SleuthkitCase db, long objId, String name, 
			TskData.TSK_FS_NAME_TYPE_ENUM dirType, TskData.TSK_FS_META_TYPE_ENUM metaType, 
			TskData.TSK_FS_NAME_FLAG_ENUM dirFlag, short meta_flags,
			long size, String parentPath, String localPath) {
		super(db, objId, name, TSK_DB_FILES_TYPE_ENUM.DERIVED, dirType, metaType, dirFlag, meta_flags, size, parentPath);
		this.localPath = localPath;

		if (localPath == null) {
			localPath = "";
		} else {
			localAbsPath = db.getDbDirPath() + java.io.File.separator + localPath;
			localFile = new java.io.File(localAbsPath);
			isFile = localFile.isFile();
		}
	}
	
	/**
	 * Create a db representation of a derived file, passing available parent id
	 * @param db sleuthkit case handle
	 * @param objId object if of this file already in database
	 * @param name name of this derived file
	 * @param dirType
	 * @param metaType 
	 * @param dirFlag 
	 * @param metaType 
	 * @param size the size of the file
	 * @param parentPath path of the parent of this derived file (e.g. fs zip file, or another derived file path)
	 * @param localPath local path of this derived file, relative to the db path
	 * @param parentId parent id of this derived file to set if available
	 */
	DerivedFile(SleuthkitCase db, long objId, String name, TskData.TSK_FS_NAME_TYPE_ENUM dirType, TskData.TSK_FS_META_TYPE_ENUM metaType, 
			TskData.TSK_FS_NAME_FLAG_ENUM dirFlag, short meta_flags,
			
			long size, String parentPath, String localPath, long parentId) {
		this(db, objId, name, dirType, metaType, dirFlag, meta_flags, size, parentPath, localPath);
		
		if (parentId > 0) {
			setParentId(parentId);
		}
	}

	/**
	 * Get local path of the file relative to database dir
	 * @return local relative file path
	 */
	public String getLocalPath() {
		return localPath;
	}

	/**
	 * Get local absolute path of the file
	 * @return local absolute file path
	 */
	public String getLocalAbsPath() {
		return localAbsPath;
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
	public boolean isVirtual() {
		return false;
	}

	@Override
	public boolean isFile() {
		return isFile;
	}

	@Override
	public boolean isDir() {
		return !isFile;
	}

	@Override
	public <T> T accept(ContentVisitor<T> v) {
		return v.visit(this);
	}

	@Override
	public List<Content> getChildren() throws TskCoreException {
		//TODO navigate local file system, OR via tsk database
		//even if local file (not dir), still check for children,
		//as it can have other derived files

		//derived file/dir children, can only be other derived files
		return getSleuthkitCase().getAbstractFileChildren(this, TSK_DB_FILES_TYPE_ENUM.DERIVED);

	}

	@Override
	public List<Long> getChildrenIds() throws TskCoreException {
		return getSleuthkitCase().getAbstractFileChildrenIds(this, TSK_DB_FILES_TYPE_ENUM.DERIVED);
	}

	@Override
	public <T> T accept(SleuthkitItemVisitor<T> v) {
		return v.visit(this);
	}

	public boolean exists() {
		if (localFile == null) {
			return false;
		}
		return localFile.exists();
	}

	public boolean canRead() {
		if (localFile == null) {
			return false;
		}
		return localFile.canRead();
	}

	@Override
	public int read(byte[] buf, long offset, long len) throws TskCoreException {
		if (localFile == null) {
			throw new TskCoreException("Local derived file not initialized: " + this.toString());
		}

		int bytesRead = 0;

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

	/**
	 * Get derived method for this derived file if it exists, or null
	 * @return derived method if exists, or null
	 * @throws TskCoreException exception thrown when critical error occurred and derived method could not be queried
	 */
	public synchronized DerivedMethod getDerivedMethod() throws TskCoreException {
		if (derivedMethod == null && hasDerivedMethod == true) {
			try {
				derivedMethod = getSleuthkitCase().getDerivedMethod(getId());
				if (derivedMethod == null) {
					hasDerivedMethod = false;  //do not attempt to lazy load
				}
			} catch (TskCoreException e) {
				String msg = "Error getting derived method for file id: " + getId();
				logger.log(Level.WARNING, msg, e);
				throw new TskCoreException(msg, e);
			}
		}

		return derivedMethod;
	}

	@Override
	protected void finalize() throws Throwable {
		try {
			if (fileHandle != null) {
				fileHandle.close();
				fileHandle = null;
			}
		} finally {
			super.finalize(); //To change body of generated methods, choose Tools | Templates.
		}
	}

	@Override
	public String toString() {
		return "DerivedFile{" + "localPath=" + localPath + ", localAbsPath=" + localAbsPath + ", isFile=" + isFile + ", derivedMethod=" + derivedMethod + ", localFile=" + localFile + ", fileHandle=" + fileHandle + ", hasDerivedMethod=" + hasDerivedMethod + '}';
	}
	
	
	

	/**
	 * Method used to derive the file super-set of tsk_files_derived and
	 * tsk_files_derived_method tables
	 */
	public static class DerivedMethod {

		private int derivedId; ///< Unique id for this derivation method.
		private String toolName; ///< Name of derivation method/tool
		private String toolVersion; ///< Version of tool used in derivation method
		private String other; ///< Other details 
		private String rederiveDetails; ///< details to rederive specific to this method

		public DerivedMethod(int derivedId, String rederiveDetails) {
			this.derivedId = derivedId;
			this.rederiveDetails = rederiveDetails;
			if (this.rederiveDetails == null) {
				this.rederiveDetails = "";
			}
			this.toolName = "";
			this.toolVersion = "";
			this.other = "";
		}

		void setToolName(String toolName) {
			this.toolName = toolName;
		}

		void setToolVersion(String toolVersion) {
			this.toolVersion = toolVersion;
		}

		void setOther(String other) {
			this.other = other;
		}

		public int getDerivedId() {
			return derivedId;
		}

		public String getToolName() {
			return toolName;
		}

		public String getToolVersion() {
			return toolVersion;
		}

		public String getOther() {
			return other;
		}

		public String getRederiveDetails() {
			return rederiveDetails;
		}

		@Override
		public String toString() {
			return "DerivedMethod{" + "derived_id=" + derivedId + ", toolName=" + toolName + ", toolVersion=" + toolVersion + ", other=" + other + ", rederiveDetails=" + rederiveDetails + '}';
		}
	}
}
