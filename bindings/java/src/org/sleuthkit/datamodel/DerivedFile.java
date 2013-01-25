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

	private String localPath;
	private boolean isFile;
	private long size;
	private volatile DerivedMethod derivedMethod;
	private java.io.File localFile;
	private volatile RandomAccessFile fileHandle;
	private static final Logger logger = Logger.getLogger(DerivedFile.class.getName());

	public DerivedFile(SleuthkitCase db, long obj_id, String name, TSK_DB_FILES_TYPE_ENUM type, String localPath) {
		super(db, obj_id, name, type);
		this.localPath = localPath;

		localFile = new java.io.File(localPath);
		isFile = localFile.isFile();
		size = localFile.length();
	}

	@Override
	public long getSize() {
		return size;
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
		return localFile.exists();
	}

	public boolean canRead() {
		return localFile.canRead();
	}

	@Override
	public int read(byte[] buf, long offset, long len) throws TskCoreException {
		int bytesRead = 0;

		synchronized (this) {
			if (fileHandle == null) {
				try {
					fileHandle = new RandomAccessFile(localFile, "r");
				} catch (FileNotFoundException ex) {
					final String msg = "Cannot read derived file: " + this.toString();
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

	public synchronized DerivedMethod getDerivedMethod() {
		if (derivedMethod == null) {
			//TODO derivedMethod = SleuthkitCase....
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

	/**
	 * Method used to derive the file
	 */
	public static class DerivedMethod {

		private int derived_id; //Unique id for this derivation method.
		private String toolName; //Name of derivation method/tool
		private String toolVersion; //Version of tool used in derivation method
		private String other; //Other details 

		public DerivedMethod(int derived_id, String toolName, String toolVersion, String other) {
			this.derived_id = derived_id;
			this.toolName = toolName;
			this.toolVersion = toolVersion;
			this.other = other;
		}

		public int getDerived_id() {
			return derived_id;
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

		@Override
		public String toString() {
			return "DerivedMethod{" + "derived_id=" + derived_id + ", toolName=" + toolName + ", toolVersion=" + toolVersion + ", other=" + other + '}';
		}
	}
}
