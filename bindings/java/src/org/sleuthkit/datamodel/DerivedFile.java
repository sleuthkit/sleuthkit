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

import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.sleuthkit.datamodel.TskData.FileKnown;
import org.sleuthkit.datamodel.TskData.TSK_DB_FILES_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_META_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_FLAG_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_TYPE_ENUM;

/**
 * Represents a file or directory that has been derived from another file and
 * contents of which are stored locally on user's machine.
 *
 * The file extends AbstractFile by adding derived method used and information
 * needed to rederive it.
 *
 * Use case example is an extracted file from an archive.
 */
public class DerivedFile extends AbstractFile {

	private volatile DerivedMethod derivedMethod;
	private static final Logger logger = Logger.getLogger(DerivedFile.class.getName());
	private boolean hasDerivedMethod = true; ///< whether it has the derived method to lazy load or not

	/**
	 * Create a db representation of a derived file
	 *
	 * @param db
	 * @param objId object if of this file already in database
	 * @param name name of this derived file
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
	 * @param parentPath path of the parent of this derived file (e.g. fs zip
	 * file, or another derived file path)
	 * @param localPath local path of this derived file, relative to the db path
	 * @param parentId parent id of this derived file to set if available
	 */
	protected DerivedFile(SleuthkitCase db, long objId, String name, TSK_FS_NAME_TYPE_ENUM dirType, TSK_FS_META_TYPE_ENUM metaType, TSK_FS_NAME_FLAG_ENUM dirFlag, short metaFlags, long size,
			long ctime, long crtime, long atime, long mtime,
			String md5Hash, FileKnown knownState, String parentPath, String localPath, long parentId) {

			super(db, objId, TskData.TSK_FS_ATTR_TYPE_ENUM.TSK_FS_ATTR_TYPE_DEFAULT, (short) 0,
				name, TSK_DB_FILES_TYPE_ENUM.LOCAL, 0L, dirType, metaType, dirFlag,
				metaFlags, size, ctime, crtime, atime, mtime, (short) 0, 0, 0, md5Hash, knownState, parentPath);
		
			//use the local path read infrastructure
			setLocalPath(localPath, false); //local paths for derived files are relative to case db
	}

	@Override
	public boolean isRoot() {
		//not a root of a fs, since it always has a parent
		return false;
	}

	@Override
	public Image getImage() throws TskCoreException {
		//TODO need schema support to implement this more efficiently
		Image image = null;
		Content ancestor = getParent();
		image = ancestor.getImage();
		while (image == null) {
			ancestor = ancestor.getParent();
			if (ancestor == null) {
				//should never happen
				break;
			}
			image = ancestor.getImage();
		}
		return image;
	}

	@Override
	public List<Content> getChildren() throws TskCoreException {
		//derived file/dir children, can only be other derived files
		return getSleuthkitCase().getAbstractFileChildren(this, TSK_DB_FILES_TYPE_ENUM.DERIVED);

	}

	@Override
	public List<Long> getChildrenIds() throws TskCoreException {
		//derived file/dir children, can only be other derived files
		return getSleuthkitCase().getAbstractFileChildrenIds(this, TSK_DB_FILES_TYPE_ENUM.DERIVED);
	}

	@Override
	public <T> T accept(SleuthkitItemVisitor<T> v) {
		return v.visit(this);
	}

	@Override
	public <T> T accept(ContentVisitor<T> v) {
		return v.visit(this);
	}

	/**
	 * Get derived method for this derived file if it exists, or null
	 *
	 * @return derived method if exists, or null
	 * @throws TskCoreException exception thrown when critical error occurred
	 * and derived method could not be queried
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
			close();
		} finally {
			super.finalize(); //To change body of generated methods, choose Tools | Templates.
		}
	}

	@Override
	public String toString(boolean preserveState) {
		return super.toString(preserveState) + "DerivedFile{" 
				+  "derivedMethod=" + derivedMethod 
				+ ", hasDerivedMethod=" + hasDerivedMethod 
				+ '}';
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
