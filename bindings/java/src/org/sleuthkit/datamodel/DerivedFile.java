/*
 * SleuthKit Java Bindings
 *
 * Copyright 2011-2017 Basis Technology Corp.
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

import java.text.MessageFormat;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.sleuthkit.datamodel.TskData.FileKnown;
import org.sleuthkit.datamodel.TskData.TSK_DB_FILES_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_META_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_FLAG_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_TYPE_ENUM;

/**
 * A representation of a file or directory that has been derived from another
 * file and is stored outside of the data source (e.g., on a user's machine). A
 * typical example of a derived file is a file extracted from an archive file.
 */
public class DerivedFile extends AbstractFile {

	private volatile DerivedMethod derivedMethod;
	private static final Logger logger = Logger.getLogger(DerivedFile.class.getName());
	private static ResourceBundle bundle = ResourceBundle.getBundle("org.sleuthkit.datamodel.Bundle");
	private boolean hasDerivedMethod = true;

	/**
	 * Constructs a representation of a file or directory that has been derived
	 * from another file and is stored outside of the data source (e.g., on a
	 * user's machine). A typical example of a derived file is a file extracted
	 * from an archive file.
	 *
	 * @param db                 The case database to which the file has been
	 *                           added.
	 * @param objId              The object id of the file in the case database.
	 * @param dataSourceObjectId The object id of the data source for the file.
	 * @param name               The name of the file.
	 * @param dirType            The type of the file, usually as reported in
	 *                           the name structure of the file system. May be
	 *                           set to TSK_FS_NAME_TYPE_ENUM.UNDEF.
	 * @param metaType           The type of the file, usually as reported in
	 *                           the metadata structure of the file system. May
	 *                           be set to
	 *                           TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_UNDEF.
	 * @param dirFlag            The allocated status of the file, usually as
	 *                           reported in the name structure of the file
	 *                           system.
	 * @param metaFlags          The allocated status of the file, usually as
	 *                           reported in the metadata structure of the file
	 *                           system.
	 * @param size               The size of the file.
	 * @param ctime              The changed time of the file.
	 * @param crtime             The created time of the file.
	 * @param atime              The accessed time of the file.
	 * @param mtime              The modified time of the file.
	 * @param md5Hash            The MD5 hash of the file, null if not yet
	 *                           calculated.
	 * @param knownState         The known state of the file from a hash
	 *                           database lookup, null if not yet looked up.
	 * @param parentPath         The path of the parent of the file.
	 * @param localPath          The absolute path of the file in secondary
	 *                           storage.
	 * @param parentId           The object id of parent of the file.
	 * @param mimeType           The MIME type of the file, null if it has not
	 *                           yet been determined.
	 * @param encodingType		     The encoding type of the file.
	 * @param extension          The extension part of the file name (not
	 *                           including the '.'), can be null.
	 */
	DerivedFile(SleuthkitCase db,
			long objId,
			long dataSourceObjectId,
			String name,
			TSK_FS_NAME_TYPE_ENUM dirType, TSK_FS_META_TYPE_ENUM metaType,
			TSK_FS_NAME_FLAG_ENUM dirFlag, short metaFlags,
			long size,
			long ctime, long crtime, long atime, long mtime,
			String md5Hash, FileKnown knownState,
			String parentPath,
			String localPath,
			long parentId,
			String mimeType,
			TskData.EncodingType encodingType,
			String extension) {
		// TODO (AUT-1904): The parent id should be passed to AbstractContent 
		// through the class hierarchy contructors.
		super(db, objId, dataSourceObjectId, TskData.TSK_FS_ATTR_TYPE_ENUM.TSK_FS_ATTR_TYPE_DEFAULT, 0,
				name, TSK_DB_FILES_TYPE_ENUM.LOCAL, 0L, 0, dirType, metaType, dirFlag,
				metaFlags, size, ctime, crtime, atime, mtime, (short) 0, 0, 0, md5Hash, knownState, parentPath, mimeType, extension);
		setLocalFilePath(localPath, false);
		setEncodingType(encodingType);
	}

	/**
	 * Indicates whether or not this derived file is the root of a file system,
	 * always returns false.
	 *
	 * @return False.
	 */
	@Override
	public boolean isRoot() {
		return false;
	}

	/**
	 * Gets the method used to derive this file, if it has been recorded.
	 *
	 * @return Derived method or null.
	 *
	 * @throws TskCoreException if there was an error querying the case
	 *                          database.
	 */
	public synchronized DerivedMethod getDerivedMethod() throws TskCoreException {
		if (derivedMethod == null && hasDerivedMethod == true) {
			try {
				derivedMethod = getSleuthkitCase().getDerivedMethod(getId());
				if (derivedMethod == null) {
					hasDerivedMethod = false;  //do not attempt to lazy load
				}
			} catch (TskCoreException e) {
				String msg = MessageFormat.format(bundle.getString("DerviedFile.derivedMethod.exception.msg1.text"), getId());
				logger.log(Level.WARNING, msg, e);
				throw new TskCoreException(msg, e);
			}
		}
		return derivedMethod;
	}

	/**
	 * Accepts a content visitor (Visitor design pattern).
	 *
	 * @param visitor A ContentVisitor supplying an algorithm to run using this
	 *                derived file as input.
	 *
	 * @return The output of the algorithm.
	 */
	@Override
	public <T> T accept(SleuthkitItemVisitor<T> v) {
		return v.visit(this);
	}

	/**
	 * Accepts a Sleuthkit item visitor (Visitor design pattern).
	 *
	 * @param visitor A SleuthkitItemVisitor supplying an algorithm to run using
	 *                this derived file as input.
	 *
	 * @return The output of the algorithm.
	 */
	@Override
	public <T> T accept(ContentVisitor<T> v) {
		return v.visit(this);
	}

	/**
	 * Closes this derived file, if it was open.
	 *
	 * @throws Throwable
	 */
	@Override
	protected void finalize() throws Throwable {
		try {
			close();
		} finally {
			super.finalize();
		}
	}

	/**
	 * Provides a string representation of this derived file.
	 *
	 * @param preserveState True if state should be included in the string
	 *                      representation of this object.
	 *
	 */
	@Override
	public String toString(boolean preserveState) {
		return super.toString(preserveState) + "DerivedFile{" //NON-NLS
				+ "derivedMethod=" + derivedMethod //NON-NLS
				+ ", hasDerivedMethod=" + hasDerivedMethod //NON-NLS
				+ '}';
	}

	/**
	 * A description of the method used to derive a file.
	 */
	public static class DerivedMethod {

		private final int derivedId;
		private String toolName;
		private String toolVersion;
		private String other;
		private String rederiveDetails;

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
			return "DerivedMethod{" + "derived_id=" + derivedId + ", toolName=" + toolName + ", toolVersion=" + toolVersion + ", other=" + other + ", rederiveDetails=" + rederiveDetails + '}'; //NON-NLS
		}
	}

	/**
	 * /**
	 * Constructs a representation of a file or directory that has been derived
	 * from another file and is stored outside of the data source (e.g., on a
	 * user's machine). A typical example of a derived file is a file extracted
	 * from an archive file.
	 *
	 * @param db         The case database to which the file has been added.
	 * @param objId      The object id of the file in the case database.
	 * @param name       The name of the file.
	 * @param dirType    The type of the file, usually as reported in the name
	 *                   structure of the file system. May be set to
	 *                   TSK_FS_NAME_TYPE_ENUM.UNDEF.
	 * @param metaType   The type of the file, usually as reported in the
	 *                   metadata structure of the file system. May be set to
	 *                   TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_UNDEF.
	 * @param dirFlag    The allocated status of the file, usually as reported
	 *                   in the name structure of the file system.
	 * @param metaFlags  The allocated status of the file, usually as reported
	 *                   in the metadata structure of the file system.
	 * @param size       The size of the file.
	 * @param ctime      The changed time of the file.
	 * @param crtime     The created time of the file.
	 * @param atime      The accessed time of the file.
	 * @param mtime      The modified time of the file.
	 * @param md5Hash    The MD5 hash of the file, null if not yet calculated.
	 * @param knownState The known state of the file from a hash database
	 *                   lookup, null if not yet looked up.
	 * @param parentPath The path of the parent of the file.
	 * @param localPath  The absolute path of the file in secondary storage.
	 * @param parentId   The object id of parent of the file.
	 *
	 * @deprecated Do not make subclasses outside of this package.
	 */
	@Deprecated
	@SuppressWarnings("deprecation")
	protected DerivedFile(SleuthkitCase db,
			long objId,
			String name,
			TSK_FS_NAME_TYPE_ENUM dirType, TSK_FS_META_TYPE_ENUM metaType,
			TSK_FS_NAME_FLAG_ENUM dirFlag, short metaFlags,
			long size,
			long ctime, long crtime, long atime, long mtime,
			String md5Hash, FileKnown knownState,
			String parentPath,
			String localPath,
			long parentId) {
		this(db, objId, db.getDataSourceObjectId(objId), name, dirType, metaType, dirFlag, metaFlags, size,
				ctime, crtime, atime, mtime,
				md5Hash, knownState,
				parentPath, localPath, parentId, null, TskData.EncodingType.NONE, null);
	}

}
