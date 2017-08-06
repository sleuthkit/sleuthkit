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

import java.util.Collections;
import java.util.List;
import org.sleuthkit.datamodel.TskData.FileKnown;
import org.sleuthkit.datamodel.TskData.TSK_DB_FILES_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_ATTR_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_META_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_FLAG_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_TYPE_ENUM;

/**
 * A representation of a local/logical file (e.g., on a user's machine) that has
 * been added to a case.
 */
public class LocalFile extends AbstractFile {

	/**
	 * Constructs a representation of a local/logical file (e.g., on a user's
	 * machine) that has been added to the case database.
	 *
	 * @param db                 The case database to which the file has been
	 *                           added.
	 * @param objId              The object id of the file in the case database.
	 * @param name               The name of the file.
	 * @param fileType           The type of the file.
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
	 * @param mimeType           The MIME type of the file, null if it has not
	 *                           yet been determined.
	 * @param md5Hash            The MD5 hash of the file, null if not yet
	 *                           calculated.
	 * @param knownState         The known state of the file from a hash
	 *                           database lookup, null if not yet looked up.
	 * @param parentId           The object id of parent of the file.
	 * @param parentPath         The path of the parent of the file.
	 * @param dataSourceObjectId The object id of the data source for the file.
	 * @param localPath          The absolute path of the file in secondary
	 *                           storage.
	 * @param encodingType		     The encoding type of the file.
	 * @param extension          The extension part of the file name (not
	 *                           including the '.'), can be null.
	 */
	LocalFile(SleuthkitCase db,
			long objId,
			String name,
			TSK_DB_FILES_TYPE_ENUM fileType,
			TSK_FS_NAME_TYPE_ENUM dirType, TSK_FS_META_TYPE_ENUM metaType,
			TSK_FS_NAME_FLAG_ENUM dirFlag, short metaFlags,
			long size,
			long ctime, long crtime, long atime, long mtime,
			String mimeType, String md5Hash, FileKnown knownState,
			long parentId, String parentPath,
			long dataSourceObjectId,
			String localPath,
			TskData.EncodingType encodingType,
			String extension) {
		super(db, objId, dataSourceObjectId, TSK_FS_ATTR_TYPE_ENUM.TSK_FS_ATTR_TYPE_DEFAULT, 0,
				name, fileType, 0L, 0, dirType, metaType, dirFlag,
				metaFlags, size, ctime, crtime, atime, mtime, (short) 0, 0, 0, md5Hash, knownState, parentPath, mimeType, extension);
		// TODO (AUT-1904): The parent id should be passed to AbstractContent 
		// through the class hierarchy contructors, using 
		// AbstractContent.UNKNOWN_ID as needed.
		if (parentId > 0) {
			setParentId(parentId);
		}
		super.setLocalFilePath(localPath, true);
		setEncodingType(encodingType);
	}

	/**
	 * Gets the extents in terms of byte addresses of this local file within its
	 * data source, an empty list.
	 *
	 * @return An empty list of extents (TskFileRange objects)
	 *
	 * @throws TskCoreException if there was an error querying the case
	 *                          database.
	 */
	@Override
	public List<TskFileRange> getRanges() throws TskCoreException {
		return Collections.<TskFileRange>emptyList();
	}

	/**
	 * Indicates whether or not this local file is the root of a file system,
	 * always returns false.
	 *
	 * @return False.
	 */
	@Override
	public boolean isRoot() {
		return false;
	}

	/**
	 * Accepts a content visitor (Visitor design pattern).
	 *
	 * @param <T>     The type returned by the visitor.
	 * @param visitor A ContentVisitor supplying an algorithm to run using this
	 *                local file as input.
	 *
	 * @return The output of the algorithm.
	 */
	@Override
	public <T> T accept(ContentVisitor<T> visitor) {
		return visitor.visit(this);
	}

	/**
	 * Accepts a Sleuthkit item visitor (Visitor design pattern).
	 *
	 * @param <T>     The type returned by the visitor.
	 * @param visitor A SleuthkitItemVisitor supplying an algorithm to run using
	 *                this local file as input.
	 *
	 * @return The output of the algorithm.
	 */
	@Override
	public <T> T accept(SleuthkitItemVisitor<T> visitor) {
		return visitor.visit(this);
	}

	/**
	 * Provides a string representation of this local file.
	 *
	 * @param preserveState True if state should be included in the string
	 *                      representation of this object.
	 */
	@Override
	public String toString(boolean preserveState) {
		return super.toString(preserveState) + "LocalFile [\t" + "]\t"; //NON-NLS
	}

	/**
	 * Constructs a representation of a local/logical file (e.g., on a user's
	 * machine) that has been added to the case database.
	 *
	 * @param db         The case database to which the file has been added.
	 * @param objId      The object id of the file in the case database.
	 * @param name       The name of the file.
	 * @param fileType   The type of the file.
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
	 *
	 * @deprecated Do not make subclasses outside of this package.
	 */
	@Deprecated
	@SuppressWarnings("deprecation")
	protected LocalFile(SleuthkitCase db,
			long objId,
			String name,
			TSK_DB_FILES_TYPE_ENUM fileType,
			TSK_FS_NAME_TYPE_ENUM dirType, TSK_FS_META_TYPE_ENUM metaType,
			TSK_FS_NAME_FLAG_ENUM dirFlag, short metaFlags,
			long size,
			long ctime, long crtime, long atime, long mtime,
			String md5Hash, FileKnown knownState,
			String parentPath,
			String localPath) {
		this(db,
				objId,
				name,
				fileType,
				dirType, metaType,
				dirFlag, metaFlags,
				size,
				ctime, crtime, atime, mtime,
				null, md5Hash, knownState,
				AbstractContent.UNKNOWN_ID, parentPath,
				db.getDataSourceObjectId(objId),
				localPath,
				TskData.EncodingType.NONE, null);
	}

	/**
	 * Constructs a representation of a local/logical file (e.g., on a user's
	 * machine) that has been added to the case database.
	 *
	 * @param db         The case database to which the file has been added.
	 * @param objId      The object id of the file in the case database.
	 * @param name       The name of the file.
	 * @param fileType   The type of the file.
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
	protected LocalFile(SleuthkitCase db,
			long objId,
			String name,
			TSK_DB_FILES_TYPE_ENUM fileType,
			TSK_FS_NAME_TYPE_ENUM dirType, TSK_FS_META_TYPE_ENUM metaType,
			TSK_FS_NAME_FLAG_ENUM dirFlag, short metaFlags,
			long size,
			long ctime, long crtime, long atime, long mtime,
			String md5Hash, FileKnown knownState,
			String parentPath, String localPath, long parentId) {
		this(db, objId, name, fileType, dirType, metaType, dirFlag, metaFlags, size, ctime, crtime, atime, mtime, md5Hash, knownState, parentPath, localPath);
	}

	/**
	 * Constructs a representation of a local/logical file (e.g., on a user's
	 * machine) that has been added to the case.
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
	protected LocalFile(SleuthkitCase db,
			long objId,
			String name,
			TSK_FS_NAME_TYPE_ENUM dirType, TSK_FS_META_TYPE_ENUM metaType,
			TSK_FS_NAME_FLAG_ENUM dirFlag, short metaFlags,
			long size,
			long ctime, long crtime, long atime, long mtime,
			String md5Hash, FileKnown knownState,
			String parentPath, String localPath, long parentId) {
		this(db, objId, name, TSK_DB_FILES_TYPE_ENUM.LOCAL, dirType, metaType, dirFlag, metaFlags, size, ctime, crtime, atime, mtime, md5Hash, knownState, parentPath, localPath);
	}
}
