/*
 * SleuthKit Java Bindings
 * 
 * Copyright 2011-2016 Basis Technology Corp.
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
import org.sleuthkit.datamodel.TskData.FileKnown;
import org.sleuthkit.datamodel.TskData.TSK_FS_ATTR_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_META_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_FLAG_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_TYPE_ENUM;

/**
 * A representation of a file system file that has been added to a case.
 */
public class File extends FsContent {

	/**
	 * Constructs a representation of a file system file that has been added to
	 * the case.
	 *
	 * @param db                 The case database to which the file has been
	 *                           added.
	 * @param objId              The object id of the file in the case database.
	 * @param dataSourceObjectId The object id of the data source for the file.
	 * @param fsObjId            The object id of the file system to which this
	 *                           file belongs.
	 * @param attrType           The type attribute given to the file by the
	 *                           file system.
	 * @param attrId             The type id given to the file by the file
	 *                           system.
	 * @param name               The name of the file.
	 * @param metaAddr           The meta address of the file.
	 * @param metaSeq            The meta sequence number of the file.
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
	 * @param modes              The modes for the file.
	 * @param uid                The UID for the file.
	 * @param gid                The GID for the file.
	 * @param md5Hash            The MD5 hash of the file, null if not yet
	 *                           calculated.
	 * @param knownState         The known state of the file from a hash
	 *                           database lookup, null if not yet looked up.
	 * @param parentPath         The path of the parent of the file.
	 * @param mimeType           The MIME type of the file, null if it has not
	 *                           yet been determined.
	 */
	File(SleuthkitCase db,
			long objId,
			long dataSourceObjectId,
			long fsObjId,
			TSK_FS_ATTR_TYPE_ENUM attrType, short attrId,
			String name,
			long metaAddr, int metaSeq,
			TSK_FS_NAME_TYPE_ENUM dirType, TSK_FS_META_TYPE_ENUM metaType,
			TSK_FS_NAME_FLAG_ENUM dirFlag, short metaFlags,
			long size,
			long ctime, long crtime, long atime, long mtime,
			short modes, int uid, int gid,
			String md5Hash, FileKnown knownState, String parentPath, String mimeType) {
		super(db, objId, dataSourceObjectId, fsObjId, attrType, attrId, name, metaAddr, metaSeq, dirType, metaType, dirFlag, metaFlags, size, ctime, crtime, atime, mtime, modes, uid, gid, md5Hash, knownState, parentPath, mimeType);
	}

	/**
	 * Gets the derived files, if any, that are children of this file.
	 *
	 * @return A list of the children.
	 *
	 * @throws TskCoreException if there was an error querying the case
	 *                          database.
	 */
	@Override
	public List<Content> getChildren() throws TskCoreException {
		return getSleuthkitCase().getAbstractFileChildren(this, TskData.TSK_DB_FILES_TYPE_ENUM.DERIVED);
	}

	/**
	 * Gets the object ids of the derived files, if any, that are children of
	 * this file.
	 *
	 * @return A list of the children.
	 *
	 * @throws TskCoreException if there was an error querying the case
	 *                          database.
	 */
	@Override
	public List<Long> getChildrenIds() throws TskCoreException {
		return getSleuthkitCase().getAbstractFileChildrenIds(this, TskData.TSK_DB_FILES_TYPE_ENUM.DERIVED);
	}

	/**
	 * Accepts a content visitor (Visitor design pattern).
	 *
	 * @param visitor A ContentVisitor supplying an algorithm to run using this
	 *                file as input.
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
	 *                this file as input.
	 *
	 * @return The output of the algorithm.
	 */
	@Override
	public <T> T accept(ContentVisitor<T> v) {
		return v.visit(this);
	}

	/**
	 * Provides a string representation of this file.
	 *
	 * @param preserveState True if state should be included in the string
	 *                      representation of this object.
	 *
	 * @throws TskCoreException if there was an error querying the case
	 *                          database.
	 */
	@Override
	public String toString(boolean preserveState) {
		return super.toString(preserveState) + "File [\t" + "]\t"; //NON-NLS
	}

	/**
	 * Constructs a representation of a file system file that has been added to
	 * the case.
	 *
	 * @param db         The case database to which the file has been added.
	 * @param objId      The object id of the file in the case database.
	 * @param fsObjId    The object id of the file system to which this file
	 *                   belongs.
	 * @param attrType   The type attribute given to the file by the file
	 *                   system.
	 * @param attrId     The type id given to the file by the file system.
	 * @param name       The name of the file.
	 * @param metaAddr   The meta address of the file.
	 * @param metaSeq    The meta sequence number of the file.
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
	 * @param modes      The modes for the file.
	 * @param uid        The UID for the file.
	 * @param gid        The GID for the file.
	 * @param md5Hash    The MD5 hash of the file, null if not yet calculated.
	 * @param knownState The known state of the file from a hash database
	 *                   lookup, null if not yet looked up.
	 * @param parentPath The path of the parent of the file.
	 *
	 * @deprecated Do not make subclasses outside of this package.
	 */
	@Deprecated
	@SuppressWarnings("deprecation")
	protected File(SleuthkitCase db,
			long objId,
			long fsObjId,
			TSK_FS_ATTR_TYPE_ENUM attrType, short attrId,
			String name,
			long metaAddr, int metaSeq,
			TSK_FS_NAME_TYPE_ENUM dirType, TSK_FS_META_TYPE_ENUM metaType,
			TSK_FS_NAME_FLAG_ENUM dirFlag, short metaFlags,
			long size,
			long ctime, long crtime, long atime, long mtime,
			short modes, int uid, int gid,
			String md5Hash, FileKnown knownState, String parentPath) {
		this(db, objId, db.getDataSourceObjectId(objId), fsObjId, attrType, attrId, name, metaAddr, metaSeq, dirType, metaType, dirFlag, metaFlags, size, ctime, crtime, atime, mtime, modes, uid, gid, md5Hash, knownState, parentPath, null);
	}

}
