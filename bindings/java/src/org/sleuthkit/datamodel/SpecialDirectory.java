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
import org.sleuthkit.datamodel.TskData.TSK_FS_META_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_FLAG_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_TYPE_ENUM;

/**
 * Parent class for special directory types (Local and Virtual)
 */
public abstract class SpecialDirectory extends AbstractFile {

	SpecialDirectory(SleuthkitCase db,
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
			String mimeType) {
		super(db, objId, dataSourceObjectId, attrType, attrId, name,
				fileType, metaAddr, metaSeq, dirType, metaType, dirFlag,
				metaFlags, size, ctime, crtime, atime, mtime, modes, uid, gid, md5Hash, knownState, parentPath, mimeType, null);
	}

	/**
	 * Gets the extents in terms of byte addresses of this directory
	 * within its data source, always an empty list.
	 *
	 * @return An empty list.
	 *
	 * @throws TskCoreException if there was an error querying the case
	 *                          database.
	 */
	@Override
	public List<TskFileRange> getRanges() throws TskCoreException {
		return Collections.<TskFileRange>emptyList();
	}
	
	/**
	 * Indicates whether or not this is a data source.
	 *
	 * @return True or false.
	 */
	public boolean isDataSource() {
		return (this.getDataSourceObjectId() == this.getId());
	}

	/**
	 * Does nothing, a special directory cannot be opened, read, or closed.
	 */
	@Override
	public void close() {
	}

	/**
	 * Indicates whether or not this directory is the root of a file
	 * system, always returns false.
	 *
	 * @return False.
	 */
	@Override
	public boolean isRoot() {
		return false;
	}
}
