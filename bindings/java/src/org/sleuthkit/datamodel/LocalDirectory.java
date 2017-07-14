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
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. * 

 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.datamodel;

import org.sleuthkit.datamodel.TskData.FileKnown;
import org.sleuthkit.datamodel.TskData.TSK_FS_ATTR_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_META_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_FLAG_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_TYPE_ENUM;

/**
 * A local directory that can be used as a parent for local files.
 * Not a file system
 */
public class LocalDirectory extends SpecialDirectory {

	/**
	 * Constructs a local directory that can be used as a parent for
	 * local files. Not a file system directory.
	 *
	 * @param db                 The case database.
	 * @param objId              The object id of the local directory.
	 * @param dataSourceObjectId The object id of the data source for the
	 *                           local directory
	 * @param name               The name of the local directory.
	 * @param dirType            The TSK_FS_NAME_TYPE_ENUM for the local
	 *                           directory.
	 * @param metaType           The TSK_FS_META_TYPE_ENUM for the local
	 *                           directory.
	 * @param dirFlag            The TSK_FS_META_TYPE_ENUM for the local
	 *                           directory.
	 * @param metaFlags          The meta flags for the local directory.
	 * @param size               The size of the local directory, should be
	 *                           zero.
	 * @param md5Hash            The MD5 hash for the local directory.
	 * @param knownState         The known state for the local directory
	 * @param parentPath         The parent path for the local directory
	 */
	LocalDirectory(SleuthkitCase db,
			long objId,
			long dataSourceObjectId,
			String name,
			TSK_FS_NAME_TYPE_ENUM dirType, TSK_FS_META_TYPE_ENUM metaType,
			TSK_FS_NAME_FLAG_ENUM dirFlag, short metaFlags,
			String md5Hash, FileKnown knownState,
			String parentPath) {
		super(db, objId, dataSourceObjectId, TSK_FS_ATTR_TYPE_ENUM.TSK_FS_ATTR_TYPE_DEFAULT, 0, name,
				TskData.TSK_DB_FILES_TYPE_ENUM.LOCAL_DIR, 0L, 0, dirType, metaType, dirFlag,
				metaFlags, 0L, 0L, 0L, 0L, 0L, (short) 0, 0, 0, md5Hash, knownState, parentPath, null);
	}
	
	/**
	 * Check whether this LocalDirectory is a data source.
	 * Will always be false.
	 * @return false
	 */
	public boolean isDataSource() {
		return false;
	}

	/**
	 * Accepts a content visitor (Visitor design pattern).
	 *
	 * @param visitor A ContentVisitor supplying an algorithm to run using this
	 *                local directory as input.
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
	 * @param visitor A SleuthkitItemVisitor supplying an algorithm to run using
	 *                this local directory as input.
	 *
	 * @return The output of the algorithm.
	 */
	@Override
	public <T> T accept(SleuthkitItemVisitor<T> visitor) {
		return visitor.visit(this);
	}

	/**
	 * Provides a string representation of this local directory.
	 *
	 * @param preserveState True if state should be included in the string
	 *                      representation of this object.
	 *
	 * @return string representation of this local directory
	 * @throws TskCoreException if there was an error querying the case
	 *                          database.
	 */
	@Override
	public String toString(boolean preserveState) {
		return super.toString(preserveState) + "LocalDirectory [\t" + "]\t"; //NON-NLS
	}
}
