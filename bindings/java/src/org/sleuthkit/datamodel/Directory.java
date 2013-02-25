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

import java.util.List;
import org.sleuthkit.datamodel.TskData.FileKnown;
import org.sleuthkit.datamodel.TskData.TSK_DB_FILES_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_ATTR_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_META_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_FLAG_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_TYPE_ENUM;

/**
 * Representation of Directory object, stored in tsk_files table. Directory can
 * have other content children associated with it. There are many similarities
 * to a File otherwise, which are defined in the parent FsContent class.
 */
public class Directory extends FsContent {

	/**
	 * Create directory from db 
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
	 * @param md5Hash
	 * @param knownState
	 * @param parentPath 
	 */	
	protected  Directory (SleuthkitCase db, long objId, long fsObjId, 
			TSK_FS_ATTR_TYPE_ENUM attrType, short attrId, 
			String name, long metaAddr, 
			TSK_FS_NAME_TYPE_ENUM dirType, TSK_FS_META_TYPE_ENUM metaType, 
			TSK_FS_NAME_FLAG_ENUM dirFlag, short metaFlags, 
			long size, long ctime, long crtime, long atime, long mtime, short modes, 
			int uid, int gid, String md5Hash, FileKnown knownState, String parentPath) {
		super(db, objId, fsObjId, attrType, attrId, name, metaAddr, dirType, metaType, dirFlag, metaFlags, size, ctime, crtime, atime, mtime, modes, uid, gid, md5Hash, knownState, parentPath);
	}
	

	@Override
	public <T> T accept(SleuthkitItemVisitor<T> v) {
		return v.visit(this);
	}

	@Override
	public <T> T accept(ContentVisitor<T> v) {
		return v.visit(this);
	}

	@Override
	public List<Content> getChildren() throws TskCoreException {
		return getSleuthkitCase().getDirectoryChildren(this);
	}

	@Override
	public List<Long> getChildrenIds() throws TskCoreException {
		return getSleuthkitCase().getDirectoryChildrenIds(this);
	}


	
	@Override
	public String toString(boolean preserveState){
		return super.toString(preserveState) + "Directory [\t" + "]\t";
	}
}
