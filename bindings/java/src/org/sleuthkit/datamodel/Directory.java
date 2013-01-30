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

	//constructor used for getdir from tskDb
	protected Directory(SleuthkitCase db, long objId, long fsObjId, long meta_addr,
			TSK_FS_ATTR_TYPE_ENUM attr_type, short attr_id, String name, TSK_FS_NAME_TYPE_ENUM dirType,
			TSK_FS_META_TYPE_ENUM metaType, TSK_FS_NAME_FLAG_ENUM dirFlag, short meta_flags, long size,
			long ctime, long crtime, long atime, long mtime, short mode,
			int uid, int gid, FileKnown known, String parent_path, String md5Hash) {
		super(db, objId, fsObjId, name, meta_addr,
				attr_type, attr_id, dirType, metaType, dirFlag,
				meta_flags, size, ctime, crtime, atime, mtime, uid, gid, mode, known,
				parent_path, md5Hash);
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
	public boolean isVirtual() {
		return type.equals(TSK_DB_FILES_TYPE_ENUM.VIRTUAL_DIR);
	}

	@Override
	public boolean isDir() {
		return true;
	}

	@Override
	public boolean isFile() {
		return false;
	}
}
