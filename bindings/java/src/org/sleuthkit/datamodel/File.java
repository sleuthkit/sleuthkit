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

import java.util.Collections;
import java.util.List;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_TYPE_ENUM;

/**
 * Representation of File object, stored in tsk_files table. This is for a
 * file-system file (allocated, not-derived, or a "virtual" file) File does not
 * have content children objects associated with it. There are many similarities
 * to a Directory otherwise, which are defined in the parent FsContent class.
 */
public class File extends FsContent {

	//constructor used for getfile from tskDb
	protected File(SleuthkitCase db, long obj_id, long fs_obj_id, long meta_addr, short attr_type,
			short attr_id, String name, short dir_type, short meta_type,
			short dir_flags, short meta_flags, long size, long ctime, long crtime,
			long atime, long mtime, short mode, int uid, int gid, byte known,
			String parent_path, String md5Hash) {
		super(db, obj_id, name, fs_obj_id, meta_addr,
				attr_type, attr_id, meta_type, dir_type, dir_flags,
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
		return Collections.<Content>emptyList();
	}

	@Override
	public List<Long> getChildrenIds() throws TskCoreException {
		return Collections.<Long>emptyList();
	}

	@Override
	public boolean isVirtual() {
		return (!type.equals(TskData.TSK_DB_FILES_TYPE_ENUM.FS)
				|| dir_type == TSK_FS_NAME_TYPE_ENUM.VIRT.getDirType());
	}

	@Override
	public boolean isDir() {
		return false;
	}

	@Override
	public boolean isFile() {
		return true;
	}
}
