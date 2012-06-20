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

import java.util.ArrayList;
import java.util.List;

/**
 * Representation of Directory object, stored in tsk_files table.
 * Directory can have other content children associated with it.
 * There are many similarities to a File otherwise, which are defined in the parent FsContent class.
 */
public class Directory extends FsContent{

	//constructor used for getdir from tskDb
    protected Directory(SleuthkitCase db, long obj_id, long fs_obj_id, long meta_addr,
			long attr_type, long attr_id, String name, long dir_type,
			long meta_type, long dir_flags, long meta_flags, long size, 
			long ctime, long crtime, long atime, long mtime, long mode,
			long uid, long gid, long known, String parent_path, String md5Hash) {
        super(db, obj_id, name, fs_obj_id, meta_addr,
			attr_type, attr_id, meta_type, dir_type, dir_flags,
			meta_flags, size, ctime, crtime, atime, mtime, uid, gid, mode, known,
			parent_path, md5Hash);
    }


    @Override
	public boolean isDir(){
        return true;
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
		return new ArrayList<Content>(getSleuthkitCase().getDirectoryChildren(this));
    }

}
