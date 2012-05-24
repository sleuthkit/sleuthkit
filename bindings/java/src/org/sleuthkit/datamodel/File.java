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


/**
 * Represents a file in a file system. 
 * Populated based on data in database.
 */
public class File extends FsContent{

	//constructor used for getfile from tskDb
	/**
	 * Constructor most fields are from the database
	 * @param db java database class
	 * @param obj_id
	 * @param meta_addr 
	 * @param attr_type
	 * @param attr_id
	 * @param name
	 * @param dir_type
	 * @param meta_type
	 * @param dir_flags
	 * @param meta_flags
	 * @param size
	 * @param ctime
	 * @param crtime
	 * @param atime
	 * @param mtime
	 * @param mode
	 * @param uid
	 * @param gid
	 */
	protected File(SleuthkitCase db, long obj_id, long fs_obj_id, long meta_addr, long attr_type,
			long attr_id, String name, long dir_type, long meta_type,
			long dir_flags, long meta_flags, long size, long ctime, long crtime,
			long atime, long mtime, long mode, long uid, long gid, long known,
			String parent_path) {
		super(db, obj_id, fs_obj_id);
		this.meta_addr = meta_addr;
		this.attr_type = attr_type;
		this.attr_id = attr_id;
		this.name = name;
		this.dir_type = dir_type;
		this.meta_type = meta_type;
		this.dir_flags = dir_flags;
		this.meta_flags = meta_flags;
		this.size = size;
		this.ctime = ctime;
		this.crtime = crtime;
		this.atime = atime;
		this.mtime = mtime;
		this.mode = mode;
		this.uid = uid;
		this.gid = gid;
		this.known = known;
		this.parent_path = parent_path;
	}

	/**
	 * is this a file?
	 * @return true, it is a file
	 */
	@Override
	public boolean isFile(){
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
	public List<Content> getChildren() throws TskException {
        return Collections.<Content>emptyList();
	}

	@Override
	public boolean isOnto() {
		return false;
	}
}

