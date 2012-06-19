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
 * Representation of File object, stored in tsk_files table.
 * This is for a file-system file (allocated, not-derived, or a "virtual" file)
 * File does not have content children objects associated with it.
 * There are many similarities to a Directory otherwise, which are defined in the parent FsContent class.
 */
public class File extends FsContent{

    //constructor used for getfile from tskDb
    protected File(SleuthkitCase db, long obj_id, long fs_obj_id, long meta_addr, long attr_type,
            long attr_id, String name, long dir_type, long meta_type,
            long dir_flags, long meta_flags, long size, long ctime, long crtime,
            long atime, long mtime, long mode, long uid, long gid, long known,
            String parent_path, String md5Hash) {
        super(db, obj_id, name, fs_obj_id, meta_addr,
			attr_type, attr_id, meta_type, dir_type, dir_flags,
			meta_flags, size, ctime, crtime, atime, mtime, uid, gid, mode, known,
			parent_path, md5Hash);
    }

    /**	
     * Is this a file?
     * @return true, it is a file
     */
    @Override
    public boolean isFile(){
        return true;
    }

	/**
     * Visitor pattern support for sleuthkit item objects 
	 * (tsk database objects, such as content and artifacts)
     * @param <T> visitor algorithm return type
     * @param v visitor supplying an algorithm to run on the sleuthkit item object
     * @return visitor return value resulting from running the algorithm
     */
    @Override
    public <T> T accept(SleuthkitItemVisitor<T> v) {
        return v.visit(this);
    }

	
	/**
     * Visitor pattern support for content objects only
     * @param <T> visitor algorithm return type
     * @param v visitor supplying an algorithm to run on the content object
     * @return visitor return value resulting from running the algorithm
     */
    @Override
    public <T> T accept(ContentVisitor<T> v) {
        return v.visit(this);
    }

	/**
	 * Gets child content objects associated with the file - an empty list.
	 * This type of a file (physical fs file, not derived) does not have children associated with it.
	 * But any future subclasses could.
	 * @return list of child content objects
	 * @throws TskCoreException exception thrown if a critical error occurred within tsk core
	 */
    @Override
    public List<Content> getChildren() throws TskCoreException {
        return Collections.<Content>emptyList();
    }
}
