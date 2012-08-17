/*
 * Autopsy Forensic Browser
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

/**
 * Common fields methods for objects stored in tsk_files table
 * Abstract files are divided into subtypes defined in TSK_DB_FILES_TYPE_ENUM
 * and further divided into files and directories
 */
public abstract class AbstractFile extends AbstractContent {
    
    protected final TskData.TSK_DB_FILES_TYPE_ENUM type;
    
	/**
	 * Initializes common fields used by AbstactFile implementations (objects in tsk_files table)
	 * 
	 * @param db case / db handle where this file belongs to
	 * @param obj_id object id in tsk_objects table
	 * @param name name field of the file
	 * @param type type of the file
	 */
    protected AbstractFile(SleuthkitCase db, long obj_id, String name, TskData.TSK_DB_FILES_TYPE_ENUM type) {
        super(db, obj_id, name);
        this.type = type;
    }
    
	/**
	 * Gets type of the abstract file as defined in TSK_DB_FILES_TYPE_ENUM
	 * 
	 * @return the type of the abstract file
	 */
    public TskData.TSK_DB_FILES_TYPE_ENUM getType() {
        return type;
    }
    
	/**
	 * Gets file ranges associated with the file.  File ranges are objects in tsk_file_layout table
	 * Any file type (especially unallocated) may have 1 or more block ranges associated with it
	 * 
	 * @return list of file layout ranges
	 * @throws TskCoreException exception thrown if critical error occurred within tsk core
	 */
    public abstract List<TskFileRange> getRanges() throws TskCoreException;
	
	
	/**
	 * is this a virtual file or directory
	 * @return true if it's virtual, false otherwise
	 */
	public abstract boolean isVirtual();
	
	/**
	 * Is this object a file
	 *
	 * @return true if a file, false otherwise
	 */
	public abstract boolean isFile();

	/**
	 * Is this object a directory
	 *
	 * @return true if directory, false otherwise
	 */
	public abstract boolean isDir();
    
}
