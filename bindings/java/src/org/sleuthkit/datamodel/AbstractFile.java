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

import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;
import java.util.logging.Level;
import java.util.logging.Logger;

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
	
	/**
	 * Is this a root of a file system
	 *
	 * @return true if root of a file system, false otherwise
	 */
	public abstract boolean isRoot();

	/**
	 * @param uniquePath the unique path to an AbstractFile (or subclass)
	 * usually obtained by a call to AbstractFile.getUniquePath.
	 * @return the path to to an AbstractFile (or subclass) with the image and
	 * volume path segments removed.
	 */
	public static String createNonUniquePath(String uniquePath) {
		
		// split the path into parts
		String[] pathSegments = uniquePath.split("/\\");
		
		// see if uniquePath had an image and/or volume name
		int index = 0;
		if (pathSegments[0].startsWith("img_")) {
			++index;
		}
		if (pathSegments[1].startsWith("vol_")) {
			++index;
		}
		
		// Assemble the non-unique path (skipping over the image and volume
		// name, if they exist).
		StringBuilder strbuf = new StringBuilder();
		for (; index < pathSegments.length; ++index) {
			strbuf.append("/").append(pathSegments[index]);
		}
		
		return strbuf.toString();
	}
	
	/**
	 * @return a list of AbstractFiles that are the children of this Directory.
	 * Only returns children of type TskData.TSK_DB_FILES_TYPE_ENUM.FS.
	 */
	public List<AbstractFile> listFiles() throws TskCoreException {
		// first, get all children
		List<Content> children = getChildren();
		
		// only keep those that are of type AbstractFile
		List<AbstractFile> files = new ArrayList<AbstractFile>();
		for (Content child : children) {
			if (child instanceof AbstractFile) {
				AbstractFile afChild = (AbstractFile)child;
				files.add(afChild);
			}
		}
		return files;
	}
	@Override
    public String toString()
	{
		return "AbstractFile [" + super.toString() + "getType " + getType() + " " + "isDir " + isDir() + " " + "isFile " + isFile() + " " + "isRoot " + isRoot() + " " + "isVirtual " + isVirtual() + "]";
	}
}
