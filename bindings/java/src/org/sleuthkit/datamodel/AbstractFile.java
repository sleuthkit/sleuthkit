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
import java.util.Set;
import org.sleuthkit.datamodel.TskData.TSK_FS_META_FLAG_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_META_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_FLAG_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_TYPE_ENUM;

/**
 * Common fields methods for objects stored in tsk_files table Abstract files
 * are divided into subtypes defined in TSK_DB_FILES_TYPE_ENUM and further
 * divided into files and directories
 */
public abstract class AbstractFile extends AbstractContent {

	protected final TskData.TSK_DB_FILES_TYPE_ENUM type;
	protected long size;
	/*
	 * path of parent directory
	 */
	protected final String parentPath;
	protected final TSK_FS_NAME_TYPE_ENUM dirType;
	protected final TSK_FS_META_TYPE_ENUM metaType;
	protected final TSK_FS_NAME_FLAG_ENUM dirFlag;
	protected final Set<TSK_FS_META_FLAG_ENUM> metaFlags;

	/**
	 * Initializes common fields used by AbstactFile implementations (objects in
	 * tsk_files table)
	 *
	 * @param db case / db handle where this file belongs to
	 * @param obj_id object id in tsk_objects table
	 * @param name name field of the file
	 * @param type type of the file
	 */
	protected AbstractFile(SleuthkitCase db, long obj_id, String name, TskData.TSK_DB_FILES_TYPE_ENUM type,
			TSK_FS_NAME_TYPE_ENUM dirType, TSK_FS_META_TYPE_ENUM metaType, TSK_FS_NAME_FLAG_ENUM dirFlag, short meta_flags,
			long size, String parentPath) {
		super(db, obj_id, name);
		this.type = type;
		this.dirType = dirType;
		this.metaType = metaType;
		this.dirFlag = dirFlag;
		this.metaFlags = TSK_FS_META_FLAG_ENUM.valuesOf(meta_flags);
		this.size = size;
		this.parentPath = parentPath;
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
	 * Get size of the file
	 *
	 * @return file size in bytes
	 */
	@Override
	public long getSize() {
		return size;
	}

	/**
	 * Get path of the parent of this file
	 *
	 * @return path string of the parent
	 */
	public String getParentPath() {
		return parentPath;
	}

	/**
	 * Gets file ranges associated with the file. File ranges are objects in
	 * tsk_file_layout table Any file type (especially unallocated) may have 1
	 * or more block ranges associated with it
	 *
	 * @return list of file layout ranges
	 * @throws TskCoreException exception thrown if critical error occurred
	 * within tsk core
	 */
	public abstract List<TskFileRange> getRanges() throws TskCoreException;

	/**
	 * is this a virtual file or directory
	 *
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
				AbstractFile afChild = (AbstractFile) child;
				files.add(afChild);
			}
		}
		return files;
	}

	/**
	 * Get the meta data type
	 *
	 * @return meta data type
	 */
	public TSK_FS_META_TYPE_ENUM getMetaType() {
		return metaType;
	}

	public String getMetaTypeAsString() {
		return metaType.toString();
	}

	/**
	 * Get the directory type id
	 *
	 * @return directory type id
	 */
	public TSK_FS_NAME_TYPE_ENUM getDirType() {
		return dirType;
	}

	public String getDirTypeAsString() {
		return dirType.toString();
	}

	/**
	 * @param flag the TSK_FS_NAME_FLAG_ENUM to check
	 * @return true if the given flag is set in this FsContent object.
	 */
	public boolean isDirNameFlagSet(TSK_FS_NAME_FLAG_ENUM flag) {
		return dirFlag == flag;
	}

	/**
	 * @return a string representation of the directory name flag (type
	 * TSK_FS_NAME_FLAG_ENUM)
	 */
	public String getDirFlagAsString() {
		return dirFlag.toString();
	}


	/**
	 * @return a string representation of the meta flags
	 */
	public String getMetaFlagsAsString() {
		String str = "";
		if (metaFlags.contains(TSK_FS_META_FLAG_ENUM.ALLOC)) {
			str = TSK_FS_META_FLAG_ENUM.ALLOC.toString();
		} else if (metaFlags.contains(TSK_FS_META_FLAG_ENUM.ALLOC)) {
			str = TSK_FS_META_FLAG_ENUM.UNALLOC.toString();
		}
		return str;
	}

	/**
	 * @param metaFlag the TSK_FS_META_FLAG_ENUM to check
	 * @return true if the given meta flag is set in this FsContent object.
	 */
	public boolean isMetaFlagSet(TSK_FS_META_FLAG_ENUM metaFlag) {
		return metaFlags.contains(metaFlag);
	}
}
