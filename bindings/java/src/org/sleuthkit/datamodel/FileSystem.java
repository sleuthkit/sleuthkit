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

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.sleuthkit.datamodel.TskData.TSK_DB_FILES_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_TYPE_ENUM;

/**
 * Represents a file system object stored in tsk_fs_info table
 * FileSystem has a parent content object (volume or image) and children content objects (files and directories)
 * and fs-specific attributes.
 * The object also maintains a handle to internal file-system structures 
 * and the handle is reused across reads.
 */
public class FileSystem extends AbstractContent {

	private long imgOffset, blockSize, blockCount, rootInum,
			firstInum, lastInum;
	private TskData.TSK_FS_TYPE_ENUM fsType;
	private Content parent;
	private long filesystemHandle = 0;

	/**
	 * Constructor most inputs are from the database
	 * @param db the case handle
	 * @param obj_id the unique object id
	 * @param name filesystem name
	 * @param img_offset image offset
	 * @param fs_type filesystem type
	 * @param block_size block size in this fs
	 * @param block_count number of blocks in this fs
	 * @param root_inum the root inum
	 * @param first_inum the first inum
	 * @param last_inum the last inum
	 */
	protected FileSystem(SleuthkitCase db, long obj_id, String name, long img_offset,
			TskData.TSK_FS_TYPE_ENUM fs_type, long block_size, long block_count, long root_inum,
			long first_inum, long last_inum) {
		super(db, obj_id, name);
		this.imgOffset = img_offset;
		this.fsType = fs_type;
		this.blockSize = block_size;
		this.blockCount = block_count;
		this.rootInum = root_inum;
		this.firstInum = first_inum;
		this.lastInum = last_inum;
	}

	/**
	 * Set the parent content object, will be called by the parent 
	 * when populating the object from database.
	 * 
	 * @param p parent volume or image.
	 * Should only be called by methods which ensure p is a volume or image
	 */
	protected void setParent(Content p) {
		parent = p;
	}


	@Override
	public synchronized int read(byte[] buf, long offset, long len) throws TskCoreException {
		return SleuthkitJNI.readFs(getFileSystemHandle(), buf, offset, len);
	}

	/**
	 * Get the parent volume or image Content object
	 * @return parent content object (volume or image)
	 */
	public Content getParent() {
		return parent;
	}


	@Override
	public long getSize() {
		// size of the file system
		return blockSize * blockCount;
	}

	/**
	 * Lazily loads the internal file system structure: won't be loaded until this is called
	 * and maintains the handle to it to reuse it
	 * @return a filesystem pointer from the sleuthkit
	 * @throws TskCoreException exception throw if an internal tsk core error occurs  
	 */
	synchronized long getFileSystemHandle() throws TskCoreException {
		if (filesystemHandle == 0) {
			filesystemHandle = SleuthkitJNI.openFs(getImage().getImageHandle(), imgOffset);
		}
		return this.filesystemHandle;
	}
	
	public Directory getRootDirectory() throws TskCoreException {
		
		String directDirectoryDescendents = "SELECT tsk_files.*"
				+ " FROM tsk_objects JOIN tsk_files"
				+ " ON tsk_objects.obj_id = tsk_files.obj_id"
				+ " WHERE (tsk_objects.par_obj_id = " + getId()
				+ " AND tsk_files.type = " + TSK_DB_FILES_TYPE_ENUM.FS.getFileType()
				+ " AND tsk_files.dir_type = " + TSK_FS_NAME_TYPE_ENUM.DIR.getDirType() + ")";
		
		Directory dir = null;
		try {
			ResultSet rs = getSleuthkitCase().runQuery(directDirectoryDescendents);
			dir = new ResultSetHelper(getSleuthkitCase()).directory(rs, this);
		} catch (SQLException ex) {
			throw new TskCoreException("There was a problem while trying to obtain this file system's root directory: ", ex);
		}

		return dir;
	}

	/**
	 * Get the byte offset of this file system in the image
	 * 
	 * @return offset
	 */
	public long getImageOffset() {
		return imgOffset;
	}

	/**
	 * Get the file system type
	 * 
	 * @return enum value of fs type
	 */
	public TskData.TSK_FS_TYPE_ENUM getFsType() {
		return fsType;
	}

	/**
	 * Get the block size
	 * 
	 * @return block size
	 */
	public long getBlock_size() {
		return blockSize;
	}

	/**
	 * Get the number of blocks
	 * 
	 * @return block count
	 */
	public long getBlock_count() {
		return blockCount;
	}

	/**
	 * Get the inum of the root directory
	 * 
	 * @return Root metadata address of the file system
	 */
	public long getRoot_inum() {
		return rootInum;
	}

	/**
	 * Get the first inum in this file system
	 * 
	 * @return first inum
	 */
	public long getFirst_inum() {
		return firstInum;
	}

	/**
	 * Get the last inum
	 * @return last inum
	 */
	public long getLastInum() {
		return lastInum;
	}


	@Override
	public void finalize() {
		if (filesystemHandle != 0) {
			SleuthkitJNI.closeFs(filesystemHandle);
		}
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
		return getSleuthkitCase().getFileSystemChildren(this);
	}
	
	@Override
	public List<Long> getChildrenIds() throws TskCoreException {
		return getSleuthkitCase().getFileSystemChildrenIds(this);
	}


	@Override
	public Image getImage() throws TskCoreException {
		return getParent().getImage();
	}
}
