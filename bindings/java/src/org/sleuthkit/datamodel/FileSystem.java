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

import java.util.*;

/**
 * Represents a file system object stored in tsk_fs_info table
 * FileSystem has a parent content object (volume or image) and children content objects (files and directories)
 * and fs-specific attributes.
 * The object also maintains a handle to internal file-system structures 
 * and the handle is reused across reads.
 */
public class FileSystem extends AbstractContent {

	long img_offset, fs_type, block_size, block_count, root_inum,
			first_inum, last_inum;
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
			long fs_type, long block_size, long block_count, long root_inum,
			long first_inum, long last_inum) {
		super(db, obj_id, name);
		this.img_offset = img_offset;
		this.fs_type = fs_type;
		this.block_size = block_size;
		this.block_count = block_count;
		this.root_inum = root_inum;
		this.first_inum = first_inum;
		this.last_inum = last_inum;
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
	public int read(byte[] buf, long offset, long len) throws TskCoreException {
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
		return block_size * block_count;
	}

	/**
	 * Lazily loads the internal file system structure: won't be loaded until this is called
	 * and maintains the handle to it to reuse it
	 * @return a filesystem pointer from the sleuthkit
	 * @throws TskCoreException exception throw if an internal tsk core error occurs  
	 */
	long getFileSystemHandle() throws TskCoreException {
		if (filesystemHandle == 0) {
			filesystemHandle = SleuthkitJNI.openFs(getImage().getImageHandle(), img_offset);
		}
		return this.filesystemHandle;
	}

	/**
	 * Get the byte offset of this file system in the image
	 * 
	 * @return offset
	 */
	public long getImg_offset() {
		return img_offset;
	}

	/**
	 * Get the file system type
	 * 
	 * @return enum number from sleuthkit database
	 */
	public long getFs_type() {
		return fs_type;
	}

	/**
	 * Get the block size
	 * 
	 * @return block size
	 */
	public long getBlock_size() {
		return block_size;
	}

	/**
	 * Get the number of blocks
	 * 
	 * @return block count
	 */
	public long getBlock_count() {
		return block_count;
	}

	/**
	 * Get the inum of the root directory
	 * 
	 * @return Root metadata address of the file system
	 */
	public long getRoot_inum() {
		return root_inum;
	}

	/**
	 * Get the first inum in this file system
	 * 
	 * @return first inum
	 */
	public long getFirst_inum() {
		return first_inum;
	}

	/**
	 * Get the last inum
	 * @return last inum
	 */
	public long getLast_inum() {
		return last_inum;
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
		return new ArrayList<Content>(getSleuthkitCase().getFileSystemChildren(this));
	}


	@Override
	public Image getImage() throws TskCoreException {
		return getParent().getImage();
	}
}
