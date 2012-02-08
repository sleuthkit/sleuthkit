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
import java.sql.SQLException;
import java.util.*;

/**
 * Represents a file system. 
 * Populated based on data in database.
 */

public class FileSystem extends AbstractContent{

	long img_offset, fs_type, block_size, block_count, root_inum,
	first_inum, last_inum;
	private FileSystemParent parent;
	private long filesystemHandle = 0;

	/**
	 * Constructor most inputs are from the database
	 * @param db java database class
	 * @param obj_id 
	 * @param img_offset
	 * @param fs_type
	 * @param block_size
	 * @param block_count
	 * @param root_inum
	 * @param first_inum
	 * @param last_inum
	 */
	protected FileSystem(SleuthkitCase db, long obj_id, long img_offset,
			long fs_type, long block_size, long block_count, long root_inum,
			long first_inum, long last_inum){
		super(db, obj_id);
		this.img_offset = img_offset; 
		this.fs_type = fs_type;
		this.block_size = block_size;
		this.block_count = block_count;
		this.root_inum = root_inum;
		this.first_inum = first_inum;
		this.last_inum = last_inum;
	}
	
	/**
	 * set the parent class, will be called by the parent
	 * @param p parent volume
	 */
	protected void setParent(FileSystemParent p){
		parent = p;
	}

	/**
	 * read data from the filesystem
	 * @param offset offset in bytes from the start of the filesystem
	 * @param len how many bytes to read
	 * @return the bytes
	 * @throws TskException
	 */
	@Override
	public byte[] read(long offset, long len) throws TskException{
		return SleuthkitJNI.readFs(getFileSystemHandle(), offset, len);
	}

	/**
	 * get the parent volume
	 * @return volume object
	 */
	public FileSystemParent getParent(){
		return parent;
	}

	/**
	 * get the size of the filesystem
	 * @return size of the filesystem
	 */
	@Override
	public long getSize() {
		// size of the file system
		return block_size * block_count;
	}

	/**
	 * lazily loads the filesystem pointer ie: won't be loaded until this is called
	 * @return a filesystem pointer from the sleuthkit
	 * @throws TskException  
	 */
	long getFileSystemHandle() throws TskException{
		if (filesystemHandle == 0){
			filesystemHandle = SleuthkitJNI.openFs(parent.getImageHandle(), img_offset);
		}
		return this.filesystemHandle;
	}

	//methods get exact data from database. could be manipulated to get more
	//meaningful data.

	/**
	 * get the byte offset of this filesystem in the image
	 * @return offset
	 */
	public long getImg_offset() {
		return img_offset;
	}	 	

	/**
	 * get the file system type
	 * @return enum number from sleuthkit database
	 */
	public long getFs_type() {
		return fs_type;
	}	 	
	/**
	 * get the block size
	 * @return block size
	 */
	public long getBlock_size() {
		return block_size;
	}	 	
	/**
	 * get the number of blocks
	 * @return block count
	 */
	public long getBlock_count() {
		return block_count;
	}	 	
	/**
	 * get the inum of the root directory
	 * @return Root metadata address of the file system
	 */
	public long getRoot_inum() {
		return root_inum;
	}	
	/**
	 * get the first inum in this file system
	 * @return first inum
	 */
	public long getFirst_inum() {
		return first_inum;
	}	 	
	/**
	 * get the last inum
	 * @return last inum
	 */
	public long getLast_inum() {
		return last_inum;
	}	

	@Override
	public void finalize(){
		if(filesystemHandle != 0){
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
	public List<Content> getChildren() throws TskException {
		try {
			return db.getFileSystemChildren(this);
		} catch (SQLException ex) {
			throw new TskException("Error while getting FileSystem children.", ex);
		}
	}

	@Override
	public boolean isOnto() {
		return true;
	}
}
