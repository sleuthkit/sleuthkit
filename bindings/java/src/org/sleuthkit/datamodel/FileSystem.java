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
 *
 * @author alawrence
 */
public class FileSystem implements Content{

	long fs_id, img_offset, vol_id, fs_type, block_size, block_count, root_inum,
	first_inum, last_inum;
	private Sleuthkit db;
	private Volume parentVolume;
	private long filesystemHandle = 0;

	/**
	 * Constructor most inputs are from the database
	 * @param db java database class
	 * @param fs_id
	 * @param img_offset
	 * @param vol_id
	 * @param fs_type
	 * @param block_size
	 * @param block_count
	 * @param root_inum
	 * @param first_inum
	 * @param last_inum
	 */
	protected FileSystem(Sleuthkit db, long fs_id, long img_offset, long vol_id, long fs_type,
			long block_size, long block_count, long root_inum, long first_inum, 
			long last_inum){
		this.db = db;
		this.fs_id = fs_id; 
		this.img_offset = img_offset; 
		this.vol_id = vol_id; 
		this.fs_type = fs_type;
		this.block_size = block_size;
		this.block_count = block_count;
		this.root_inum = root_inum;
		this.first_inum = first_inum;
		this.last_inum = last_inum;
	}

	/**
	 * set the parent class, will be called by the parent
	 * @param parent parent volume
	 */
	protected void setParent(Volume parent){
		parentVolume = parent;
	}


	/**
	 * get the root directory if one exists
	 * @return a directory object if the root is listed in the db otherwise null
	 */
	public FsContent getRootDir() throws SQLException{
		//get the root directory. good for starting a file browser 
		FsContent dir = db.getFile(fs_id, root_inum);
		if (dir != null){
			dir.setParent(this);
		}
		return dir;
	}

	/**
	 * gets a list of files and directories in the root of this file system
	 * @return an arraylist of files and directories in the root directory
	 */
	public ArrayList<FsContent> getRootFiles() throws SQLException{
		//getfiles in root directory
		ArrayList<Long> childIds = db.getChildIds(root_inum, fs_id);
		ArrayList<FsContent> content = new ArrayList<FsContent>();

		for(Long id : childIds){
			FsContent newContent = db.getFile(fs_id, id);
			if(!newContent.getName().equals(".")&&!newContent.getName().equals("..")){
				newContent.setParent(this);
				content.add(newContent);
			}
		}
		return content;
	}

	/**
	 * gets a directory with the given inum
	 * @param INUM directory's id
	 * @return a directory or null if it doesn't exist
	 */
	public FsContent getDirectory(long INUM) throws SQLException{
		//get the directory at the given inum, will need to use commandline tools
		//if file id is the same as inum then can use database
		FsContent dir = db.getFile(fs_id, INUM);
		if(dir != null){
			dir.setParent(this);
		}
		return dir;
	}

	/**
	 * read data from the filesystem
	 * @param offset offset in bytes from the start of the filesystem
	 * @param len how many bytes to read
	 * @return the bytes
	 * @throws TskException
	 */
	public byte[] read(long offset, long len) throws TskException{
		// read from the file system
		if(filesystemHandle == 0){
			filesystemHandle = SleuthkitJNI.openFs(this.getParent().getParent().getParent().getImageHandle(), img_offset);
		}
		return SleuthkitJNI.readFs(filesystemHandle, offset, len);
	}

	/**
	 * get the parent volume
	 * @return volume object
	 */
	public Volume getParent(){
		return parentVolume;
	}

	/**
	 * get the size of the filesystem
	 * @return size of the filesystem
	 */
	public long getSize() {
		// size of the file system
		return block_size * block_count;
	}

	/**
	 * lazily loads the filesystem pointer ie: won't be loaded until this is called
	 * @return a filesystem pointer from the sleuthkit
	 */
	public long getFileSystemHandle() throws TskException{
		if (filesystemHandle == 0){
			filesystemHandle = SleuthkitJNI.openFs(this.getParent().getParent().getParent().getImageHandle(), img_offset);
		}
		return this.filesystemHandle;
	}

	//methods get exact data from database. could be manipulated to get more
	//meaningful data.
	/**
	 * get the file system id
	 * @return fs id
	 */
	public long getFs_id() {
		return fs_id;
	}	
	/**
	 * get the byte offset of this filesystem in the image
	 * @return offset
	 */
	public long getImg_offset() {
		return img_offset;
	}	 	
	/**
	 * get the volume id
	 * @return id
	 */
	public long getVol_id() {
		return vol_id;
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
	 * @return
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

	public void finalize(){
		if(filesystemHandle != 0){
			SleuthkitJNI.closeFs(filesystemHandle);
		}
	}
}
