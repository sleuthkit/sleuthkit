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
import java.util.ArrayList;

/**
 * Volume System Object
 * @author alawrence
 */
public class VolumeSystem implements Content{
	private Sleuthkit db;
	private long volumeSystemHandle = 0;
	private long type, imgOffset, blockSize;
	private Image parent;
	private ArrayList<Long> vol_ids;

	/**
	 * Constructor most inputs are from the database
	 * @param db database object
	 * @param type
	 * @param imgOffset
	 * @param blockSize
	 * @param vol_ids
	 */
	protected VolumeSystem(Sleuthkit db, long type, long imgOffset, long blockSize, ArrayList<Long> vol_ids){
		this.db = db;
		this.type = type;
		this.imgOffset = imgOffset;
		this.blockSize = blockSize;
		this.vol_ids = vol_ids;
	}

	/**
	 * set the parent image called by parent on creation
	 * @param parent parent image
	 */
	protected void setParent(Image parent){
		this.parent = parent;
	}
	
	//byte offset
	public byte[] read(long offset, long len) throws TskException{
		if(volumeSystemHandle == 0){
			volumeSystemHandle = SleuthkitJNI.openVs(this.getParent().getImageHandle(), imgOffset);
		}
		return SleuthkitJNI.readVs(volumeSystemHandle, offset, len);
	}
	
	/**
	 * get the sleuthkit database object
	 * @return the sleuthkit object
	 */
	public Sleuthkit getSleuthkit(){
		return db;
	}

	/**
	 * get the volume in the volume system with the given id
	 * @param id volume id
	 * @return volume
	 */
	public Volume getVolume(long id) throws SQLException{
		//get given volume.
		Volume vol = db.getVolume(id);
		if (vol != null){
			vol.setParent(this);
		}
		return vol;
	}

	/**
	 * get the parent image
	 * @return parent image
	 */
	public Image getParent(){
		return parent;
	}
	/**
	 * get the size of the volume system
	 * @return the size of the volume system
	 */
	public long getSize() {
		return 0;
	}
	/**
	 * get the type
	 * @return type
	 */
	public long getType(){
		return type;
	}
	/**
	 * get the byte offset
	 * @return byte offset
	 */
	public long getOffset(){
		return imgOffset;
	}
	/**
	 * get the block size
	 * @return block size
	 */
	public long getBlockSize(){
		return blockSize;
	}
	/**
	 * get the volume system Handle pointer
	 * @return volume system Handle pointer
	 */
	protected long getVolumeSystemHandle() throws TskException{
		if (volumeSystemHandle == 0){
			volumeSystemHandle = SleuthkitJNI.openVs(this.getParent().getImageHandle(), imgOffset);
		}

		return volumeSystemHandle;
	}
	/**
	 * get the child volume ids
	 * @return child volume ids
	 */
	public ArrayList<Long> getVolIds(){
		return vol_ids;
	}

	public void finalize(){
		SleuthkitJNI.closeVs(volumeSystemHandle);
	}
}
