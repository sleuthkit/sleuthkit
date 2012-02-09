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
import java.util.List;

/**
 * Represents a volume in a VolumeSystem.
 * Populated based on data in database.
 */
public class Volume extends FileSystemParent {
	// @@@ We should mark these as private and comment somewhere what the units are (bytes, sectors, etc.)
	long addr, start, length, flags;
	String desc;
	private VolumeSystem parentVs;
	private long volumeHandle = 0;

	/**
	 * Constructor most inputs are from the database
	 * @param db database object
	 * @param obj_id 
	 * @param addr
	 * @param start
	 * @param length
	 * @param flags
	 * @param desc  
	 */
	protected Volume(SleuthkitCase db, long obj_id, long addr, long start, long length, long flags, String desc){
		super(db, obj_id);
		this.addr = addr;
		this.start = start;
		this.length = length;
		this.flags = flags;
		if(!desc.equals("")){
			this.desc = desc;
		}
		else{
			this.desc = "Unknown";
		}
	}

	/**
	 * set the parent volume system. called by the parent on creation
	 * @param parent parent volume system
	 */
	protected void setParent(VolumeSystem parent){
		parentVs = parent;
	}


	/**
	 * read from this volume
	 * @param offset in bytes
	 * @param len in bytes
	 * @return the byte data
	 * @throws TskException
	 */
	@Override
	public byte[] read(long offset, long len) throws TskException {
		// read from the volume
		if(volumeHandle == 0){
			volumeHandle = SleuthkitJNI.openVsPart(parentVs.getVolumeSystemHandle(), addr);
		}
		return SleuthkitJNI.readVsPart(volumeHandle, offset, len);
	}

	@Override
	public long getSize() {
		// size of the volume
		return length;
	}

	/**
	 * get the parent volume system
	 * @return parent volume system object
	 */
	public VolumeSystem getParent(){
		return parentVs;
	}

	//methods get exact data from database. could be manipulated to get more
	//meaningful data.

	
	
	/**
	 * get the partition address
	 * @return partition address in volume system
	 */
	public long getAddr() {
		return addr;
	}
	/**
	 * get the starting byte offset
	 * @return starting byte offset
	 */
	public long getStart() {
		return start;
	}
	/**
	 * get the length
	 * @return length
	 */
	public long getLength() {
		return length;
	}
	/**
	 * get the flags
	 * @return flags
	 */
	public long getFlags() {
		return flags;
	}
	/**
	 * get the flags as String
	 * @return flags as String
	 */
	public String getFlagsAsString() {
		return Volume.vsFlagToString(flags);
	}

	/**
	 * get the description
	 * @return description
	 */
	public String getDescription(){
		return desc;
	}

	// ----- Here all the methods for vs flags conversion / mapping -----
	public static String vsFlagToValue(long vsFlag){

		String result = "";

		for (TskData.TSK_VS_PART_FLAG_ENUM flag : TskData.TSK_VS_PART_FLAG_ENUM.values()){
			if(flag.getVsFlag() == vsFlag){
				result = flag.toString();
			}
		}
		return result;
	}

	public static long valueToVsFlag(String vsFlag){

		long result = 0;

		for (TskData.TSK_VS_PART_FLAG_ENUM flag : TskData.TSK_VS_PART_FLAG_ENUM.values()){
			if(flag.toString().equals(vsFlag)){
				result = flag.getVsFlag();
			}
		}
		return result;
	}

	public static String vsFlagToString(long vsFlag){

		String result = "";

		long allocFlag = TskData.TSK_VS_PART_FLAG_ENUM.TSK_VS_PART_FLAG_ALLOC.getVsFlag();
		long unallocFlag = TskData.TSK_VS_PART_FLAG_ENUM.TSK_VS_PART_FLAG_UNALLOC.getVsFlag();

		// some variables that might be needed in the future
		long metaFlag = TskData.TSK_VS_PART_FLAG_ENUM.TSK_VS_PART_FLAG_META.getVsFlag();
		long allFlag = TskData.TSK_VS_PART_FLAG_ENUM.TSK_VS_PART_FLAG_ALL.getVsFlag();

		if((vsFlag & allocFlag) == allocFlag){
			result = "Allocated";
		}
		if((vsFlag & unallocFlag) == unallocFlag){
			result = "Unallocated";
		}
		// ... add more code here if needed

		return result;
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
			return db.getVolumeChildren(this);
		} catch (SQLException ex) {
			throw new TskException("Error while getting Volume children.", ex);
		}
	}

	@Override
	public long getImageHandle() throws TskException {
		return getParent().getParent().getImageHandle();
	}

	@Override
	public boolean isOnto() {
		return true;
	}
}
