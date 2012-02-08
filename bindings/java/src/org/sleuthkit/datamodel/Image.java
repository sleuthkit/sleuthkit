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
 * Represents a disk image file.
 * Populated based on data in database.
 */

public class Image extends FileSystemParent {
	//data about image

	private long type, ssize;
	private String name;
	private String[] paths;
	private long imageHandle = 0;
	
	/**
	 * constructor most inputs are from the database
	 * @param db database object
	 * @param obj_id 
	 * @param type
	 * @param ssize
	 * @param name
	 * @param paths  
	 */	
	
	protected Image(SleuthkitCase db, long obj_id, long type, long ssize, String name, String[] paths) throws TskException {
		super(db, obj_id);
		this.type = type;
		this.ssize = ssize;
		this.name = name;
		this.paths = paths;
	}

	/**
	 * sets a new image path (NOT CURRENTLY IMPLEMENTED)
	 * @param newPath new image path
	 */
	public void setPath(String newPath) {
		//check if path is valid/leads to an image
	}

	/**
	 * get the handle to the sleuthkit image info object
	 * @return the object pointer
	 */
	@Override
	public long getImageHandle() throws TskException {
		if (imageHandle == 0) {
			imageHandle = SleuthkitJNI.openImage(paths);
		}
		
		return imageHandle;
	}
	
	@Override
	public void finalize() throws Throwable {
		super.finalize();
		if(imageHandle != 0){
			SleuthkitJNI.closeImg(imageHandle);
		}
	}

	/**
	 * read from the image
	 * @param offset in bytes
	 * @param len in bytes
	 * @return the byte data
	 * @throws TskException
	 */
	@Override
	public byte[] read(long offset, long len) throws TskException {
		// read from the image
		return SleuthkitJNI.readImg(getImageHandle(), offset, len);
	}

	/**
	 * get the image size
	 * @return image size
	 */
	@Override
	public long getSize() {
		return 0;
	}

	//methods get exact data from database. could be manipulated to get more
	//meaningful data.
	/**
	 * get the type
	 * @return type
	 */
	public long getType() {
		return type;
	}

	/**
	 * get the sector size
	 * @return sector size
	 */
	public long getSsize() {
		return ssize;
	}

	/**
	 * get the name
	 * @return name
	 */
	public String getName() {
		return name;
	}

	/**
	 * get the path
	 * @return path
	 */
	public String[] getPaths() {
		return paths;
	}

	// ----- Here all the methods for Image Type conversion / mapping -----

	public static String imageTypeToValue(long imageType){

		String result = "";

		for (TskData.TSK_IMG_TYPE_ENUM imgType : TskData.TSK_IMG_TYPE_ENUM.values()){
			if(imgType.getImageType() == imageType){
				result = imgType.toString();
			}
		}
		return result;
	}

	public static long valueToImageType(String imageType){

		long result = 0;

		for (TskData.TSK_IMG_TYPE_ENUM imgType : TskData.TSK_IMG_TYPE_ENUM.values()){
			if(imgType.toString().equals(imageType)){
				result = imgType.getImageType();
			}
		}
		return result;
	}

	public static String imageTypeToString(long imageType){

		String result = "";

		long detect = TskData.TSK_IMG_TYPE_ENUM.TSK_IMG_TYPE_DETECT.getImageType();
		long raw = TskData.TSK_IMG_TYPE_ENUM.TSK_IMG_TYPE_RAW_SING.getImageType();
		long split = TskData.TSK_IMG_TYPE_ENUM.TSK_IMG_TYPE_RAW_SPLIT.getImageType();
		long aff = TskData.TSK_IMG_TYPE_ENUM.TSK_IMG_TYPE_AFF_AFF.getImageType();
		long afd = TskData.TSK_IMG_TYPE_ENUM.TSK_IMG_TYPE_AFF_AFD.getImageType();
		long afm = TskData.TSK_IMG_TYPE_ENUM.TSK_IMG_TYPE_AFF_AFM.getImageType();
		long afflib = TskData.TSK_IMG_TYPE_ENUM.TSK_IMG_TYPE_AFF_ANY.getImageType();
		long ewf = TskData.TSK_IMG_TYPE_ENUM.TSK_IMG_TYPE_EWF_EWF.getImageType();
		long unsupported = TskData.TSK_IMG_TYPE_ENUM.TSK_IMG_TYPE_UNSUPP.getImageType();

		if(imageType == detect){
			result = "Auto Detection";
		}
		if(imageType == raw){
			result = "Single raw file (dd)";
		}
		if(imageType == split){
			result = "Split raw files";
		}
		if(imageType == aff){
			result = "Advanced Forensic Format";
		}
		if(imageType == afd){
			result = "AFF Multiple File";
		}
		if(imageType == afm){
			result = "AFF with external metadata";
		}
		if(imageType == afflib){
			result = "All AFFLIB image formats (including beta ones)";
		}
		if(imageType == ewf){
			result = "Expert Witness format (encase)";
		}
		if(imageType == unsupported){
			result = "Unsupported Image Type";
		}

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
			return db.getImageChildren(this);
		} catch (SQLException ex) {
			throw new TskException("Error getting Image children.", ex);
		}
	}

	@Override
	public boolean isOnto() {
		return true;
	}
}
