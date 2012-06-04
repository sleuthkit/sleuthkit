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
import org.sleuthkit.datamodel.TskData.TSK_DB_FILES_TYPE_ENUM;

/**
 * Represents a disk image file.
 * Populated based on data in database.
 */
public class Image extends AbstractContent{
	//data about image

	private long type, ssize;
	private String[] paths;
	private long imageHandle = 0;
	private String timezone;
	
	/**
	 * constructor most inputs are from the database
	 * @param db database object
	 * @param obj_id 
	 * @param type
	 * @param ssize
	 * @param name
	 * @param paths 
	 * @param timezone 
	 */	
	
	protected Image(SleuthkitCase db, long obj_id, long type, long ssize, String name, String[] paths, String timezone) throws TskCoreException {
		super(db, obj_id, name);
		this.type = type;
		this.ssize = ssize;
		this.paths = paths;
		this.timezone = timezone;
	}
	
	/**
	 * get the handle to the sleuthkit image info object
	 * @return the object pointer
	 */
	public long getImageHandle() throws TskCoreException {
		if (imageHandle == 0) {
			imageHandle = SleuthkitJNI.openImage(paths);
	}

		return imageHandle;
	}
	
	@Override
	public Image getImage() {
		return this;
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
	 * @param buf the buffer to read to
	 * @param offset in bytes
	 * @param len in bytes
	 * @return number of bytes read, -1 if error
	 * @throws TskException
	 */
	@Override
	public int read(byte[] buf, long offset, long len) throws TskCoreException {
		// read from the image
		return SleuthkitJNI.readImg(getImageHandle(), buf, offset, len);
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
	 * get the path
	 * @return path
	 */
	public String[] getPaths() {
		return paths;
	}

	/**
	 * get the timezone
	 * @return 
	 */
	public String getTimeZone() {
		return timezone;
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
	public List<Content> getChildren() throws TskCoreException {
		return getSleuthkitCase().getImageChildren(this);
	}
	
}
