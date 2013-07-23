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
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.io.File;

/**
 * Represents a disk image file, stored in tsk_image_info. Populated based on
 * data in database.
 *
 * Caches internal tsk image handle and reuses it for reads
 */
public class Image extends AbstractContent {
	//data about image

	private long type, ssize, size;
	private String[] paths;
	private volatile long imageHandle = 0;
	private String timezone;

	/**
	 * constructor most inputs are from the database
	 *
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
		this.size = 0;
	}

	/**
	 * Get the handle to the sleuthkit image info object
	 *
	 * @return the object pointer
	 */
	public synchronized long getImageHandle() throws TskCoreException {
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
	public void close() {
		//frees nothing, as we are caching image handles
	}

	
	
	@Override
	public void finalize() throws Throwable {
		try {
			if (imageHandle != 0) {
				SleuthkitJNI.closeImg(imageHandle);
				imageHandle = 0;
			}
		} finally {
			super.finalize();
		}
	}

	@Override
	public int read(byte[] buf, long offset, long len) throws TskCoreException {
		// read from the image
		return SleuthkitJNI.readImg(getImageHandle(), buf, offset, len);
	}

	@Override
	public long getSize() {
		if (size == 0) {
			try {
				if (paths.length > 0) {
					//should always had at least one path 
					size = SleuthkitJNI.findDeviceSize(paths[0]);
				}
			} catch (TskCoreException ex) {
				Logger.getLogger(Image.class.getName()).log(Level.SEVERE, "Could not find image size, image: " + this.getId(), ex);
			}
		}
		return size;
	}

	//Methods for retrieval of meta-data attributes
	/**
	 * Get the image type
	 *
	 * @return image type
	 */
	public long getType() {
		return type;
	}

	/**
	 * Get the sector size
	 *
	 * @return sector size
	 */
	public long getSsize() {
		return ssize;
	}

	@Override
	public String getUniquePath() throws TskCoreException {
		return "/img_" + getName();
	}

	/**
	 * Get the image path
	 *
	 * @return image path
	 */
	public String[] getPaths() {
		return paths;
	}

	/**
	 * @return a list of VolumeSystem associated with this Image.
	 * @throws TskCoreException
	 */
	public List<VolumeSystem> getVolumeSystems() throws TskCoreException {

		List<Content> children = getChildren();
		List<VolumeSystem> vs = new ArrayList<VolumeSystem>();
		for (Content child : children) {
			if (child instanceof VolumeSystem) {
				vs.add((VolumeSystem) child);
			}
		}

		return vs;
	}

	/**
	 * @return a list of Volume associated with this Image.
	 * @throws TskCoreException
	 */
	public List<Volume> getVolumes() throws TskCoreException {

		List<Content> children = getChildren();
		List<Volume> volumes = new ArrayList<Volume>();
		for (Content child : children) {
			if (child instanceof Volume) {
				volumes.add((Volume) child);
			}
		}

		return volumes;
	}

	/**
	 * @return a list of FileSystems in this Image. This includes FileSystems
	 * that are both children of this Image as well as children of Volumes in
	 * this image.
	 * @throws TskCoreException
	 */
	public List<FileSystem> getFileSystems() throws TskCoreException {
		List<FileSystem> fs = new ArrayList<FileSystem>();
		fs.addAll(getSleuthkitCase().getFileSystems(this));
		return fs;
	}

	/**
	 * Get the timezone set for the image
	 *
	 * @return timezone string representation
	 */
	public String getTimeZone() {
		return timezone;
	}

	// ----- Methods for Image Type conversion / mapping -----
	/**
	 * Convert image type id to string value
	 *
	 * @param imageType to convert
	 * @return string representation of the image type
	 */
	public static String imageTypeToValue(long imageType) {

		String result = "";

		for (TskData.TSK_IMG_TYPE_ENUM imgType : TskData.TSK_IMG_TYPE_ENUM.values()) {
			if (imgType.getImageType() == imageType) {
				result = imgType.toString();
			}
		}
		return result;
	}

	/**
	 * Convert image type value string to image type id
	 *
	 * @param imageType value string to convert
	 * @return image type id
	 */
	public static long valueToImageType(String imageType) {

		long result = 0;

		for (TskData.TSK_IMG_TYPE_ENUM imgType : TskData.TSK_IMG_TYPE_ENUM.values()) {
			if (imgType.toString().equals(imageType)) {
				result = imgType.getImageType();
			}
		}
		return result;
	}

	/**
	 * Convert image type id to string representation
	 *
	 * @param imageType to convert
	 * @return user-readable string representation of the image type
	 */
	public static String imageTypeToString(long imageType) {

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

		if (imageType == detect) {
			result = "Auto Detection";
		}
		if (imageType == raw) {
			result = "Single raw file (dd)";
		}
		if (imageType == split) {
			result = "Split raw files";
		}
		if (imageType == aff) {
			result = "Advanced Forensic Format";
		}
		if (imageType == afd) {
			result = "AFF Multiple File";
		}
		if (imageType == afm) {
			result = "AFF with external metadata";
		}
		if (imageType == afflib) {
			result = "All AFFLIB image formats (including beta ones)";
		}
		if (imageType == ewf) {
			result = "Expert Witness format (encase)";
		}
		if (imageType == unsupported) {
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

	@Override
	public List<Long> getChildrenIds() throws TskCoreException {
		return getSleuthkitCase().getImageChildrenIds(this);
	}
	@Override
	public String toString(boolean preserveState){
		return super.toString(preserveState) + "Image [\t" + "\t" + "paths " + Arrays.toString(paths) + "\t" + "size " + size + "\t" + "ssize " + ssize + "\t" + "timezone " + timezone + "\t" + "type " + type + "]\t";
	}
	
	public Boolean imageFileExists() {
		if (paths.length > 0) {
			File imageFile = new File(paths[0]);
			return imageFile.exists();
		}
		
		return false;
	}
}
