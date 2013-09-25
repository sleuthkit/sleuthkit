/*
 * Autopsy Forensic Browser
 * 
 * Copyright 2011-2013 Basis Technology Corp.
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
	public TskData.TSK_IMG_TYPE_ENUM getType() {
		return TskData.TSK_IMG_TYPE_ENUM.valueOf(type);
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
	
	/**
	 * Test if the image represented by this object exists on disk. 
	 * @return True if the file still exists
	 */
	public Boolean imageFileExists() {
		if (paths.length > 0) {
			File imageFile = new File(paths[0]);
			return imageFile.exists();
		}
		
		return false;
	}
	
	/**
     * Perform some sanity checks on the bounds of the image contents to 
     * determine if we could be missing some pieces of the image. 
     * 
     * @returns String of error messages to display to user or empty string if there are no errors 
     */
    public String verifyImageSize() {
        Logger logger1 = Logger.getLogger("verifyImageSizes");
        String errorString = "";
        try {
            List<VolumeSystem> volumeSystems = getVolumeSystems();
            for (VolumeSystem vs : volumeSystems) {
                List<Volume> volumes = vs.getVolumes();
                for (Volume v : volumes) {
                    byte[] buf = new byte[512];
                    long endOffset = (v.getStart() + v.getLength()) * 512 - 512;
                    try {
                        int readBytes = read(buf, endOffset, 512);
                        if (readBytes < 0) {
                            logger1.warning("Possible Incomplete Image: Error reading volume at offset " + endOffset);
                            errorString = "\nPossible Incomplete Image: Error reading volume at offset " + endOffset;
                        }
                    } catch (TskCoreException ex) {
                        logger1.warning("Possible Incomplete Image: Error reading volume at offset " + endOffset + ": " + ex.getLocalizedMessage());
                        errorString = "\nPossible Incomplete Image: Error reading volume at offset " + endOffset;
                    }
                }
            }
            
            List<FileSystem> fileSystems = getFileSystems();
            for (FileSystem fs : fileSystems) {
                long block_size = fs.getBlock_size();
                long endOffset = fs.getImageOffset() + fs.getSize() - block_size;
                try {
                    byte[] buf = new byte[(int) block_size];
                    int readBytes = read(buf, endOffset, block_size);
                    if (readBytes < 0) {
                        logger1.warning("Possible Incomplete Image: Error reading file system at offset " + endOffset);
                        errorString = "\nPossible Incomplete Image: Error reading file system at offset " + endOffset;
                    }
                } catch (TskCoreException ex) {
                    logger1.warning("Possible Incomplete Image: Error reading file system at offset " + endOffset + ": " + ex.getLocalizedMessage());
                    errorString = "\nPossible Incomplete Image: Error reading file system at offset " + endOffset;
                }
            }
        } catch (TskException ex) {
            // do nothing if we got an exception from trying to get file systems and volume systems
        }
        return errorString;
    }
}
