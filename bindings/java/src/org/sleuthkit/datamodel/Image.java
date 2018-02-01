/*
 * Autopsy Forensic Browser
 *
 * Copyright 2011-2018 Basis Technology Corp.
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

import java.text.MessageFormat;
import java.util.ResourceBundle;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.io.File;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Represents a disk image file, stored in tsk_image_info. Populated based on
 * data in database.
 *
 * Caches internal tsk image handle and reuses it for reads
 */
public class Image extends AbstractContent implements DataSource {
	//data about image

	private final long type, ssize;
	private long size;
	private final String[] paths;
	private volatile long imageHandle = 0;
	private final String deviceId, timezone, md5;
	private static ResourceBundle bundle = ResourceBundle.getBundle("org.sleuthkit.datamodel.Bundle");

	private static final Logger LOGGER = Logger.getLogger(Image.class.getName());

	/**
	 * Create a disk image.
	 *
	 * Note: Most inputs originate from the database.
	 *
	 * @param db       Case database.
	 * @param obj_id   Object ID.
	 * @param type     Image type.
	 * @param ssize    Sector size.
	 * @param name     Display name.
	 * @param paths    Image paths.
	 * @param timezone Timezone.
	 * @param md5      MD5 hash.
	 *
	 * @throws TskCoreException
	 *
	 * @deprecated Use the constructor that takes a device ID and size.
	 */
	@Deprecated
	protected Image(SleuthkitCase db, long obj_id, long type, long ssize, String name, String[] paths, String timezone, String md5) throws TskCoreException {
		super(db, obj_id, name);
		this.deviceId = "";
		this.type = type;
		this.ssize = ssize;
		this.paths = paths;
		this.timezone = timezone;
		this.size = 0;
		this.md5 = md5;
	}

	/**
	 * Create a disk image.
	 *
	 * Note: Most inputs originate from the database.
	 *
	 * @param db       Case database.
	 * @param obj_id   Object ID.
	 * @param type     Image type.
	 * @param deviceId Device ID.
	 * @param ssize    Sector size.
	 * @param name     Display name.
	 * @param paths    Image paths.
	 * @param timezone Timezone.
	 * @param md5      MD5 hash.
	 * @param size     Size.
	 */
	Image(SleuthkitCase db, long obj_id, long type, String deviceId, long ssize, String name, String[] paths, String timezone, String md5, long size) throws TskCoreException {
		super(db, obj_id, name);
		this.deviceId = deviceId;
		this.type = type;
		this.ssize = ssize;
		this.paths = paths;
		this.timezone = timezone;
		this.size = size;
		this.md5 = md5;
	}

	/**
	 * Get the handle to the sleuthkit image info object
	 *
	 * @return the object pointer
	 *
	 * @throws TskCoreException
	 */
	public synchronized long getImageHandle() throws TskCoreException {
		if (imageHandle == 0) {
			imageHandle = SleuthkitJNI.openImage(paths, (int)ssize);
		}

		return imageHandle;
	}

	@Override
	public Content getDataSource() {
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
				Logger.getLogger(Image.class.getName()).log(Level.SEVERE, "Could not find image size, image: " + this.getId(), ex); //NON-NLS
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
		return "/img_" + getName(); //NON-NLS
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
	 *
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
	 *
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
	 *         that are both children of this Image as well as children of
	 *         Volumes in this image.
	 *
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
	@Override
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
	public String toString(boolean preserveState) {
		return super.toString(preserveState) + "Image [\t" + "\t" + "paths " + Arrays.toString(paths) + "\t" + "size " + size + "\t" + "ssize " + ssize + "\t" + "timezone " + timezone + "\t" + "type " + type + "]\t"; //NON-NLS
	}

	/**
	 * Test if the file that created this image exists on disk. Does not work on
	 * local disks - will always return false
	 *
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
	 * @return String of error messages to display to user or empty string if
	 *         there are no errors
	 */
	public String verifyImageSize() {
		Logger logger1 = Logger.getLogger("verifyImageSizes"); //NON-NLS
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
							logger1.log(Level.WARNING, "Possible Incomplete Image: Error reading volume at offset {0}", endOffset); //NON-NLS
							errorString = MessageFormat.format(bundle.getString("Image.verifyImageSize.errStr1.text"), endOffset);
						}
					} catch (TskCoreException ex) {
						logger1.log(Level.WARNING, "Possible Incomplete Image: Error reading volume at offset {0}: {1}", new Object[]{endOffset, ex.getLocalizedMessage()}); //NON-NLS
						errorString = MessageFormat.format(bundle.getString("Image.verifyImageSize.errStr2.text"), endOffset);
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
						logger1.log(Level.WARNING, "Possible Incomplete Image: Error reading file system at offset {0}", endOffset); //NON-NLS
						errorString = MessageFormat.format(bundle.getString("Image.verifyImageSize.errStr3.text"), endOffset);
					}
				} catch (TskCoreException ex) {
					logger1.log(Level.WARNING, "Possible Incomplete Image: Error reading file system at offset {0}: {1}", new Object[]{endOffset, ex.getLocalizedMessage()}); //NON-NLS
					errorString = MessageFormat.format(bundle.getString("Image.verifyImageSize.errStr4.text"), endOffset);
				}
			}
		} catch (TskException ex) {
			// do nothing if we got an exception from trying to get file systems and volume systems
		}
		return errorString;
	}

	/**
	 * gets the md5 hash value
	 *
	 * @return md5 hash if attained(from database). returns null if not set.
	 */
	public String getMd5() {
		return md5;
	}

	/**
	 * Gets the ASCII-printable identifier for the device associated with the
	 * data source. This identifier is intended to be unique across multiple
	 * cases (e.g., a UUID).
	 *
	 * @return The device id.
	 */
	@Override
	public String getDeviceId() {
		return deviceId;
	}

	/**
	 * Gets the size of the contents of the data source in bytes. This size can
	 * change as archive files within the data source are expanded, files are
	 * carved, etc., and is different from the size of the data source as
	 * returned by Content.getSize, which is the size of the data source as a
	 * file.
	 *
	 * @param sleuthkitCase The sleuthkit case instance from which to make calls
	 *                      to the database.
	 *
	 * @return The size in bytes.
	 *
	 * @throws TskCoreException Thrown when there is an issue trying to retrieve
	 *                          data from the database.
	 */
	@Override
	public long getContentSize(SleuthkitCase sleuthkitCase) throws TskCoreException {
		SleuthkitCase.CaseDbConnection connection;
		Statement statement = null;
		ResultSet resultSet = null;
		long contentSize = 0;

		connection = sleuthkitCase.getConnection();

		try {
			statement = connection.createStatement();
			resultSet = connection.executeQuery(statement, "SELECT SUM (size) FROM tsk_image_info WHERE tsk_image_info.obj_id = " + getId());
			if (resultSet.next()) {
				contentSize = resultSet.getLong("sum");
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("There was a problem while querying the database for size data for object ID %d.", getId()), ex);
		} finally {
			closeResultSet(resultSet);
			closeStatement(statement);
			connection.close();
		}

		return contentSize;
	}

	/**
	 * Close a ResultSet.
	 *
	 * @param resultSet The ResultSet to be closed.
	 */
	private static void closeResultSet(ResultSet resultSet) {
		if (resultSet != null) {
			try {
				resultSet.close();
			} catch (SQLException ex) {
				LOGGER.log(Level.SEVERE, "Error closing ResultSet", ex); //NON-NLS
			}
		}
	}

	/**
	 * Close a Statement.
	 *
	 * @param statement The Statement to be closed.
	 */
	private static void closeStatement(Statement statement) {
		if (statement != null) {
			try {
				statement.close();
			} catch (SQLException ex) {
				LOGGER.log(Level.SEVERE, "Error closing Statement", ex); //NON-NLS
			}
		}
	}
}
