/*
 * Sleuth Kit Data Model
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
	private volatile Host host = null;
	private final String deviceId, timezone;
	private String md5, sha1, sha256;
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
		this.sha1 = "";
		this.sha256 = "";
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
	Image(SleuthkitCase db, long obj_id, long type, String deviceId, long ssize, String name, String[] paths, String timezone, 
			String md5, String sha1, String sha256, long size) throws TskCoreException {
		super(db, obj_id, name);
		this.deviceId = deviceId;
		this.type = type;
		this.ssize = ssize;
		this.paths = paths;
		this.timezone = timezone;
		this.size = size;
		this.md5 = md5;
		this.sha1 = sha1;
		this.sha256 = sha256;
	}

	/**
	 * Get the handle to the sleuthkit image info object
	 *
	 * @return the object pointer
	 *
	 * @throws TskCoreException
	 */
	public synchronized long getImageHandle() throws TskCoreException {
		if (paths.length == 0) {
			throw new TskCoreException("Image has no associated paths");
		}
		
		if (imageHandle == 0) {
			imageHandle = SleuthkitJNI.openImage(paths, (int)ssize, getSleuthkitCase());
		}

		return imageHandle;
	}
	
	synchronized void setImageHandle(long imageHandle) {
		this.imageHandle = imageHandle;
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
				// SleuthkitJNI.closeImg(imageHandle); // closeImg is currently a no-op
				imageHandle = 0;
			}
		} finally {
			super.finalize();
		}
	}

	@Override
	public int read(byte[] buf, long offset, long len) throws TskCoreException {
		// If there are no paths, don't attempt to read the image
		if (paths.length == 0) {
			return 0;
		}
		
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
		List<FileSystem> fs = new ArrayList<>();
		fs.addAll(getSleuthkitCase().getImageFileSystems(this));
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
	 * Gets the md5 hash value
	 *
	 * @return md5 hash if attained(from database), empty string otherwise
	 * 
	 * @throws TskCoreException
	 */
	public String getMd5() throws TskCoreException {
		if (md5 == null || md5.isEmpty()) {
			md5 = getSleuthkitCase().getMd5ImageHash(this);
		}
		return md5;
	}
	
	/**
	 * gets the SHA1 hash value
	 *
	 * @return SHA1 hash if attained(from database), empty string otherwise
	 * 
	 * @throws TskCoreException on DB error. 
	 */
	public String getSha1() throws TskCoreException {
		if (sha1 == null || sha1.isEmpty()) {
			sha1 = getSleuthkitCase().getSha1ImageHash(this);
		}
		return sha1;
	}
	
	/**
	 * gets the SHA256 hash value
	 *
	 * @return SHA256 hash if attained(from database), empty string otherwise
	 * 
	 * @throws TskCoreException
	 */
	public String getSha256() throws TskCoreException {
		if (sha256 == null || sha256.isEmpty()) {
			sha256 = getSleuthkitCase().getSha256ImageHash(this);
		}
		return sha256;
	}
	
	/**
	 * 
	 * @param md5
	 * @throws TskCoreException On DB errors
	 * @throws TskDataException If hash has already been set
	 */
	public void setMD5(String md5) throws TskCoreException, TskDataException {
		if (getMd5().isEmpty() == false) {
			throw new TskDataException("MD5 value has already been set");
		}
		getSleuthkitCase().setMd5ImageHash(this, md5);
		this.md5 = md5;
	}
	
	/**
	 * 
	 * @param sha1
	 * @throws TskCoreException On DB errors
	 * @throws TskDataException If hash has already been set
	 */
	public void setSha1(String sha1) throws TskCoreException, TskDataException {
		if (getSha1().isEmpty() == false) {
			throw new TskDataException("SHA1 value has already been set");
		}
		getSleuthkitCase().setSha1ImageHash(this, sha1);
		this.sha1 = sha1;
	}
	
	/**
	 * 
	 * @param sha256
	 * @throws TskCoreException On DB errors
	 * @throws TskDataException If hash has already been set
	 */
	public void setSha256(String sha256) throws TskCoreException, TskDataException {
		if (getSha256().isEmpty() == false) {
			throw new TskDataException("SHA256 value has already been set");
		}
		getSleuthkitCase().setSha256ImageHash(this, sha256);
		this.sha256 = sha256;
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
	 * Set the name for this data source.
	 * 
	 * @param newName       The new name for the data source
	 * 
	 * @throws TskCoreException Thrown if an error occurs while updating the database
	 */
	@Override
	public void setDisplayName(String newName) throws TskCoreException {
		this.getSleuthkitCase().setImageName(newName, getId());
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
	 * Sets the acquisition details field in the case database.
	 *
	 * @param details The acquisition details
	 * 
	 * @throws TskCoreException Thrown if the data can not be written
	 */
	@Override
	public void setAcquisitionDetails(String details) throws TskCoreException {
		getSleuthkitCase().setAcquisitionDetails(this, details);
	}

	/**
	 * Sets the acquisition tool details such as its name, version number and
	 * any settings used during the acquisition to acquire data.
	 *
	 * @param name     The name of the acquisition tool. May be NULL.
	 * @param version  The acquisition tool version number. May be NULL.
	 * @param settings The settings used by the acquisition tool. May be NULL.
	 *
	 * @throws TskCoreException Thrown if the data can not be written
	 */
	@Override
	public void setAcquisitionToolDetails(String name, String version, String settings) throws TskCoreException {
		getSleuthkitCase().setAcquisitionToolDetails(this, name, version, settings);
	}

	/**
	 * Gets the acquisition tool settings field from the case database.
	 *
	 * @return The acquisition tool settings. May be Null if not set.
	 *
	 * @throws TskCoreException Thrown if the data can not be read
	 */
	public String getAcquisitionToolSettings() throws TskCoreException {
		return getSleuthkitCase().getDataSourceInfoString(this, "acquisition_tool_settings");
	}

	/**
	 * Gets the acquisition tool name field from the case database.
	 *
	 * @return The acquisition tool name. May be Null if not set.
	 *
	 * @throws TskCoreException Thrown if the data can not be read
	 */
	public String getAcquisitionToolName() throws TskCoreException{
		return getSleuthkitCase().getDataSourceInfoString(this, "acquisition_tool_name");
	}

	/**
	 * Gets the acquisition tool version field from the case database.
	 *
	 * @return The acquisition tool version. May be Null if not set.
	 *
	 * @throws TskCoreException Thrown if the data can not be read
	 */
	public String getAcquisitionToolVersion() throws TskCoreException {
		return getSleuthkitCase().getDataSourceInfoString(this, "acquisition_tool_version");
	}

	/**
	 * Gets the added date field from the case database.
	 *
	 * @return The date time when the image was added in epoch seconds.
	 *
	 * @throws TskCoreException Thrown if the data can not be read
	 */
	public Long getDateAdded() throws TskCoreException {
		return getSleuthkitCase().getDataSourceInfoLong(this, "added_date_time");
	}

	/**
	 * Gets the acquisition details field from the case database.
	 * 
	 * @return The acquisition details
	 * 
	 * @throws TskCoreException Thrown if the data can not be read
	 */
	@Override
	public String getAcquisitionDetails() throws TskCoreException {
		return getSleuthkitCase().getAcquisitionDetails(this);
	}	
	
	/**
	 * Gets the host for this data source.
	 * 
	 * @return The host
	 * 
	 * @throws TskCoreException 
	 */
	@Override
	public Host getHost() throws TskCoreException {
		// This is a check-then-act race condition that may occasionally result
		// in additional processing but is safer than using locks.
		if (host == null) {
			host = getSleuthkitCase().getHostManager().getHostByDataSource(this);
		}
		return host;
	}	

	/**
	 * Updates the image's total size and sector size.This function may be used
	 * to update the sizes after the image was created.
	 *
	 * Can only update the sizes if they were not set before. Will throw
	 * TskCoreException if the values in the db are not 0 prior to this call.
	 *
	 * @param totalSize  The total size
	 * @param sectorSize The sector size
	 *
	 * @throws TskCoreException If there is an error updating the case database.
	 *
	 */
	public void setSizes(long totalSize, long sectorSize) throws TskCoreException {
		getSleuthkitCase().setImageSizes(this, totalSize, sectorSize);
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
