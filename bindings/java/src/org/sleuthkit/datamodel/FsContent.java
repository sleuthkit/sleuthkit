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

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.StringTokenizer;
import org.sleuthkit.datamodel.TskData.FileKnown;
import org.sleuthkit.datamodel.TskData.TSK_FS_META_FLAG_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_META_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_FLAG_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_ATTR_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_META_MODE_ENUM;

/**
 * Generalized class that stores metadata that are common to both File and
 * Directory objects stored in tsk_files table Caches internal tsk file handle
 * and reuses it for reads
 * 
 * TODO move common getters to AbstractFile class
 */
public abstract class FsContent extends AbstractFile {

	///read only database tsk_files fields
	protected final long fsObjId, metaAddr, size, ctime, crtime, atime, mtime;
	protected final int uid, gid;
	protected final short attrId;
	protected final TSK_FS_ATTR_TYPE_ENUM attrType;
	protected final TSK_FS_META_TYPE_ENUM metaType;
	protected final Set<TSK_FS_META_FLAG_ENUM> metaFlags;
	protected final Set<TSK_FS_META_MODE_ENUM> modes;
	protected final TSK_FS_NAME_TYPE_ENUM dirType;
	protected final TSK_FS_NAME_FLAG_ENUM dirFlag;
	
	/*
	 * path of parent directory
	 */
	protected final String parentPath;
	///read-write database tsk_files fields
	/**
	 * known status in database
	 */
	protected FileKnown known;
	/*
	 * md5 hash
	 */
	protected String md5Hash;
	///other members

	/**
	 * parent file system
	 */
	protected FileSystem parentFileSystem;
	/**
	 * file Handle
	 */
	protected long fileHandle = 0;

	/**
	 * Constructor to create FsContent object instance from database
	 *
	 * @param db
	 * @param obj_id
	 * @param name
	 * @param fs_obj_id
	 * @param meta_addr
	 * @param attr_type
	 * @param attr_id
	 * @param meta_type
	 * @param dir_type
	 * @param dir_flags
	 * @param meta_flags
	 * @param size
	 * @param ctime
	 * @param crtime
	 * @param atime
	 * @param mtime
	 * @param uid
	 * @param gid
	 * @param mode
	 * @param known
	 * @param parent_path
	 * @param md5Hash
	 */
	FsContent(SleuthkitCase db, long obj_id, String name, long fs_obj_id, long meta_addr,
			TSK_FS_ATTR_TYPE_ENUM attrType, short attr_id, TSK_FS_META_TYPE_ENUM metaType, TSK_FS_NAME_TYPE_ENUM dirType, TSK_FS_NAME_FLAG_ENUM dirFlag,
			short meta_flags, long size, long ctime, long crtime, long atime, long mtime, int uid, int gid, short modes, FileKnown known,
			String parent_path, String md5Hash) {
		super(db, obj_id, name, TskData.TSK_DB_FILES_TYPE_ENUM.FS);
		this.fsObjId = fs_obj_id;
		this.metaAddr = meta_addr;
		this.attrType = attrType;
		this.attrId = attr_id;
		this.metaType = metaType;
		this.dirType = dirType;
		this.dirFlag = dirFlag;
		this.metaFlags = TSK_FS_META_FLAG_ENUM.valuesOf(meta_flags);
		this.size = size;
		this.ctime = ctime;
		this.crtime = crtime;
		this.atime = atime;
		this.mtime = mtime;
		this.uid = uid;
		this.gid = gid;
		this.modes = TSK_FS_META_MODE_ENUM.valuesOf(modes);
		this.known = known;
		this.parentPath = parent_path;
		this.md5Hash = md5Hash;
	}

	/**
	 * Sets the parent file system, called by parent during object creation
	 *
	 * @param parent parent file system object
	 */
	protected void setFileSystem(FileSystem parent) {
		parentFileSystem = parent;
	}

	/**
	 * Sets md5 hash string
	 * Note: database or other FsContent objects are not updated.
	 * Currently only SleuthkiCase calls it to update the object while updating tsk_files entry
	 * 
	 * @param md5Hash 
	 */
	void setMd5Hash(String md5Hash) {
		this.md5Hash = md5Hash;
	}

	/**
	 * Sets known status
	 * Note: database or other FsContent objects are not updated.
	 * Currently only SleuthkiCase calls it to update the object while updating tsk_files entry
	 * 
	 * @param known 
	 */
	void setKnown(FileKnown known) {
		this.known = known;
	}

	@Override
	public int read(byte[] buf, long offset, long len) throws TskCoreException {
		if (offset == 0 && size == 0) {
			//special case for 0-size file
			return 0;
		}
		synchronized (this) {
			if (fileHandle == 0) {
				fileHandle = 
						SleuthkitJNI.openFile(parentFileSystem.getFileSystemHandle(), metaAddr, attrType, attrId);
			}
		}
		return SleuthkitJNI.readFile(fileHandle, buf, offset, len);
	}

	
	@Override
	public boolean isRoot() {
		return parentFileSystem.getRoot_inum() == this.getMetaAddr();
	}
		
	/*
	 * -------------------------------------------------------------------------
	 * Getters to retrieve meta-data attributes values
	 * -------------------------------------------------------------------------
	 */
	


	/**
	 * Gets parent directory
	 *
	 * @return the parent Directory
	 * @throws TskCoreException exception thrown if error occurred in tsk core
	 */
	public AbstractFile getParentDirectory() throws TskCoreException {
		return getSleuthkitCase().getParentDirectory(this);
	}

	/**
	 * Get the parent file system
	 *
	 * @return the file system object of the parent
	 */
	public FileSystem getFileSystem() {
		return parentFileSystem;
	}

	@Override
	public Image getImage() throws TskCoreException {
		return this.getFileSystem().getImage();
	}

	/**
	 * Get the attribute type
	 *
	 * @return attribute type
	 */
	public TSK_FS_ATTR_TYPE_ENUM getAttrType() {
		return attrType;
	}

	/**
	 * Get the attribute id
	 *
	 * @return attribute id
	 */
	public short getAttrId() {
		return attrId;
	}

	/**
	 * Get the meta data type
	 *
	 * @return meta data type
	 */
	public TSK_FS_META_TYPE_ENUM getMetaType() {
		return metaType;
	}

	/**
	 * Get the directory type id
	 *
	 * @return directory type id
	 */
	public TSK_FS_NAME_TYPE_ENUM getDirType() {
		return dirType;
	}

	public boolean isDirNameFlagSet(TSK_FS_NAME_FLAG_ENUM flag) {
		return dirFlag == flag;
	}

	/**
	 * Get the file meta address
	 *
	 * @return Address of the meta data structure
	 */
	public long getMetaAddr() {
		return metaAddr;
	}

	/**
	 * Get the meta data flags
	 *
	 * @return meta data flags
	 */
	public short getMetaFlagsInt() {
		return TSK_FS_META_FLAG_ENUM.toInt(metaFlags);
	}
	
	public Set<TSK_FS_META_FLAG_ENUM> getMetaFlags() {
		return Collections.unmodifiableSet(metaFlags);
	}
	
	public boolean isMetaFlagSet(TSK_FS_META_FLAG_ENUM metaFlag) {
		return metaFlags.contains(metaFlag);
	}

	@Override
	public long getSize() {
		return size;
	}

	@Override
	public List<TskFileRange> getRanges() {
		return Collections.<TskFileRange>emptyList();
	}

	/**
	 * Get the change time
	 *
	 * @return change time
	 */
	public long getCtime() {
		return ctime;
	}

	/**
	 * Get the change time as Date
	 *
	 * @return change time as Date
	 */
	public String getCtimeAsDate() {
		return FsContent.epochToTime(ctime);
	}

	/**
	 * Get the creation time
	 *
	 * @return creation time
	 */
	public long getCrtime() {
		return crtime;
	}

	/**
	 * Get the creation time as Date
	 *
	 * @return creation time as Date
	 */
	public String getCrtimeAsDate() {
		return FsContent.epochToTime(crtime);
	}

	/**
	 * Get the access time
	 *
	 * @return access time
	 */
	public long getAtime() {
		return atime;
	}

	/**
	 * Get the access time as Date
	 *
	 * @return access time as Date
	 */
	public String getAtimeAsDate() {
		return FsContent.epochToTime(atime);
	}

	/**
	 * Get the modified time
	 *
	 * @return modified time
	 */
	public long getMtime() {
		return mtime;
	}

	/**
	 * Get the modified time as Date
	 *
	 * @return modified time as Date
	 */
	public String getMtimeAsDate() {
		return FsContent.epochToTime(mtime);
	}

	/**
	 * Get the user id
	 *
	 * @return user id
	 */
	public int getUid() {
		return uid;
	}

	/**
	 * Get the group id
	 *
	 * @return group id
	 */
	public int getGid() {
		return gid;
	}
	
	public Set<TSK_FS_META_MODE_ENUM> getModes() {
		return modes;
	}

	/**
	 * Get the mode
	 *
	 * @return mode
	 */
	public short getModesInt() {
		return TSK_FS_META_MODE_ENUM.toInt(modes);
	}

	/**
	 * Get "known" file status - after running a HashDB ingest on it As marked
	 * by a known file database, such as NSRL
	 *
	 * @return file known status enum value
	 */
	public FileKnown getKnown() {
		return known;
	}

	/**
	 * Get the absolute parent path string of this FsContent
	 *
	 * @return the parent path string
	 */
	public String getParentPath() {
		return this.parentPath;
	}

	@Override
	public String getUniquePath() throws TskCoreException {
		if (uniquePath != null) {
			return uniquePath;
		}

		StringBuilder sb = new StringBuilder();
		//prepend image and volume to file path
		Image image = this.getImage();
		StringTokenizer tok = new StringTokenizer(image.getName(), "/\\");
		String imageName = null;
		while (tok.hasMoreTokens()) {
			imageName = tok.nextToken();
		}
		sb.append("/img_").append(imageName);
		if (parentFileSystem != null) {
			Content vol = parentFileSystem.getParent();
			if (vol != null
					&& !vol.equals(image)) {
				sb.append("/vol_");
				sb.append(vol.getName());
			}
		}

		sb.append(getParentPath());
		sb.append(getName());

		uniquePath = sb.toString();
		return uniquePath;
	}

	/**
	 * Get the md5 hash value as calculated, if present
	 *
	 * @return md5 hash string, if it is present
	 */
	public String getMd5Hash() {
		return this.md5Hash;
	}

	@Override
	public void finalize() {
		if (fileHandle != 0) {
			SleuthkitJNI.closeFile(fileHandle);
		}
	}

	/*
	 * -------------------------------------------------------------------------
	 * Util methods to convert / map the data
	 * -------------------------------------------------------------------------
	 */
	/**
	 * Return the epoch into string in ISO 8601 dateTime format
	 *
	 * @param epoch time in seconds
	 * @return formatted date time string as "yyyy-MM-dd HH:mm:ss"
	 */
	public static String epochToTime(long epoch) {
		String time = "0000-00-00 00:00:00";
		if (epoch != 0) {
			time = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new java.util.Date(epoch * 1000));
		}
		return time;
	}

	/**
	 * Convert from ISO 8601 formatted date time string to epoch time in seconds
	 *
	 * @param time formatted date time string as "yyyy-MM-dd HH:mm:ss"
	 * @return epoch time in seconds
	 */
	public static long timeToEpoch(String time) {
		long epoch = 0;
		try {
			epoch = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").parse(time).getTime() / 1000;
		} catch (Exception e) {
		}

		return epoch;
	}
}
