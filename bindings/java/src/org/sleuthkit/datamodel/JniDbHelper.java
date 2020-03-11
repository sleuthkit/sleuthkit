/*
 * Autopsy Forensic Browser
 *
 * Copyright 2020 Basis Technology Corp.
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

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbTransaction;

/**
 * This is a utility class to allow the native C code to write to the 
 * case database. All callbacks from the native code should come through this class.
 * Any changes to the method signatures in this class will require changes to the 
 * native code.
 */
class JniDbHelper {
	
	private static final Logger logger = Logger.getLogger(JniDbHelper.class.getName());
	
	private final SleuthkitCase caseDb;
	private CaseDbTransaction trans = null;
	
	private final Map<Long, Long> fsIdToRootDir = new HashMap<>();
	
	JniDbHelper(SleuthkitCase caseDb) {
		this.caseDb = caseDb;
		trans = null;
	}
	
	/**
	 * Start the add image transaction
	 * 
	 * @throws TskCoreException 
	 */
	void beginTransaction() throws TskCoreException {
		trans = caseDb.beginTransaction();
	}
	
	/**
	 * Commit the add image transaction
	 * 
	 * @throws TskCoreException 
	 */
	void commitTransaction() throws TskCoreException {
		trans.commit();
		trans = null;
	}
	
	/**
	 * Revert the add image transaction
	 * 
	 * @throws TskCoreException 
	 */
	void revertTransaction() throws TskCoreException {
		trans.rollback();
		trans = null;
	}		
	
	/**
	 * Add a new image to the database.
	 * Intended to be called from the native code during the add image process.
	 * 
	 * @param type
	 * @param ssize
	 * @param timezone
	 * @param size
	 * @param md5
	 * @param sha1
	 * @param sha256
	 * @param deviceId
	 * @param collectionDetails
	 * 
	 * @return The object ID of the new image or -1 if an error occurred
	 */
	long addImageInfo(int type, long ssize, String timezone, 
			long size, String md5, String sha1, String sha256, String deviceId, 
			String collectionDetails) {
		try {
			return caseDb.addImageJNI(TskData.TSK_IMG_TYPE_ENUM.valueOf(type), ssize, size,
					timezone, md5, sha1, sha256, deviceId, trans);
		} catch (TskCoreException ex) {
			logger.log(Level.SEVERE, "Error adding image to the database", ex);
			return -1;
		}
	}
	
	/**
	 * Add an image name to the database. 
	 * Intended to be called from the native code during the add image process.
	 * 
	 * @param objId
	 * @param name
	 * @param sequence
	 * 
	 * @return 0 if successful, -1 if not
	 */
	int addImageName(long objId, String name, long sequence) {
		try {
			caseDb.addImageNameJNI(objId, name, sequence, trans);
			return 0;
		} catch (TskCoreException ex) {
			logger.log(Level.SEVERE, "Error adding image name to the database - image obj ID: " + objId + ", image name: " + name
					+ ", sequence: " + sequence, ex);
			return -1;
		}
	}
	
	/**
	 * Add a volume system to the database. 
	 * Intended to be called from the native code during the add image process.
	 * 
	 * @param parentObjId
	 * @param vsType
	 * @param imgOffset
	 * @param blockSize
	 * 
	 * @return The object ID of the new volume system or -1 if an error occurred
	 */
	long addVsInfo(long parentObjId, int vsType, long imgOffset, long blockSize) {
		try {
			VolumeSystem vs = caseDb.addVolumeSystem(parentObjId, TskData.TSK_VS_TYPE_ENUM.valueOf(vsType), imgOffset, blockSize, trans);
			return vs.getId();
		} catch (TskCoreException ex) {
			logger.log(Level.SEVERE, "Error adding volume system to the database - parent obj ID: " + parentObjId 
					+ ", image offset: " + imgOffset, ex);
			return -1;
		}
	}
	
	/**
	 * Add a volume to the database. 
	 * Intended to be called from the native code during the add image process.
	 * 
	 * @param parentObjId
	 * @param addr
	 * @param start
	 * @param length
	 * @param desc
	 * @param flags
	 * 
	 * @return The object ID of the new volume or -1 if an error occurred
	 */
	long addVolume(long parentObjId, long addr, long start, long length, String desc,
			long flags) {
		try {
			Volume vol = caseDb.addVolume(parentObjId, addr, start, length, desc, flags, trans);
			return vol.getId();
		} catch (TskCoreException ex) {
			logger.log(Level.SEVERE, "Error adding volume to the database - parent object ID: " + parentObjId
				+ ", addr: " + addr, ex);
			return -1;
		}
	}

	/**
	 * Add a pool to the database. 
	 * Intended to be called from the native code during the add image process.
	 * 
	 * @param parentObjId
	 * @param poolType
	 * 
	 * @return The object ID of the new pool or -1 if an error occurred
	 */
	long addPool(long parentObjId, int poolType) {
		try {
			Pool pool = caseDb.addPool(parentObjId, TskData.TSK_POOL_TYPE_ENUM.valueOf(poolType), trans);
			return pool.getId();
		} catch (TskCoreException ex) {
			logger.log(Level.SEVERE, "Error adding pool to the database - parent object ID: " + parentObjId, ex);
			return -1;
		}
	}

	/**
	 * Add a file system to the database. 
	 * Intended to be called from the native code during the add image process.
	 * 
	 * @param parentObjId
	 * @param imgOffset
	 * @param fsType
	 * @param blockSize
	 * @param blockCount
	 * @param rootInum
	 * @param firstInum
	 * @param lastInum
	 * 
	 * @return The object ID of the new file system or -1 if an error occurred
	 */
	long addFileSystem(long parentObjId, long imgOffset, int fsType, long blockSize, long blockCount,
			long rootInum, long firstInum, long lastInum) {
		try {
			FileSystem fs = caseDb.addFileSystem(parentObjId, imgOffset, TskData.TSK_FS_TYPE_ENUM.valueOf(fsType), blockSize, blockCount,
					rootInum, firstInum, lastInum, null, trans);
			return fs.getId();
		} catch (TskCoreException ex) {
			logger.log(Level.SEVERE, "Error adding file system to the database - parent object ID: " + parentObjId
					+ ", offset: " + imgOffset, ex);
			return -1;
		}
	}

	/**
	 * Add a file to the database. 
	 * Intended to be called from the native code during the add image process.
	 * 
	 * @param parentObjId
	 * @param fsObjId
	 * @param dataSourceObjId
	 * @param fsType
	 * @param attrType
	 * @param attrId
	 * @param name
	 * @param metaAddr
	 * @param metaSeq
	 * @param dirType
	 * @param metaType
	 * @param dirFlags
	 * @param metaFlags
	 * @param size
	 * @param crtime
	 * @param ctime
	 * @param atime
	 * @param mtime
	 * @param meta_mode
	 * @param gid
	 * @param uid
	 * @param escaped_path
	 * @param extension
	 * 
	 * @return The object ID of the new file or -1 if an error occurred
	 */
	long addFile(long parentObjId, 
        long fsObjId, long dataSourceObjId,
        int fsType,
        int attrType, int attrId, String name,
        long metaAddr, long metaSeq,
        int dirType, int metaType, int dirFlags, int metaFlags,
        long size,
        long crtime, long ctime, long atime, long mtime,
        int meta_mode, int gid, int uid,
        String escaped_path, String extension) {
		try {
			long objId = caseDb.addFileSystemFileJNI(parentObjId, 
				fsObjId, dataSourceObjId,
				fsType,
				attrType, attrId, name,
				metaAddr, metaSeq,
				dirType, metaType, dirFlags, metaFlags,
				size,
				crtime, ctime, atime, mtime,
				meta_mode, gid, uid,
				null, TskData.FileKnown.UNKNOWN,
				escaped_path, extension, 
				false, trans);
			
			// If we're adding the root directory for the file system, cache it
			if (parentObjId == fsObjId) {
				fsIdToRootDir.put(fsObjId, objId);
			}
			return objId;
		} catch (TskCoreException ex) {
			logger.log(Level.SEVERE, "Error adding file to the database - parent object ID: " + parentObjId
					+ ", file system object ID: " + fsObjId + ", name: " + name, ex);
			return -1;
		}
	}
	
	/**
	 * Add a layout file to the database. 
	 * Intended to be called from the native code during the add image process.
	 * 
	 * @param parentObjId
	 * @param fsObjId
	 * @param dataSourceObjId
	 * @param fileType
	 * @param name
	 * @param size
	 * 
	 * @return The object ID of the new file or -1 if an error occurred
	 */
	long addLayoutFile(long parentObjId, 
        long fsObjId, long dataSourceObjId,
        int fileType,
		String name, long size) {
		try {
			// The file system may be null for layout files
			Long fsObjIdForDb = fsObjId;
			if (fsObjId == 0) {
				fsObjIdForDb = null;
			}
			
			long objId = caseDb.addFileSystemFileJNI(parentObjId, 
				fsObjIdForDb, dataSourceObjId,
				fileType,
				null, null, name,
				null, null,
				TskData.TSK_FS_NAME_TYPE_ENUM.REG.getValue(), 
				TskData.TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_REG.getValue(), 
				TskData.TSK_FS_NAME_FLAG_ENUM.UNALLOC.getValue(), 
				TskData.TSK_FS_META_FLAG_ENUM.UNALLOC.getValue(),
				size,
				null, null, null, null,
				null, null, null,
				null, TskData.FileKnown.UNKNOWN,
				null, null, 
				true, trans);
			return objId;
		} catch (TskCoreException ex) {
			logger.log(Level.SEVERE, "Error adding layout file to the database - parent object ID: " + parentObjId
					+ ", file system object ID: " + fsObjId + ", name: " + name, ex);
			return -1;
		}
	}	
	
	/**
	 * Add a layout file range to the database. 
	 * Intended to be called from the native code during the add image process.
	 * 
	 * @param objId
	 * @param byteStart
	 * @param byteLen
	 * @param seq
	 * 
	 * @return 0 if successful, -1 if not
	 */
	long addLayoutFileRange(long objId, long byteStart, long byteLen, long seq) {
		try {
			caseDb.addLayoutFileRangeJNI(objId, byteStart, byteLen, seq, trans);
			return 0;
		} catch (TskCoreException ex) {
			logger.log(Level.SEVERE, "Error adding layout file range to the database - layout file ID: " + objId 
				+ ", byte start: " + byteStart, ex);
			return -1;
		}
	}
	
	/**
	 * Look up the parent of a file based on metadata address and name/path.
	 * Intended to be called from the native code during the add image process.
	 * 
	 * @param metaAddr
	 * @param fsObjId
	 * @param path
	 * @param name
	 * 
	 * @return The object ID of the parent or -1 if not found
	 */
	long findParentObjId(long metaAddr, long fsObjId, String path, String name) {
		try {
			return caseDb.findParentObjIdJNI(metaAddr, fsObjId, path, name, trans);
		} catch (TskCoreException ex) {
			logger.log(Level.WARNING, "Error looking up parent with meta addr: " + metaAddr + " and name " + name, ex);
			return -1;
		}
	}
	
	/**
	 * Add a virtual directory to hold unallocated file system blocks.
	 * Intended to be called from the native code during the add image process.
	 * 
	 * @param fsObjId
	 * @param name
	 * 
	 * @return The object ID of the new virtual directory or -1 if an error occurred
	 */
	long addUnallocFsBlockFilesParent(long fsObjId, String name) {
		try {
			if (! fsIdToRootDir.containsKey(fsObjId)) {
				logger.log(Level.SEVERE, "Error - root directory for file system ID {0} not found", fsObjId);
				return -1;
			}
			VirtualDirectory dir = caseDb.addVirtualDirectory(fsIdToRootDir.get(fsObjId), name, trans);
			return dir.getId();
		} catch (TskCoreException ex) {
			logger.log(Level.SEVERE, "Error creating virtual directory " + name + " under file system ID " + fsObjId, ex);
			return -1;
		}
	}
}
