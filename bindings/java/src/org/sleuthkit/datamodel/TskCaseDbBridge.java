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

import com.google.common.base.Strings;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import org.apache.commons.lang3.StringUtils;
import java.util.List;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Queue;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.sleuthkit.datamodel.OsAccountManager.NotUserSIDException;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbTransaction;

/**
 * This is a utility class to allow the native C code to write to the 
 * case database. All callbacks from the native code should come through this class.
 * Any changes to the method signatures in this class will require changes to the 
 * native code.
 * 
 * Note that this code should only be used for the add image process, and not
 * to add additional files afterward.
 */
class TskCaseDbBridge {
    
    private static final Logger logger = Logger.getLogger(TskCaseDbBridge.class.getName());
    
    private final SleuthkitCase caseDb;
    private CaseDbTransaction trans = null;
    private final AddDataSourceCallbacks addDataSourceCallbacks;
	private final Host imageHost;
    
    private final Map<Long, Long> fsIdToRootDir = new HashMap<>();
    private final Map<Long, TskData.TSK_FS_TYPE_ENUM> fsIdToFsType = new HashMap<>();
    private final Map<ParentCacheKey, Long> parentDirCache = new HashMap<>();
    
    private final Map<String, OsAccount> ownerIdToAccountMap = new HashMap<>();
	
    private static final long BATCH_FILE_THRESHOLD = 500;
    private final Queue<FileInfo> batchedFiles = new LinkedList<>();
    private final Queue<LayoutRangeInfo> batchedLayoutRanges = new LinkedList<>();
    private final List<Long> layoutFileIds = new ArrayList<>();
    
    TskCaseDbBridge(SleuthkitCase caseDb, AddDataSourceCallbacks addDataSourceCallbacks, Host host) {
        this.caseDb = caseDb;
        this.addDataSourceCallbacks = addDataSourceCallbacks;
		imageHost = host;
        trans = null;
    }
    
    /**
     * Start a transaction
     * 
     * @throws TskCoreException 
     */
    private void beginTransaction() throws TskCoreException {
        trans = caseDb.beginTransaction();
    }
    
    /**
     * Commit the current transaction
     * 
     * @throws TskCoreException 
     */
    private void commitTransaction() throws TskCoreException {
        trans.commit();
        trans = null;
    }
    
    /**
     * Revert the current transaction
     */
    private void revertTransaction() {
        try {
            if (trans != null) {
                trans.rollback();
                trans = null;
            }
        } catch (TskCoreException ex) {
            logger.log(Level.SEVERE, "Error rolling back transaction", ex);
        }
    }        
    
    /**
     * Add any remaining files to the database.
     */
    void finish() {
        addBatchedFilesToDb();
        addBatchedLayoutRangesToDb();
        processLayoutFiles();
    }
    
    /**
     * Add a new image to the database.
     * Intended to be called from the native code during the add image process.
	 * Will not be called if the image was added to the database prior to starting
	 * the add image process.
     * 
     * @param type        Type of image.
     * @param ssize       Sector size.
     * @param timezone    Time zone.
     * @param size        Image size.
     * @param md5         MD5 hash.
     * @param sha1        SHA1 hash.
     * @param sha256      SHA256 hash.
     * @param deviceId    Device ID.
     * @param collectionDetails  The collection details.
     * @param paths       Data source path(s)
     * 
     * @return The object ID of the new image or -1 if an error occurred
     */
    long addImageInfo(int type, long ssize, String timezone, 
            long size, String md5, String sha1, String sha256, String deviceId, 
            String collectionDetails, String[] paths) {    
        try {
            beginTransaction();
            long objId = addImageToDb(TskData.TSK_IMG_TYPE_ENUM.valueOf(type), ssize, size,
                    timezone, md5, sha1, sha256, deviceId, collectionDetails, trans);
            for (int i = 0;i < paths.length;i++) {
                addImageNameToDb(objId, paths[i], i, trans);
            }
            commitTransaction();
            return objId;
        } catch (TskCoreException ex) {
            logger.log(Level.SEVERE, "Error adding image to the database", ex);
            revertTransaction();
            return -1;
        }
    }
	
	/**
	 * Add the acquisition details to the image object. 
	 * 
	 * @param imgId   ID of the image
	 * @param details The details
	 */
	void addAcquisitionDetails(long imgId, String details) {
        try {
            beginTransaction();
            caseDb.setAcquisitionDetails(imgId, details, trans);
            commitTransaction();
        } catch (TskCoreException ex) {
            logger.log(Level.SEVERE, "Error adding image details \"" + details + "\" to image with ID " + imgId, ex);
            revertTransaction();
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
            beginTransaction();
            VolumeSystem vs = caseDb.addVolumeSystem(parentObjId, TskData.TSK_VS_TYPE_ENUM.valueOf(vsType), imgOffset, blockSize, trans);
            commitTransaction();
            return vs.getId();
        } catch (TskCoreException ex) {
            logger.log(Level.SEVERE, "Error adding volume system to the database - parent obj ID: " + parentObjId 
                    + ", image offset: " + imgOffset, ex);
            revertTransaction();
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
            beginTransaction();
            Volume vol = caseDb.addVolume(parentObjId, addr, start, length, desc, flags, trans);
            commitTransaction();
            return vol.getId();
        } catch (TskCoreException ex) {
            logger.log(Level.SEVERE, "Error adding volume to the database - parent object ID: " + parentObjId
                + ", addr: " + addr, ex);
            revertTransaction();
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
            beginTransaction();
            Pool pool = caseDb.addPool(parentObjId, TskData.TSK_POOL_TYPE_ENUM.valueOf(poolType), trans);
            commitTransaction();
            return pool.getId();
        } catch (TskCoreException ex) {
            logger.log(Level.SEVERE, "Error adding pool to the database - parent object ID: " + parentObjId, ex);
            revertTransaction();
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
            beginTransaction();
            FileSystem fs = caseDb.addFileSystem(parentObjId, imgOffset, TskData.TSK_FS_TYPE_ENUM.valueOf(fsType), blockSize, blockCount,
                    rootInum, firstInum, lastInum, null, trans);
            commitTransaction();
            fsIdToFsType.put(fs.getId(), TskData.TSK_FS_TYPE_ENUM.valueOf(fsType));
            return fs.getId();
        } catch (TskCoreException ex) {
            logger.log(Level.SEVERE, "Error adding file system to the database - parent object ID: " + parentObjId
                    + ", offset: " + imgOffset, ex);
            revertTransaction();
            return -1;
        }
    }

    /**
     * Add a file to the database.
     * File inserts are batched so the file may not be added immediately.
     * Intended to be called from the native code during the add image process.
     * 
     * @param parentObjId     The parent of the file if known or 0 if unknown.
     * @param fsObjId         The object ID of the file system.
     * @param dataSourceObjId The data source object ID.
     * @param fsType    The type.
     * @param attrType  The type attribute given to the file by the file system.
     * @param attrId    The type id given to the file by the file  system.
     * @param name      The name of the file.
     * @param metaAddr  The meta address of the file.
     * @param metaSeq   The meta sequence number of the file from fs_file->name->meta_seq.
     * @param dirType   The type of the file, usually as reported in
     *                     the name structure of the file system. 
     * @param metaType  The type of the file, usually as reported in
     *                     the metadata structure of the file system.
     * @param dirFlags  The allocated status of the file, usually as
     *                     reported in the name structure of the file system.
     * @param metaFlags The allocated status of the file, usually as
     *                     reported in the metadata structure of the file system.
     * @param size      The file size.
     * @param crtime    The created time.
     * @param ctime     The last changed time
     * @param atime     The last accessed time.
     * @param mtime     The last modified time.
     * @param meta_mode The modes for the file.
     * @param gid       The group identifier.
     * @param uid       The user identifier.
     * @param md5       The MD5 hash.
     * @param known     The file known status.
     * @param escaped_path The escaped path to the file.
     * @param extension    The file extension.
     * @param seq         The sequence number from fs_file->meta->seq. 
     * @param parMetaAddr The metadata address of the parent
     * @param parSeq      The parent sequence number if NTFS, -1 otherwise.
	 * @param ownerUid	  String uid of the file owner.  May be an empty string.
     * 
     * @return 0 if successful, -1 if not
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
        String escaped_path, String extension, 
        long seq, long parMetaAddr, long parSeq, String ownerUid) {
        
        // Add the new file to the list
        batchedFiles.add(new FileInfo(parentObjId,
                fsObjId, dataSourceObjId,
                fsType,
                attrType, attrId, name,
                metaAddr, metaSeq,
                dirType, metaType, dirFlags, metaFlags,
                size,
                crtime, ctime, atime, mtime,
                meta_mode, gid, uid,
                escaped_path, extension,
                seq, parMetaAddr, parSeq, ownerUid));
        
        // Add the current files to the database if we've exceeded the threshold or if we
        // have the root folder.
        if ((fsObjId == parentObjId)
                || (batchedFiles.size() > BATCH_FILE_THRESHOLD)) {
            return addBatchedFilesToDb();
        }
        return 0;
    }
    
    /**
     * Add the current set of files to the database.
     * 
     * @return 0 if successful, -1 if not
     */
    private long addBatchedFilesToDb() {
        List<Long> newObjIds = new ArrayList<>();
        try {
			
			// loop through the batch, and make sure owner accounts exist for all the files in the batch.
			// If not, create accounts.
			Iterator<FileInfo> it = batchedFiles.iterator();

			while (it.hasNext()) {
				FileInfo fileInfo = it.next();
				String ownerUid = fileInfo.ownerUid;
				if (Strings.isNullOrEmpty(fileInfo.ownerUid) == false)  { 
					// first check the owner id is in the map, if found, then continue
					if (this.ownerIdToAccountMap.containsKey(ownerUid)) {
						continue;
					}

					// query the DB to get the owner account
					try {
						Optional<OsAccount> ownerAccount = caseDb.getOsAccountManager().getWindowsOsAccount(ownerUid, null, null, imageHost);
						if (ownerAccount.isPresent()) {
							// found account - add to map 
							ownerIdToAccountMap.put(ownerUid, ownerAccount.get());
						} else {
							// account not found in the database,  create the account and add to map
							// Currently we expect only NTFS systems to provide a windows style SID as owner id.
							OsAccount newAccount = caseDb.getOsAccountManager().newWindowsOsAccount(ownerUid, null, null, imageHost, OsAccountRealm.RealmScope.UNKNOWN);
							ownerIdToAccountMap.put(ownerUid, newAccount);
						}
					} catch (NotUserSIDException ex) {
						// if the owner SID is not a user SID, set the owner account to null
						ownerIdToAccountMap.put(ownerUid, null);
					}
				}
			}
			
			
					
            beginTransaction();
            FileInfo fileInfo;
            while ((fileInfo = batchedFiles.poll()) != null) {
                long computedParentObjId = fileInfo.parentObjId;
                try {
                    // If we weren't given the parent object ID, look it up
                    if (fileInfo.parentObjId == 0) {
                        computedParentObjId = getParentObjId(fileInfo);
                    }

					Long ownerAccountObjId = OsAccount.NO_ACCOUNT;
					if (Strings.isNullOrEmpty(fileInfo.ownerUid) == false) { 
						if (ownerIdToAccountMap.containsKey(fileInfo.ownerUid)) {
							// for any non user SIDs, the map will have a null for account
							if (Objects.nonNull(ownerIdToAccountMap.get(fileInfo.ownerUid))) {
							    ownerAccountObjId = ownerIdToAccountMap.get(fileInfo.ownerUid).getId();
							}
						} else {
							// Error - the map should have an account or a null at this point for the owner SID.
							throw new TskCoreException(String.format("Failed to add file. Owner account not found for file with parent object ID: %d, name: %s, owner id: %s", fileInfo.parentObjId, fileInfo.name, fileInfo.ownerUid));
						}
					}
					
					
                    long objId = addFileToDb(computedParentObjId, 
                        fileInfo.fsObjId, fileInfo.dataSourceObjId,
                        fileInfo.fsType,
                        fileInfo.attrType, fileInfo.attrId, fileInfo.name,
                        fileInfo.metaAddr, fileInfo.metaSeq,
                        fileInfo.dirType, fileInfo.metaType, fileInfo.dirFlags, fileInfo.metaFlags,
                        fileInfo.size,
                        fileInfo.crtime, fileInfo.ctime, fileInfo.atime, fileInfo.mtime,
                        fileInfo.meta_mode, fileInfo.gid, fileInfo.uid,
                        null, TskData.FileKnown.UNKNOWN,
                        fileInfo.escaped_path, fileInfo.extension, fileInfo.ownerUid, ownerAccountObjId,
                        false, trans);
                    if (fileInfo.fsObjId != fileInfo.parentObjId) {
                        // Add new file ID to the list to send to ingest unless it is the root folder
                        newObjIds.add(objId);
                    }

                    // If we're adding the root directory for the file system, cache it
                    if (fileInfo.parentObjId == fileInfo.fsObjId) {
                        fsIdToRootDir.put(fileInfo.fsObjId, objId);
                    }

                    // If the file is a directory, cache the object ID
                    if ((fileInfo.metaType == TskData.TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_DIR.getValue()
                            || (fileInfo.metaType == TskData.TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_VIRT_DIR.getValue()))
                            && (fileInfo.name != null)
                            && ! fileInfo.name.equals(".")
                            && ! fileInfo.name.equals("..")) {
                        String dirName = fileInfo.escaped_path + fileInfo.name;
                        ParentCacheKey key = new ParentCacheKey(fileInfo.fsObjId, fileInfo.metaAddr, fileInfo.seq, dirName);
                        parentDirCache.put(key, objId);
                    }
                } catch (TskCoreException ex) {
                    if (computedParentObjId > 0) {
                        // Most likely a database error occurred
                        logger.log(Level.SEVERE, "Error adding file to the database - parent object ID: " + computedParentObjId
                            + ", file system object ID: " + fileInfo.fsObjId + ", name: " + fileInfo.name, ex);
                    } else {
                        // The parent lookup failed
                        logger.log(Level.SEVERE, "Error adding file to the database", ex);
                    }
                }
            }
            commitTransaction();
            try {
                addDataSourceCallbacks.onFilesAdded(newObjIds);
			} catch (Exception ex) {
                // Exception firewall to prevent unexpected return to the native code
                logger.log(Level.SEVERE, "Unexpected error from files added callback", ex);
            }
        } catch (TskCoreException ex) {
            logger.log(Level.SEVERE, "Error adding batched files to database", ex);
            revertTransaction();
            return -1;
        }
        return 0;
    }
    
    /**
     * Look up the parent object ID for a file using the cache or the database.
     * 
     * @param fileInfo The file to find the parent of
     * 
     * @return Parent object ID
     * 
     * @throws TskCoreException 
     */
    private long getParentObjId(FileInfo fileInfo) throws TskCoreException {
        // Remove the final slash from the path unless we're in the root folder
        String parentPath = fileInfo.escaped_path;
        if(parentPath.endsWith("/") && ! parentPath.equals("/")) {
            parentPath =  parentPath.substring(0, parentPath.lastIndexOf('/'));
        }

        // Look up the parent
        ParentCacheKey key = new ParentCacheKey(fileInfo.fsObjId, fileInfo.parMetaAddr, fileInfo.parSeq, parentPath);
        if (parentDirCache.containsKey(key)) {
            return parentDirCache.get(key);
        } else {
            // There's no reason to do a database query since every folder added is being
            // stored in the cache.
            throw new TskCoreException("Could not find parent (fsObjId: " +fileInfo.fsObjId + ", parMetaAddr: " + fileInfo.parMetaAddr
                + ", parSeq: " + fileInfo.parSeq + ", parentPath: " + parentPath + ")");
        }
    }
    
    /**
     * Add a layout file to the database. 
     * Intended to be called from the native code during the add image process.
     * 
     * @param parentObjId     The parent object ID of the layout file.
     * @param fsObjId         The file system object ID.
     * @param dataSourceObjId The data source object ID.
     * @param fileType        The file type.
     * @param name            The file name.
     * @param size            The file size.
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
            
            beginTransaction();
            long objId = addFileToDb(parentObjId, 
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
                null, null, null, OsAccount.NO_ACCOUNT,
                true, trans);
            commitTransaction();

            // Store the layout file ID for later processing
            layoutFileIds.add(objId);

            return objId;
        } catch (TskCoreException ex) {
            logger.log(Level.SEVERE, "Error adding layout file to the database - parent object ID: " + parentObjId
                    + ", file system object ID: " + fsObjId + ", name: " + name, ex);
            revertTransaction();
            return -1;
        }
    }    
    
    /**
     * Add a layout file range to the database. 
     * Intended to be called from the native code during the add image process.
     * 
     * @param objId     Object ID of the layout file.
     * @param byteStart Start byte.
     * @param byteLen   Length in bytes.
     * @param seq       Sequence number of this range.
     * 
     * @return 0 if successful, -1 if not
     */
    long addLayoutFileRange(long objId, long byteStart, long byteLen, long seq) {
        batchedLayoutRanges.add(new LayoutRangeInfo(objId, byteStart, byteLen, seq));
        
        if (batchedLayoutRanges.size() > BATCH_FILE_THRESHOLD) {
            return addBatchedLayoutRangesToDb();
        }
        return 0;
    }
    
    /**
     * Add the current set of layout ranges to the database.
     * 
     * @return 0 if successful, -1 if not
     */
    private long addBatchedLayoutRangesToDb() {
        try {
            beginTransaction();
    		LayoutRangeInfo range;
            while ((range = batchedLayoutRanges.poll()) != null) {
                try {
                    addLayoutFileRangeToDb(range.objId, range.byteStart, range.byteLen, range.seq, trans);
                } catch (TskCoreException ex) {
                    logger.log(Level.SEVERE, "Error adding layout file range to the database - layout file ID: " + range.objId 
                        + ", byte start: " + range.byteStart + ", length: " + range.byteLen + ", seq: " + range.seq, ex);
                }
            }
            commitTransaction();
            return 0;
        } catch (TskCoreException ex) {
            logger.log(Level.SEVERE, "Error adding batched files to database", ex);
            revertTransaction();
            return -1;
        }
    }
	
    /**
     * Send completed layout files on for further processing.
     * Note that this must wait until we know all the ranges for each
     * file have been added to the database. 
     */
    void processLayoutFiles() {
        addDataSourceCallbacks.onFilesAdded(layoutFileIds);
        layoutFileIds.clear();
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
            beginTransaction();
            VirtualDirectory dir = caseDb.addVirtualDirectory(fsIdToRootDir.get(fsObjId), name, trans);
            commitTransaction();
            addDataSourceCallbacks.onFilesAdded(Arrays.asList(dir.getId()));
            return dir.getId();
        } catch (TskCoreException ex) {
            logger.log(Level.SEVERE, "Error creating virtual directory " + name + " under file system ID " + fsObjId, ex);
            revertTransaction();
            return -1;
        }
    }
    
    /**
     * Class to use as a key into the parent object ID map
     */
    private class ParentCacheKey {
        long fsObjId;
        long metaAddr;
        long seqNum;
        String path;
        
        /**
         * Create the key into the parent dir cache.
         * Only NTFS uses the seqNum of the parent. For all file systems set to zero.
         * 
         * @param fsObjId  The file system object ID.
         * @param metaAddr The metadata address of the directory.
         * @param seqNum   The sequence number of the directory. Unused unless file system is NTFS.
         * @param path     The path to the directory (should not include final slash unless root dir).
         */
        ParentCacheKey(long fsObjId, long metaAddr, long seqNum, String path) {
            this.fsObjId = fsObjId;
            this.metaAddr = metaAddr;
            if (ownerIdToAccountMap.containsKey(fsObjId) 
                    && (ownerIdToAccountMap.get(fsObjId).equals(TskData.TSK_FS_TYPE_ENUM.TSK_FS_TYPE_NTFS)
                        || ownerIdToAccountMap.get(fsObjId).equals(TskData.TSK_FS_TYPE_ENUM.TSK_FS_TYPE_NTFS_DETECT))) {
                this.seqNum = seqNum;
            } else {
                this.seqNum = 0;
            }
            this.path = path;
        }
        
        @Override
        public boolean equals(Object obj) {
            if (! (obj instanceof ParentCacheKey)) {
                return false;
            }
          
            ParentCacheKey otherKey = (ParentCacheKey) obj;
            if (this.fsObjId != otherKey.fsObjId 
                    || this.metaAddr != otherKey.metaAddr
                    || this.seqNum != otherKey.seqNum) {
                return false;
            }
            
            return StringUtils.equals(this.path, otherKey.path);
        }

        @Override
        public int hashCode() {
            int hash = 3;
            hash = 31 * hash + (int) (this.fsObjId ^ (this.fsObjId >>> 32));
            hash = 31 * hash + (int) (this.metaAddr ^ (this.metaAddr >>> 32));
            hash = 31 * hash + (int) (this.seqNum ^ (this.seqNum >>> 32));
            hash = 31 * hash + Objects.hashCode(this.path);
            return hash;
        }
    }
    
    /**
     * Utility class to hold data for layout ranges waiting
     * to be added to the database.
     */
    private class LayoutRangeInfo {
        long objId;
        long byteStart;
        long byteLen;
        long seq;
        
        LayoutRangeInfo(long objId, long byteStart, long byteLen, long seq) {
            this.objId = objId;
            this.byteStart = byteStart;
            this.byteLen = byteLen;
            this.seq = seq;
        }
    }
    
    /**
     * Utility class to hold data for files waiting to be
     * added to the database.
     */
    private class FileInfo {
        long parentObjId; 
        long fsObjId;
        long dataSourceObjId;
        int fsType;
        int attrType;
        int attrId;
        String name;
        long metaAddr; 
        long metaSeq;
        int dirType;
        int metaType;
        int dirFlags;
        int metaFlags;
        long size;
        long crtime;
        long ctime;
        long atime;
        long mtime;
        int meta_mode;
        int gid;
        int uid;
        String escaped_path;
        String extension;
        long seq;
        long parMetaAddr;
        long parSeq;
		String ownerUid;
        
        FileInfo(long parentObjId, 
            long fsObjId, long dataSourceObjId,
            int fsType,
            int attrType, int attrId, String name,
            long metaAddr, long metaSeq,
            int dirType, int metaType, int dirFlags, int metaFlags,
            long size,
            long crtime, long ctime, long atime, long mtime,
            int meta_mode, int gid, int uid,
            String escaped_path, String extension, 
            long seq, long parMetaAddr, long parSeq, String ownerUid) {
            
            this.parentObjId = parentObjId;
            this.fsObjId = fsObjId;
            this.dataSourceObjId = dataSourceObjId;
            this.fsType = fsType;
            this.attrType = attrType;
            this.attrId = attrId;
            this.name = name;
            this.metaAddr = metaAddr; 
            this.metaSeq = metaSeq;
            this.dirType = dirType;
            this.metaType = metaType;
            this.dirFlags = dirFlags;
            this.metaFlags = metaFlags;
            this.size = size;
            this.crtime = crtime;
            this.ctime = ctime;
            this.atime = atime;
            this.mtime = mtime;
            this.meta_mode = meta_mode;
            this.gid = gid;
            this.uid = uid;
            this.escaped_path = escaped_path;
            this.extension = extension;
            this.seq = seq;
            this.parMetaAddr = parMetaAddr;
            this.parSeq = parSeq;
			this.ownerUid = ownerUid;
        }
    }
	
	/**
	 * Add a file system file to the database.
	 *
	 * @param parentObjId     The parent of the file.
	 * @param fsObjId         The object ID of the file system.
	 * @param dataSourceObjId The data source object ID.
	 * @param fsType          The type.
	 * @param attrType        The type attribute given to the file by the file
	 *                        system.
	 * @param attrId          The type id given to the file by the file system.
	 * @param name            The name of the file.
	 * @param metaAddr        The meta address of the file.
	 * @param metaSeq         The meta sequence number of the file.
	 * @param dirType         The type of the file, usually as reported in the
	 *                        name structure of the file system.
	 * @param metaType        The type of the file, usually as reported in the
	 *                        metadata structure of the file system.
	 * @param dirFlags        The allocated status of the file, usually as
	 *                        reported in the name structure of the file system.
	 * @param metaFlags       The allocated status of the file, usually as
	 *                        reported in the metadata structure of the file
	 *                        system.
	 * @param size            The file size.
	 * @param crtime          The created time.
	 * @param ctime           The last changed time
	 * @param atime           The last accessed time.
	 * @param mtime           The last modified time.
	 * @param meta_mode       The modes for the file.
	 * @param gid             The group identifier.
	 * @param uid             The user identifier.
	 * @param md5             The MD5 hash.
	 * @param known           The file known status.
	 * @param escaped_path    The escaped path to the file.
	 * @param extension       The file extension.
	 * @param ownerUid        Unique id of the file owner.
	 * @param ownerAcctObjId  Object id of the owner account.
	 * @param hasLayout       True if this is a layout file, false otherwise.
	 * @param transaction     The open transaction.
	 *
	 * @return The object ID of the new file system
	 *
	 * @throws TskCoreException
	 */
	private long addFileToDb(long parentObjId,
			Long fsObjId, long dataSourceObjId,
			int fsType,
			Integer attrType, Integer attrId, String name,
			Long metaAddr, Long metaSeq,
			int dirType, int metaType, int dirFlags, int metaFlags,
			long size,
			Long crtime, Long ctime, Long atime, Long mtime,
			Integer meta_mode, Integer gid, Integer uid,
			String md5, TskData.FileKnown known,
			String escaped_path, String extension, String ownerUid, Long ownerAcctObjId,
			boolean hasLayout,  CaseDbTransaction transaction) throws TskCoreException {

		try {
			SleuthkitCase.CaseDbConnection connection = transaction.getConnection();
			
			// Insert a row for the local/logical file into the tsk_objects table.
			// INSERT INTO tsk_objects (par_obj_id, type) VALUES (?, ?)
			long objectId = caseDb.addObject(parentObjId, TskData.ObjectType.ABSTRACTFILE.getObjectType(), connection);
				
			String fileInsert = "INSERT INTO tsk_files (fs_obj_id, obj_id, data_source_obj_id, type, attr_type, attr_id, name, meta_addr, meta_seq, dir_type, meta_type, dir_flags, meta_flags, size, crtime, ctime, atime, mtime, mode, gid, uid, md5, known, parent_path, extension, has_layout, owner_uid, os_account_obj_id)"
				+ " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"; // NON-NLS
			PreparedStatement preparedStatement = connection.getPreparedStatement(fileInsert, Statement.NO_GENERATED_KEYS);			
			preparedStatement.clearParameters();
			
			if (fsObjId != null) {
				preparedStatement.setLong(1, fsObjId);			    // fs_obj_id
			} else {
				preparedStatement.setNull(1, java.sql.Types.BIGINT);
			}
			preparedStatement.setLong(2, objectId);					// obj_id 
			preparedStatement.setLong(3, dataSourceObjId);			// data_source_obj_id 
			preparedStatement.setShort(4, (short) fsType);	        // type
			if (attrType != null) {
				preparedStatement.setShort(5, attrType.shortValue());  // attr_type
			} else {
				preparedStatement.setNull(5, java.sql.Types.SMALLINT);
			}
			if (attrId != null) {
				preparedStatement.setInt(6, attrId);				// attr_id
			} else {
				preparedStatement.setNull(6, java.sql.Types.INTEGER);
			}
			preparedStatement.setString(7, name);					// name
			if (metaAddr != null) {
				preparedStatement.setLong(8, metaAddr);				// meta_addr
			} else {
				preparedStatement.setNull(8, java.sql.Types.BIGINT);
			}
			if (metaSeq != null) {
				preparedStatement.setInt(9, metaSeq.intValue());	// meta_seq
			} else {
				preparedStatement.setNull(9, java.sql.Types.INTEGER);
			}
			preparedStatement.setShort(10, (short) dirType);			// dir_type
			preparedStatement.setShort(11, (short) metaType);		// meta_type
			preparedStatement.setShort(12, (short) dirFlags);		// dir_flags
			preparedStatement.setShort(13, (short) metaFlags);		// meta_flags
			preparedStatement.setLong(14, size < 0 ? 0 : size);     // size
			if (crtime != null) {
				preparedStatement.setLong(15, crtime);              // crtime
			} else {
				preparedStatement.setNull(15, java.sql.Types.BIGINT);
			}
			if (ctime != null) {
				preparedStatement.setLong(16, ctime);               // ctime
			} else {
				preparedStatement.setNull(16, java.sql.Types.BIGINT);
			}
			if (atime != null) {
				preparedStatement.setLong(17, atime);               // atime
			} else {
				preparedStatement.setNull(17, java.sql.Types.BIGINT);
			}
			if (mtime != null) {
				preparedStatement.setLong(18, mtime);               // mtime
			} else {
				preparedStatement.setNull(18, java.sql.Types.BIGINT);
			}
			if (meta_mode != null) {
				preparedStatement.setLong(19, meta_mode);           // mode
			} else {
				preparedStatement.setNull(19, java.sql.Types.BIGINT);
			}
			if (gid != null) {
				preparedStatement.setLong(20, gid);                 // gid
			} else {
				preparedStatement.setNull(20, java.sql.Types.BIGINT);
			}
			if (uid != null) {
				preparedStatement.setLong(21, uid);                 // uid
			} else {
				preparedStatement.setNull(21, java.sql.Types.BIGINT);
			}
			preparedStatement.setString(22, md5);                   // md5
			preparedStatement.setInt(23, known.getFileKnownValue());// known
			preparedStatement.setString(24, escaped_path);          // parent_path
			preparedStatement.setString(25, extension);             // extension
			if (hasLayout) {
				preparedStatement.setInt(26, 1);                    // has_layout
			} else {
				preparedStatement.setNull(26, java.sql.Types.INTEGER);
			}
			
			preparedStatement.setString(27, ownerUid); // ownerUid
			
			if (ownerAcctObjId != OsAccount.NO_ACCOUNT) {
				preparedStatement.setLong(28, ownerAcctObjId); //
			} else {
				preparedStatement.setNull(28, java.sql.Types.BIGINT);
			}
			
			connection.executeUpdate(preparedStatement);

			// If this is not a slack file create the timeline events
			if (!hasLayout
					&& TskData.TSK_DB_FILES_TYPE_ENUM.SLACK.getFileType() != fsType
					&& (!name.equals(".")) && (!name.equals(".."))) {
				TimelineManager timelineManager = caseDb.getTimelineManager();
				DerivedFile derivedFile = new DerivedFile(caseDb, objectId, dataSourceObjId, name,
						TskData.TSK_FS_NAME_TYPE_ENUM.valueOf((short) dirType),
						TskData.TSK_FS_META_TYPE_ENUM.valueOf((short) metaType),
						TskData.TSK_FS_NAME_FLAG_ENUM.valueOf(dirFlags),
						(short) metaFlags,
						size, ctime, crtime, atime, mtime, null, null, null, escaped_path, null, parentObjId, null, null, extension, ownerUid, ownerAcctObjId);

				timelineManager.addEventsForNewFileQuiet(derivedFile, connection);
			}

			return objectId;
		} catch (SQLException ex) {
			throw new TskCoreException("Failed to add file system file", ex);
		}
	}	
	
	/**
	 * Add an image to the database.
	 *
	 * @param type              Type of image.
	 * @param sectorSize        Sector size.
	 * @param size              Image size.
	 * @param timezone          Time zone.
	 * @param md5               MD5 hash.
	 * @param sha1              SHA1 hash.
	 * @param sha256            SHA256 hash.
	 * @param deviceId          Device ID.
	 * @param collectionDetails Collection details.
	 * @param hostId            The ID of a host already in the database.
	 * @param transaction       Case DB transaction.
	 *
	 * @return The newly added Image object ID.
	 *
	 * @throws TskCoreException
	 */
	private long addImageToDb(TskData.TSK_IMG_TYPE_ENUM type, long sectorSize, long size,
			String timezone, String md5, String sha1, String sha256,
			String deviceId, String collectionDetails,
			CaseDbTransaction transaction) throws TskCoreException {
		try {
			// Insert a row for the Image into the tsk_objects table.
			SleuthkitCase.CaseDbConnection connection = transaction.getConnection();
			long newObjId = caseDb.addObject(0, TskData.ObjectType.IMG.getObjectType(), connection);

			// Add a row to tsk_image_info
			// INSERT INTO tsk_image_info (obj_id, type, ssize, tzone, size, md5, sha1, sha256, display_name)
			String imageInfoSql = "INSERT INTO tsk_image_info (obj_id, type, ssize, tzone, size, md5, sha1, sha256, display_name)"
				+ " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"; // NON-NLS
			PreparedStatement preparedStatement = connection.getPreparedStatement(imageInfoSql, Statement.NO_GENERATED_KEYS);
			preparedStatement.clearParameters();
			preparedStatement.setLong(1, newObjId);
			preparedStatement.setShort(2, (short) type.getValue());
			preparedStatement.setLong(3, sectorSize);
			preparedStatement.setString(4, timezone);
			//prevent negative size
			long savedSize = size < 0 ? 0 : size;
			preparedStatement.setLong(5, savedSize);
			preparedStatement.setString(6, md5);
			preparedStatement.setString(7, sha1);
			preparedStatement.setString(8, sha256);
			preparedStatement.setString(9, null);
			connection.executeUpdate(preparedStatement);

			// Add a row to data_source_info
			String dataSourceInfoSql = "INSERT INTO data_source_info (obj_id, device_id, time_zone, acquisition_details, host_id) VALUES (?, ?, ?, ?, ?)"; // NON-NLS
			preparedStatement = connection.getPreparedStatement(dataSourceInfoSql, Statement.NO_GENERATED_KEYS);
			preparedStatement.clearParameters();
			preparedStatement.setLong(1, newObjId);
			preparedStatement.setString(2, deviceId);
			preparedStatement.setString(3, timezone);
			preparedStatement.setString(4, collectionDetails);
			preparedStatement.setLong(5, imageHost.getHostId());
			connection.executeUpdate(preparedStatement);

			return newObjId;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error adding image to database"), ex);
		}
	}	
	
	/**
	 * Add an image name to the database.
	 *
	 * @param objId       The object id of the image.
	 * @param name        The file name for the image
	 * @param sequence    The sequence number of this file.
	 * @param transaction The open transaction.
	 *
	 * @throws TskCoreException
	 */
	private void addImageNameToDb(long objId, String name, long sequence,
			CaseDbTransaction transaction) throws TskCoreException {
		try {
			SleuthkitCase.CaseDbConnection connection = transaction.getConnection();
			
			String imageNameSql = "INSERT INTO tsk_image_names (obj_id, name, sequence) VALUES (?, ?, ?)"; // NON-NLS
			PreparedStatement preparedStatement = connection.getPreparedStatement(imageNameSql, Statement.NO_GENERATED_KEYS);
			preparedStatement.clearParameters();
			preparedStatement.setLong(1, objId);
			preparedStatement.setString(2, name);
			preparedStatement.setLong(3, sequence);
			connection.executeUpdate(preparedStatement);
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error adding image name %s to image with object ID %d", name, objId), ex);
		}
	}	
	
	/**
	 * Add a layout file range to the database.
	 *
	 * @param objId       Object ID of the layout file.
	 * @param byteStart   Start byte.
	 * @param byteLen     Length in bytes.
	 * @param seq         Sequence number of this range.
	 * @param transaction The open transaction.
	 *
	 * @throws TskCoreException
	 */
	void addLayoutFileRangeToDb(long objId, long byteStart, long byteLen,
			long seq, CaseDbTransaction transaction) throws TskCoreException {
		try {
			SleuthkitCase.CaseDbConnection connection = transaction.getConnection();

			String insertRangeSql = "INSERT INTO tsk_file_layout (obj_id, byte_start, byte_len, sequence) " //NON-NLS
				+ "VALUES (?, ?, ?, ?)";
			PreparedStatement preparedStatement = connection.getPreparedStatement(insertRangeSql, Statement.NO_GENERATED_KEYS);
			preparedStatement.clearParameters();
			preparedStatement.setLong(1, objId);
			preparedStatement.setLong(2, byteStart);
			preparedStatement.setLong(3, byteLen);
			preparedStatement.setLong(4, seq);
			connection.executeUpdate(preparedStatement);
		} catch (SQLException ex) {
			throw new TskCoreException("Error adding layout range to file with obj ID " + objId, ex);
		}
	}
}
