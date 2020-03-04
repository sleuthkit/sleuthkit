/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.datamodel;

import java.util.HashMap;
import java.util.Map;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbTransaction;

/**
 *
 */
class JniDbHelper {
	
	private SleuthkitCase caseDb;
	private CaseDbTransaction trans;
	
	private Map<Long, Long> fsIdToRootDir = new HashMap<>();
	
	JniDbHelper(SleuthkitCase caseDb) {
		this.caseDb = caseDb;
		trans = null;
	}
	
	void beginTransaction() throws TskCoreException {
		trans = caseDb.beginTransaction();
	}
	
	void commitTransaction() throws TskCoreException {
		trans.commit();
		trans = null;
	}
	
	void test(int x) {
		System.out.println("\n@@@ Java test method");
	}
	
	long testLong(int x) {
		System.out.println("\n@@@ Java testLong method");
		return 10;
	}
	
	void testStringArg(String str) {
		System.out.println("\n@@@ Got string: " + str);
	}
	
	void testStringArg2(String str, int x) {
		System.out.println("\n@@@ Got string: " + str + " and int: " + x);
	}
	
	
	long addImageInfo(int type, long ssize, String timezone, 
			long size, String md5, String sha1, String sha256, String deviceId, 
			String collectionDetails) {
		System.out.println("\n@@@ In Java! addImageInfo");
		System.out.flush();
		try {
			return caseDb.addImageJNI(TskData.TSK_IMG_TYPE_ENUM.valueOf(type), ssize, size,
					timezone, md5, sha1, sha256, deviceId, trans);
		} catch (TskCoreException ex) {
			ex.printStackTrace();
			return -1;
		}
	}
	
	int addImageName(long objId, String name, long sequence) {
		try {
			caseDb.addImageNameJNI(objId, name, sequence, trans);
			return 0;
		} catch (TskCoreException ex) {
			ex.printStackTrace();
			return -1;
		}
	}
	
	long addVsInfo(long parentObjId, int vsType, long imgOffset, long blockSize) {
		try {
			VolumeSystem vs = caseDb.addVolumeSystem(parentObjId, TskData.TSK_VS_TYPE_ENUM.valueOf(vsType), imgOffset, blockSize, trans);
			return vs.getId();
		} catch (TskCoreException ex) {
			ex.printStackTrace();
			return -1;
		}
	}
	
	long addVolume(long parentObjId, long addr, long start, long length, String desc,
			long flags) {
		try {
			Volume vol = caseDb.addVolume(parentObjId, addr, start, length, desc, flags, trans);
			return vol.getId();
		} catch (TskCoreException ex) {
			ex.printStackTrace();
			return -1;
		}
	}

	long addPool(long parentObjId, int poolType) {
		try {
			Pool pool = caseDb.addPool(parentObjId, TskData.TSK_POOL_TYPE_ENUM.valueOf(poolType), trans);
			return pool.getId();
		} catch (TskCoreException ex) {
			ex.printStackTrace();
			return -1;
		}
	}

	long addFileSystem(long parentObjId, long imgOffset, int fsType, long blockSize, long blockCount,
			long rootInum, long firstInum, long lastInum) {
		try {
			FileSystem fs = caseDb.addFileSystem(parentObjId, imgOffset, TskData.TSK_FS_TYPE_ENUM.valueOf(fsType), blockSize, blockCount,
					rootInum, firstInum, lastInum, null, trans);
			return fs.getId();
		} catch (TskCoreException ex) {
			ex.printStackTrace();
			return -1;
		}
	}

	long addFile(long parentObjId, 
        long fsObjId, long dataSourceObjId,
        int fsType,
        int attrType, int attrId, String name,
        long metaAddr, long metaSeq,
        int dirType, int metaType, int dirFlags, int metaFlags,
        long size,
        long crtime, long ctime, long atime, long mtime,
        int meta_mode, int gid, int uid, /// md5TextPtr, known,
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
			
			if (parentObjId == fsObjId) {
				fsIdToRootDir.put(fsObjId, objId);
			}
			return objId;
		} catch (TskCoreException ex) {
			ex.printStackTrace();
			return -1;
		}
	}
	
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
			
			System.out.println("@@@ addLayoutFile: parentObjId: " + parentObjId + ", fsObjId: " + fsObjId + ", dsObjId: " + dataSourceObjId);
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
			System.out.println("\n@@@ Error in addLayoutFile");
			ex.printStackTrace();
			return -1;
		}
	}	
	
	long addLayoutFileRange(long objId, long byteStart, long byteLen, long seq) {
		try {
			caseDb.addLayoutFileRangeJNI(objId, byteStart, byteLen, seq, trans);
			return 0;
		} catch (TskCoreException ex) {
			ex.printStackTrace();
			return -1;
		}
	}
	
	long findParentObjId(long metaAddr, long fsObjId, String path, String name) {
		try {
			return caseDb.findParentObjIdJNI(metaAddr, fsObjId, path, name, trans);
		} catch (TskCoreException ex) {
			ex.printStackTrace();
			return -1;
		}
	}
	
	long addUnallocFsBlockFilesParent(long fsObjId, String name) {
		try {
			if (! fsIdToRootDir.containsKey(fsObjId)) {
				System.out.println("Argh no fs id...");
				return -1;
			}
			VirtualDirectory dir = caseDb.addVirtualDirectory(fsIdToRootDir.get(fsObjId), name, trans);
			return dir.getId();
		} catch (TskCoreException ex) {
			ex.printStackTrace();
			return -1;
		}
	}
	
}
