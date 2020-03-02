/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.datamodel;

import org.sleuthkit.datamodel.SleuthkitCase.CaseDbTransaction;

/**
 *
 */
class JniDbHelper {
	
	SleuthkitCase caseDb;
	CaseDbTransaction trans;
	
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
	// TskData.TSK_POOL_TYPE_ENUM
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
					rootInum, firstInum, lastInum, "", trans);
			return fs.getId();
		} catch (TskCoreException ex) {
			ex.printStackTrace();
			return -1;
		}
	}

	// fs_obj_id, obj_id, data_source_obj_id, type, 
	// attr_type, attr_id, 
	// name, 
	// meta_addr, meta_seq, 
	// dir_type, 
	// meta_type, dir_flags, meta_flags, 
	// size, crtime, ctime, atime, mtime, mode, gid, uid, md5, known, parent_path, extension)"
	long addFile(long parentObjId, 
        long fsObjId, long dataSourceObjId,
        int fsType, // TSK_DB_FILES_TYPE_FS,
        int attrType, int attrId, String name,
        long metaAddr, long metaSeq,
        int dirType, int metaType, int dirFlags, int metaFlags,
        long size,
        long crtime, long ctime, long atime, long mtime,
        int meta_mode, int gid, int uid, /// md5TextPtr, known,
        String escaped_path, String extension
	
	) {
		try {
			return caseDb.addFileSystemFileJNI(parentObjId, 
				fsObjId, dataSourceObjId,
				fsType,
				attrType, attrId, name,
				metaAddr, metaSeq,
				dirType, metaType, dirFlags, metaFlags,
				size,
				crtime, ctime, atime, mtime,
				meta_mode, gid, uid, /// md5TextPtr, known,
				"", TskData.FileKnown.UNKNOWN,
				escaped_path, extension, trans);
		} catch (TskCoreException ex) {
			ex.printStackTrace();
			return -1;
		}
	}
	
	long findParentObjId(long metaAddr, long fsobjId, String path, String name) {
		try {
			return caseDb.findParentObjIdJNI(metaAddr, fsobjId, path, name, trans);
		} catch (TskCoreException ex) {
			ex.printStackTrace();
			return -1;
		}
	}
	
}
