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
			return caseDb.addImageJNI(TskData.TSK_IMG_TYPE_ENUM.valueOf(type), ssize, size, "displayName",
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
}
