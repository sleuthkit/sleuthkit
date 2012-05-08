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
 *	 http://www.apache.org/licenses/LICENSE-2.0
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

/**
 * Interfaces with the sleuthkit c/c++ libraries to read data from image files
 */
public class SleuthkitJNI {
	//Native methods
	private static native String getVersionNat();
	private static native void startVerboseLoggingNat(String logPath);
	
	//database
	private static native long newCaseDbNat(String dbPath) throws TskException;
	private static native long openCaseDbNat(String path) throws TskException;
	private static native void closeCaseDbNat(long db) throws TskException;
	private static native void setDbNSRLNat(String hashDbPath) throws TskException;
	private static native void setDbKnownBadNat(String hashDbPath) throws TskException;
	private static native void closeDbLookupsNat() throws TskException;
	private static native int hashDBLookup(String hash) throws TskException;

	
	//load image
	private static native long initAddImgNat(long db, String timezone, boolean noFatFsOrphans) throws TskException;
	private static native void runAddImgNat(long process, String[] imgPath, int splits) throws TskException; // if runAddImg finishes without being stopped, revertAddImg or commitAddImg MUST be called
	private static native void stopAddImgNat(long process) throws TskException;
	private static native void revertAddImgNat(long process) throws TskException;
	private static native long commitAddImgNat(long process) throws TskException;
	//open functions
	private static native long openImgNat(String[] imgPath, int splits) throws TskException;
	private static native long openVsNat(long imgHandle, long vsOffset) throws TskException;
	private static native long openVolNat(long vsHandle, long volId) throws TskException;
	private static native long openFsNat(long imgHandle, long fsId) throws TskException;
	private static native long openFileNat(long fsHandle, long fileId) throws TskException;
 
	//read functions
	private static native int readImgNat(long imgHandle, byte[] readBuffer, long offset, long len) throws TskException;
	private static native int readVsNat(long vsHandle, byte[] readBuffer, long offset, long len) throws TskException;
	private static native int readVolNat(long volHandle, byte[] readBuffer, long offset, long len) throws TskException;
	private static native int readFsNat(long fsHandle, byte[] readBuffer, long offset, long len) throws TskException;
	private static native int readFileNat(long fileHandle, byte[] readBuffer, long offset, long len) throws TskException;

	//close functions
	private static native void closeImgNat(long imgHandle);
	private static native void closeVsNat(long vsHandle);
	private static native void closeFsNat(long fsHandle);
	private static native void closeFileNat(long fileHandle);
	
	//hash-lookup database functions
	private static native void createLookupIndexNat(String dbPath) throws TskException;
	private static native boolean lookupIndexExistsNat(String dbPath) throws TskException;

	static {
		try {
			System.loadLibrary("zlib");
			System.loadLibrary("libewf");
		}
		catch (UnsatisfiedLinkError e) {
			// @@@ LOG??
		}
		System.loadLibrary("libtsk_jni");
		//System.load("/Users/brianc/proj/github/bindings/java/jni/.libs/libtsk_jni.0.dylib");
	}


	public SleuthkitJNI() {}
	

	public static class CaseDbHandle {
		private long caseDbPointer;
		
		//map concat. image paths to cached image handle
		private static final Map<String,Long> imageHandleCache = new HashMap<String,Long>(); 
		//map image and offsets to cached fs handle
		private static final Map<Long,Map<Long,Long>> fsHandleCache = new HashMap<Long,Map<Long,Long>>();
		
		private CaseDbHandle(long pointer) {
			this.caseDbPointer = pointer;
		}
		
		void free() throws TskException {
			SleuthkitJNI.closeCaseDbNat(caseDbPointer);
		}
		void clearLookupDatabases() throws TskException {
			closeDbLookupsNat();
		}
		
		
		/**
		 * Set the path to an NSRL database
		 */
		void setNSRLDatabase(String path) throws TskException {
			setDbNSRLNat(path);
		}

		/**
		 * Set the path to a known bad hash database
		 */
		void setKnownBadDatabase(String path) throws TskException {
			setDbKnownBadNat(path);
		}

		
	
		/**
		 * Start the process of adding a disk image to the case. 
		 * @param timezone Timezone that image was from
		 * @param noFatFsOrphans true if to skip processing of orphans on FAT filesystems 
		 * 
		 * @return Object that can be used to manage the process.
		 */
		AddImageProcess initAddImageProcess(String timezone, boolean noFatFsOrhpans) {
			return new AddImageProcess(timezone, noFatFsOrhpans);
		}
		
		/**
		 * Encapsulates a multi-step process to add a disk image.
		 * Adding a disk image takes a while and this object
		 * has objects to manage that process.
		 */
		public class AddImageProcess {
			String timezone;
			boolean noFatFsOrphans;
			long autoDbPointer;
			
			private AddImageProcess(String timezone, boolean noFatFsOrphans) {
				this.timezone = timezone;
				this.noFatFsOrphans = noFatFsOrphans;
				autoDbPointer = 0;
			}
			
			/**
			 * Start the process of adding an image to the case database. 
			 * MUST call either commit() or revert() after calling run().
			 * @param imgPath Full path(s) to the image file(s).
			 * @throws TskException
			 */
			public void run(String[] imgPath) throws TskException {
				if (autoDbPointer != 0) {
					throw new TskException("AddImgProcess:run: AutoDB pointer is already set");
				}
				
				autoDbPointer = initAddImgNat(caseDbPointer, timezone, noFatFsOrphans);
				runAddImgNat(autoDbPointer, imgPath, imgPath.length);
			}
			
			/**
			 * Call while run() is executing in another thread to prematurely
			 * halt the process. Must call revert() in the other thread once
			 * the stopped run() returns.
			 * @throws TskException
			 */
			public void stop() throws TskException {
				if (autoDbPointer == 0) {
					throw new TskException("AddImgProcess::stop: AutoDB pointer is NULL");
				}
				
				stopAddImgNat(autoDbPointer);
			}
			
			/**
			 * Rollback a process that has already been run(), reverting the
			 * database.  This releases the C++ object and no additional 
			 * operations can be performed. 
			 * 
			 * @throws TskException
			 */
			public void revert() throws TskException {
				if (autoDbPointer == 0) {
					throw new TskException("AddImgProcess::revert: AutoDB pointer is NULL");
				}
				
				revertAddImgNat(autoDbPointer);
				// the native code deleted the object
				autoDbPointer = 0;
			}
			
			/**
			 * Finish off a process that has already been run(), closing the
			 * transaction and committing the new image data to the database.
			 * @return The id of the image that was added. This releases the 
			 * C++ object and no additional operations can be performed. 
			 * @throws TskException 
			 */
			public long commit() throws TskException {
				if (autoDbPointer == 0) {
					throw new TskException("AddImgProcess::commit: AutoDB pointer is NULL");
				}
	
				long id = commitAddImgNat(autoDbPointer);
				// the native code deleted the object
				autoDbPointer = 0;
				return id;
			}
		}
	}
	
	/**
	 * Creates a new case database. Must call .free() on CaseDbHandle instance
	 * when done.
	 * @param path Location to create the database at.
	 * @return Handle for a new TskCaseDb instance.
	 * @throws TskException 
	 */
	static CaseDbHandle newCaseDb(String path) throws TskException {
		return new CaseDbHandle(newCaseDbNat(path));
	}
	
	/**
	 * Opens an existing case database. Must call .free() on CaseDbHandle 
	 * instance when done.
	 * @param path Location of the existing database.
	 * @return Handle for a new TskCaseDb instance.
	 * @throws TskException 
	 */
	static CaseDbHandle openCaseDb(String path) throws TskException {
		return new CaseDbHandle(openCaseDbNat(path));
	}
	

	/**
	 * get the Sleuth Kit version string
	 * @return the version string
	 */
	public static String getVersion(){
		return getVersionNat();
	}
	
	/**
	 * Enable verbose logging and redirect stderr to the given log file.
	 */
	public static void startVerboseLogging(String logPath) {
		startVerboseLoggingNat(logPath);
	}


	/**
	 * open the image and return the image info pointer
	 * @param imageFiles the paths to the images
	 * @return the image info pointer
	 * @throws TskException
	 */
	public synchronized static long openImage(String[] imageFiles) throws TskException{
		long imageHandle = 0;
		
		StringBuilder keyBuilder = new StringBuilder();
		for (int i=0; i<imageFiles.length; ++i)
			keyBuilder.append(imageFiles[i]);
		final String imageKey = keyBuilder.toString();
		
		if (CaseDbHandle.imageHandleCache.containsKey(imageKey) )
			//get from cache
			imageHandle = CaseDbHandle.imageHandleCache.get(imageKey);
		else {
			//open new handle and cache it
			imageHandle = openImgNat(imageFiles, imageFiles.length);
			CaseDbHandle.fsHandleCache.put(imageHandle, new HashMap<Long,Long>());
			CaseDbHandle.imageHandleCache.put(imageKey, imageHandle);
		}

		return imageHandle;
		
	}

	/**
	 * Get volume system Handle
	 * @param vsOffset byte offset in the image to the volume system (usually 0)
	 * @return pointer to a vsHandle structure in the sleuthkit
	 */
	public static long openVs(long imgHandle, long vsOffset) throws TskException{
		return openVsNat(imgHandle, vsOffset);
	}

	//get pointers
	/**
	 * Get volume Handle
	 * @param vsHandle pointer to the volume system structure in the sleuthkit
	 * @param volId id of the volume
	 * @return pointer to a volHandle structure in the sleuthkit
	 * @throws TskException  
	 */
	public static long openVsPart(long vsHandle, long volId) throws TskException{
		//returned long is ptr to vs Handle object in tsk
		return openVolNat(vsHandle, volId);
	}

	/**
	 * get file system Handle
	 * @param imgHandle pointer to imgHandle in sleuthkit
	 * @param fsOffset byte offset to the file system
	 * @return pointer to a fsHandle structure in the sleuthkit
	 * @throws TskException  
	 */
	public synchronized static long openFs(long imgHandle, long fsOffset) throws TskException{
		long fsHandle = 0;
		final Map<Long,Long> imgOffSetToFsHandle = CaseDbHandle.fsHandleCache.get(imgHandle);
		if (imgOffSetToFsHandle.containsKey(fsOffset)) {
			//return cached
			fsHandle = imgOffSetToFsHandle.get(fsOffset);
		}
		else {
			fsHandle = openFsNat(imgHandle, fsOffset);
			//cache it
			imgOffSetToFsHandle.put(fsOffset, fsHandle);
		}
		return fsHandle;
	}

	/**
	 * get file Handle
	 * @param fsHandle fsHandle pointer in the sleuthkit
	 * @param fileId id of the file
	 * @return pointer to a file structure in the sleuthkit
	 * @throws TskException  
	 */
	public static long openFile(long fsHandle, long fileId) throws TskException{
		return openFileNat(fsHandle, fileId);
	}

	//do reads
	/**
	 * reads data from an image
	 * @param imgHandle 
	 * @param readBuffer buffer to read to
	 * @param offset byte offset in the image to start at
	 * @param len amount of data to read
	 * @return the number of characters read, or -1 if the end of the stream has been reached 
	 * @throws TskException  
	 */
	public static int readImg(long imgHandle, byte[] readBuffer, long offset, long len) throws TskException{
		//returned byte[] is the data buffer
		return readImgNat(imgHandle, readBuffer, offset, len);
	}
	/**
	 * reads data from an volume system
	 * @param vsHandle pointer to a volume system structure in the sleuthkit
	 * @param readBuffer buffer to read to
	 * @param offset sector offset in the image to start at
	 * @param len amount of data to read
	 * @return the number of characters read, or -1 if the end of the stream has been reached 
	 * @throws TskException  
	 */
	public static int readVs(long vsHandle, byte[] readBuffer, long offset, long len) throws TskException{
		return readVsNat(vsHandle, readBuffer, offset, len);
	}
	/**
	 * reads data from an volume
	 * @param volHandle pointer to a volume structure in the sleuthkit
	 * @param readBuffer buffer to read to
	 * @param offset byte offset in the image to start at
	 * @param len amount of data to read
	 * @return the number of characters read, or -1 if the end of the stream has been reached 
	 * @throws TskException  
	 */
	public static int readVsPart(long volHandle, byte[] readBuffer, long offset, long len) throws TskException{
		//returned byte[] is the data buffer
		return readVolNat(volHandle, readBuffer, offset, len);
	}
	/**
	 * reads data from an file system
	 * @param fsHandle pointer to a file system structure in the sleuthkit
	 * @param readBuffer buffer to read to
	 * @param offset byte offset in the image to start at
	 * @param len amount of data to read
	 * @return the number of characters read, or -1 if the end of the stream has been reached 
	 * @throws TskException  
	 */
	public static int readFs(long fsHandle, byte[] readBuffer, long offset, long len) throws TskException{
		//returned byte[] is the data buffer
		return readFsNat(fsHandle, readBuffer, offset, len);
	}
	
	
	/**
	 * reads data from an file
	 * @param fileHandle pointer to a file structure in the sleuthkit
	 * @param readBuffer pre-allocated buffer to read to
	 * @param offset byte offset in the image to start at
	 * @param len amount of data to read
	 * @return the number of characters read, or -1 if the end of the stream has been reached 
	 * @throws TskException  
	 */
	public static int readFile(long fileHandle, byte[] readBuffer, long offset, long len) throws TskException {
		return readFileNat(fileHandle, readBuffer, offset, len);
	}

	//free pointers
	/**
	 * frees the imgHandle pointer
	 * 
	 * @param imgHandle 
	 */
	public static void closeImg(long imgHandle){
		//@@@ TODO close the image handle when Case is closed instead
		//currently the image handle is not being freed, it's cached for duration of the application
		//closeImgNat(imgHandle); 
	}
	/**
	 * frees the vsHandle pointer
	 * @param vsHandle pointer to volume system structure in sleuthkit
	 */
	public static void closeVs(long vsHandle){
		closeVsNat(vsHandle);
	}

	/**
	 * frees the fsHandle pointer
	 * @param fsHandle pointer to file system structure in sleuthkit
	 */
	public static void closeFs(long fsHandle){
		//@@@ TODO close the fs handle when Case is closed instead
		//currently the fs handle is not being freed, it's cached for duration of the application
		//closeFsNat(fsHandle);
	}
	/**
	 * frees the fileHandle pointer
	 * @param fileHandle pointer to file structure in sleuthkit
	 */
	public static void closeFile(long fileHandle){
		closeFileNat(fileHandle);
	}
	
	/**
	 * Create an index for the given database path.
	 * @param dbPath
	 * @throws TskException 
	 */
	public static void createLookupIndex(String dbPath) throws TskException {
		createLookupIndexNat(dbPath);
	}
	
	/**
	 * Check if an index exists for the given database path.
	 * @param dbPath
	 * @return true if index exists
	 * @throws TskException 
	 */
	public static boolean lookupIndexExists(String dbPath) throws TskException {
		return lookupIndexExistsNat(dbPath);
	}
	
	/**
	 * Set the path to an NSRL database
	 */
	public static void setNSRLDatabase(String path) throws TskException {
		setDbNSRLNat(path);
	}

	/**
	 * Set the path to a known bad hash database
	 */
	public static void setKnownBadDatabase(String path) throws TskException {
		setDbKnownBadNat(path);
	}
	
	public static TskData.FileKnown lookupHash(String hash) throws TskException{
		return TskData.FileKnown.valueOf(hashDBLookup(hash));
	}
	
}
