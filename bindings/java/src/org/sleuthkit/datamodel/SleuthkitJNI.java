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

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;
import org.sleuthkit.datamodel.TskData.TSK_FS_ATTR_TYPE_ENUM;

/**
 * Interfaces with the Sleuthkit TSK c/c++ libraries Supports case management,
 * add image process, reading data off content objects Setting up Hash database
 * parameters and updating / reading values
 *
 * Caches image and filesystem handles and reuses them for the duration of the
 * application
 */
public class SleuthkitJNI {

	private static final int MAX_DATABASES = 256;

	//Native methods
	private static native String getVersionNat();

	private static native void startVerboseLoggingNat(String logPath);

	//database
	private static native long newCaseDbNat(String dbPath) throws TskCoreException;

	private static native long openCaseDbNat(String path) throws TskCoreException;

	private static native void closeCaseDbNat(long db) throws TskCoreException;

	private static native int setDbNSRLNat(String hashDbPath) throws TskCoreException;

	private static native int addDbKnownBadNat(String hashDbPath) throws TskCoreException;

	private static native String getDbName(String hashDbPath) throws TskCoreException;

	private static native void closeDbLookupsNat() throws TskCoreException;

	private static native int knownBadDbLookup(String hash, int dbHandle) throws TskCoreException;

	private static native int nsrlDbLookup(String hash) throws TskCoreException;

	private static native int getIndexSizeNat(String hashDbPath) throws TskCoreException;

	//load image
	private static native long initAddImgNat(long db, String timezone, boolean processUnallocSpace, boolean noFatFsOrphans) throws TskCoreException;

	private static native void runAddImgNat(long process, String[] imgPath, int splits, String timezone) throws TskCoreException, TskDataException; // if runAddImg finishes without being stopped, revertAddImg or commitAddImg MUST be called

	private static native void stopAddImgNat(long process) throws TskCoreException;

	private static native void revertAddImgNat(long process) throws TskCoreException;

	private static native long commitAddImgNat(long process) throws TskCoreException;

	//open functions
	private static native long openImgNat(String[] imgPath, int splits) throws TskCoreException;

	private static native long openVsNat(long imgHandle, long vsOffset) throws TskCoreException;

	private static native long openVolNat(long vsHandle, long volId) throws TskCoreException;

	private static native long openFsNat(long imgHandle, long fsId) throws TskCoreException;

	private static native long openFileNat(long fsHandle, long fileId, int attrType, int attrId) throws TskCoreException;

	//read functions
	private static native int readImgNat(long imgHandle, byte[] readBuffer, long offset, long len) throws TskCoreException;

	private static native int readVsNat(long vsHandle, byte[] readBuffer, long offset, long len) throws TskCoreException;

	private static native int readVolNat(long volHandle, byte[] readBuffer, long offset, long len) throws TskCoreException;

	private static native int readFsNat(long fsHandle, byte[] readBuffer, long offset, long len) throws TskCoreException;

	private static native int readFileNat(long fileHandle, byte[] readBuffer, long offset, long len) throws TskCoreException;

	//close functions
	private static native void closeImgNat(long imgHandle);

	private static native void closeVsNat(long vsHandle);

	private static native void closeFsNat(long fsHandle);

	private static native void closeFileNat(long fileHandle);

	//hash-lookup database functions
	private static native void createLookupIndexNat(String dbPath) throws TskCoreException;

	private static native boolean lookupIndexExistsNat(String dbPath) throws TskCoreException;

	//util functions
	private static native long findDeviceSizeNat(String devicePath) throws TskCoreException;

	private static native String getCurDirNat(long process);

	//Linked library loading
	static {
		LibraryUtils.loadSleuthkitJNI();
    }

	public SleuthkitJNI() {
	}

	/**
	 * Handle to TSK Case database
	 */
	public static class CaseDbHandle {

		private long caseDbPointer;
		//map concat. image paths to cached image handle
		private static final Map<String, Long> imageHandleCache = new HashMap<String, Long>();
		//map image and offsets to cached fs handle
		private static final Map<Long, Map<Long, Long>> fsHandleCache = new HashMap<Long, Map<Long, Long>>();

		private CaseDbHandle(long pointer) {
			this.caseDbPointer = pointer;
		}

		/**
		 * Close the case database
		 *
		 * @throws TskCoreException exception thrown if critical error occurs
		 * within TSK
		 */
		void free() throws TskCoreException {
			SleuthkitJNI.closeCaseDbNat(caseDbPointer);
		}

		/**
		 * Clear currently set lookup databases within TSK
		 *
		 * @throws TskCoreException exception thrown if critical error occurs
		 * within TSK
		 */
		void clearLookupDatabases() throws TskCoreException {
			closeDbLookupsNat();
		}

		/**
		 * Set the NSRL database
		 *
		 * @param path The path to the database
		 * @return a handle for that database
		 */
		int setNSRLDatabase(String path) throws TskCoreException {
			return setDbNSRLNat(path);
		}

		/**
		 * Add the known bad database
		 *
		 * @param path The path to the database
		 * @return a handle for that database
		 */
		int addKnownBadDatabase(String path) throws TskCoreException {
			return addDbKnownBadNat(path);
		}

		/**
		 * Start the process of adding a disk image to the case
		 *
		 * @param timezone Timezone that image was from
		 * @param processUnallocSpace true if to process unallocated space in
		 * the image
		 * @param noFatFsOrphans true if to skip processing of orphans on FAT
		 * filesystems
		 *
		 * @return Object that can be used to manage the process.
		 */
		AddImageProcess initAddImageProcess(String timezone, boolean processUnallocSpace, boolean noFatFsOrphans) {
			return new AddImageProcess(timezone, processUnallocSpace, noFatFsOrphans);
		}

		/**
		 * Encapsulates a multi-step process to add a disk image. Adding a disk
		 * image takes a while and this object has objects to manage that
		 * process. Methods within this class are intended to be threadsafe.
		 */
		public class AddImageProcess {

			private String timezone;
			private boolean processUnallocSpace;
			private boolean noFatFsOrphans;
			private volatile long autoDbPointer;

			private AddImageProcess(String timezone, boolean processUnallocSpace, boolean noFatFsOrphans) {
				this.timezone = timezone;
				this.processUnallocSpace = processUnallocSpace;
				this.noFatFsOrphans = noFatFsOrphans;
				autoDbPointer = 0;
			}

			/**
			 * Start the process of adding an image to the case database. MUST
			 * call either commit() or revert() after calling run().
			 *
			 * @param imgPath Full path(s) to the image file(s).
			 * @throws TskCoreException exception thrown if critical error
			 * occurs within TSK
			 * @throws TskDataException exception thrown if non-critical error
			 * occurs within TSK (should be OK to continue)
			 */
			public void run(String[] imgPath) throws TskCoreException, TskDataException {
				if (autoDbPointer != 0) {
					throw new TskCoreException("AddImgProcess:run: AutoDB pointer is already set");
				}

				synchronized (this) {
					autoDbPointer = initAddImgNat(caseDbPointer, timezoneLongToShort(timezone), processUnallocSpace, noFatFsOrphans);
				}
				if (autoDbPointer == 0) {
					//additional check in case initAddImgNat didn't throw exception
					throw new TskCoreException("AddImgProcess::run: AutoDB pointer is NULL after initAddImgNat");
				}
				runAddImgNat(autoDbPointer, imgPath, imgPath.length, timezone);
			}

			/**
			 * Call while run() is executing in another thread to prematurely
			 * halt the process. Must call revert() in the other thread once the
			 * stopped run() returns.
			 *
			 * @throws TskCoreException exception thrown if critical error
			 * occurs within TSK
			 */
			public void stop() throws TskCoreException {
				if (autoDbPointer == 0) {
					throw new TskCoreException("AddImgProcess::stop: AutoDB pointer is NULL");
				}

				stopAddImgNat(autoDbPointer);
			}

			/**
			 * Rollback a process that has already been run(), reverting the
			 * database. This releases the C++ object and no additional
			 * operations can be performed. This method is threadsafe.
			 *
			 * @throws TskCoreException exception thrown if critical error
			 * occurs within TSK
			 */
			public synchronized void revert() throws TskCoreException {
				if (autoDbPointer == 0) {
					throw new TskCoreException("AddImgProcess::revert: AutoDB pointer is NULL");
				}

				revertAddImgNat(autoDbPointer);
				// the native code deleted the object
				autoDbPointer = 0;
			}

			/**
			 * Finish off a process that has already been run(), closing the
			 * transaction and committing the new image data to the database.
			 *
			 * @return The id of the image that was added. This releases the C++
			 * object and no additional operations can be performed. This method
			 * is threadsafe.
			 *
			 * @throws TskCoreException exception thrown if critical error
			 * occurs within TSK
			 */
			public synchronized long commit() throws TskCoreException {
				if (autoDbPointer == 0) {
					throw new TskCoreException("AddImgProcess::commit: AutoDB pointer is NULL");
				}

				long id = commitAddImgNat(autoDbPointer);
				// the native code deleted the object
				autoDbPointer = 0;
				return id;
			}

			/**
			 * Gets the directory currently being processed by TSK. This method
			 * is threadsafe.
			 *
			 * @return the currently processing directory
			 */
			public synchronized String currentDirectory() {
				return autoDbPointer == 0 ? "NO_INFO" : getCurDirNat(autoDbPointer);
			}
		}
	}

	/**
	 * Creates a new case database. Must call .free() on CaseDbHandle instance
	 * when done.
	 *
	 * @param path Location to create the database at.
	 * @return Handle for a new TskCaseDb instance.
	 * @throws TskCoreException exception thrown if critical error occurs within
	 * TSK
	 */
	static CaseDbHandle newCaseDb(String path) throws TskCoreException {
		return new CaseDbHandle(newCaseDbNat(path));
	}

	/**
	 * Opens an existing case database. Must call .free() on CaseDbHandle
	 * instance when done.
	 *
	 * @param path Location of the existing database.
	 * @return Handle for a new TskCaseDb instance.
	 * @throws TskCoreException exception thrown if critical error occurs within
	 * TSK
	 */
	static CaseDbHandle openCaseDb(String path) throws TskCoreException {
		return new CaseDbHandle(openCaseDbNat(path));
	}

	/**
	 * get the Sleuth Kit version string
	 *
	 * @return the version string
	 */
	public static String getVersion() {
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
	 *
	 * @param imageFiles the paths to the images
	 * @return the image info pointer
	 * @throws TskCoreException exception thrown if critical error occurs within
	 * TSK
	 */
	public synchronized static long openImage(String[] imageFiles) throws TskCoreException {
		long imageHandle = 0;

		StringBuilder keyBuilder = new StringBuilder();
		for (int i = 0; i < imageFiles.length; ++i) {
			keyBuilder.append(imageFiles[i]);
		}
		final String imageKey = keyBuilder.toString();

		if (CaseDbHandle.imageHandleCache.containsKey(imageKey)) //get from cache
		{
			imageHandle = CaseDbHandle.imageHandleCache.get(imageKey);
		} else {
			//open new handle and cache it
			imageHandle = openImgNat(imageFiles, imageFiles.length);
			CaseDbHandle.fsHandleCache.put(imageHandle, new HashMap<Long, Long>());
			CaseDbHandle.imageHandleCache.put(imageKey, imageHandle);
		}

		return imageHandle;

	}

	/**
	 * Get volume system Handle
	 *
	 * @param imgHandle a handle to previously opened image
	 * @param vsOffset byte offset in the image to the volume system (usually 0)
	 * @return pointer to a vsHandle structure in the sleuthkit
	 * @throws TskCoreException exception thrown if critical error occurs within
	 * TSK
	 */
	public static long openVs(long imgHandle, long vsOffset) throws TskCoreException {
		return openVsNat(imgHandle, vsOffset);
	}

	//get pointers
	/**
	 * Get volume Handle
	 *
	 * @param vsHandle pointer to the volume system structure in the sleuthkit
	 * @param volId id of the volume
	 * @return pointer to a volHandle structure in the sleuthkit
	 * @throws TskCoreException exception thrown if critical error occurs within
	 * TSK
	 */
	public static long openVsPart(long vsHandle, long volId) throws TskCoreException {
		//returned long is ptr to vs Handle object in tsk
		return openVolNat(vsHandle, volId);
	}

	/**
	 * Get file system Handle Opened handle is cached (transparently) so it does
	 * not need be reopened next time for the duration of the application
	 *
	 * @param imgHandle pointer to imgHandle in sleuthkit
	 * @param fsOffset byte offset to the file system
	 * @return pointer to a fsHandle structure in the sleuthkit
	 * @throws TskCoreException exception thrown if critical error occurs within
	 * TSK
	 */
	public synchronized static long openFs(long imgHandle, long fsOffset) throws TskCoreException {
		long fsHandle = 0;
		final Map<Long, Long> imgOffSetToFsHandle = CaseDbHandle.fsHandleCache.get(imgHandle);
		if (imgOffSetToFsHandle.containsKey(fsOffset)) {
			//return cached
			fsHandle = imgOffSetToFsHandle.get(fsOffset);
		} else {
			fsHandle = openFsNat(imgHandle, fsOffset);
			//cache it
			imgOffSetToFsHandle.put(fsOffset, fsHandle);
		}
		return fsHandle;
	}

	/**
	 * Get file Handle
	 *
	 * @param fsHandle fsHandle pointer in the sleuthkit
	 * @param fileId id of the file
	 * @param attrType file attribute type to open
	 * @param attrId file attribute id to open
	 * @return pointer to a file structure in the sleuthkit
	 * @throws TskCoreException exception thrown if critical error occurs within
	 * TSK
	 */
	public static long openFile(long fsHandle, long fileId, TSK_FS_ATTR_TYPE_ENUM attrType, int attrId) throws TskCoreException {
		return openFileNat(fsHandle, fileId, attrType.getValue(), attrId);
	}

	//do reads
	/**
	 * reads data from an image
	 *
	 * @param imgHandle
	 * @param readBuffer buffer to read to
	 * @param offset byte offset in the image to start at
	 * @param len amount of data to read
	 * @return the number of characters read, or -1 if the end of the stream has
	 * been reached
	 * @throws TskCoreException exception thrown if critical error occurs within
	 * TSK
	 */
	public static int readImg(long imgHandle, byte[] readBuffer, long offset, long len) throws TskCoreException {
		//returned byte[] is the data buffer
		return readImgNat(imgHandle, readBuffer, offset, len);
	}

	/**
	 * reads data from an volume system
	 *
	 * @param vsHandle pointer to a volume system structure in the sleuthkit
	 * @param readBuffer buffer to read to
	 * @param offset sector offset in the image to start at
	 * @param len amount of data to read
	 * @return the number of characters read, or -1 if the end of the stream has
	 * been reached
	 * @throws TskCoreException exception thrown if critical error occurs within
	 * TSK
	 */
	public static int readVs(long vsHandle, byte[] readBuffer, long offset, long len) throws TskCoreException {
		return readVsNat(vsHandle, readBuffer, offset, len);
	}

	/**
	 * reads data from an volume
	 *
	 * @param volHandle pointer to a volume structure in the sleuthkit
	 * @param readBuffer buffer to read to
	 * @param offset byte offset in the image to start at
	 * @param len amount of data to read
	 * @return the number of characters read, or -1 if the end of the stream has
	 * been reached
	 * @throws TskCoreException exception thrown if critical error occurs within
	 * TSK
	 */
	public static int readVsPart(long volHandle, byte[] readBuffer, long offset, long len) throws TskCoreException {
		//returned byte[] is the data buffer
		return readVolNat(volHandle, readBuffer, offset, len);
	}

	/**
	 * reads data from an file system
	 *
	 * @param fsHandle pointer to a file system structure in the sleuthkit
	 * @param readBuffer buffer to read to
	 * @param offset byte offset in the image to start at
	 * @param len amount of data to read
	 * @return the number of characters read, or -1 if the end of the stream has
	 * been reached
	 * @throws TskCoreException exception thrown if critical error occurs within
	 * TSK
	 */
	public static int readFs(long fsHandle, byte[] readBuffer, long offset, long len) throws TskCoreException {
		//returned byte[] is the data buffer
		return readFsNat(fsHandle, readBuffer, offset, len);
	}

	/**
	 * reads data from an file
	 *
	 * @param fileHandle pointer to a file structure in the sleuthkit
	 * @param readBuffer pre-allocated buffer to read to
	 * @param offset byte offset in the image to start at
	 * @param len amount of data to read
	 * @return the number of characters read, or -1 if the end of the stream has
	 * been reached
	 * @throws TskCoreException exception thrown if critical error occurs within
	 * TSK
	 */
	public static int readFile(long fileHandle, byte[] readBuffer, long offset, long len) throws TskCoreException {
		return readFileNat(fileHandle, readBuffer, offset, len);
	}

	//free pointers
	/**
	 * frees the imgHandle pointer currently does not close the image, until the
	 * application terminates (image handle is cached)
	 *
	 * @param imgHandle to close the image
	 */
	public static void closeImg(long imgHandle) {
		//@@@ TODO close the image handle when Case is closed instead
		//currently the image handle is not being freed, it's cached for duration of the application
		//closeImgNat(imgHandle); 
	}

	/**
	 * frees the vsHandle pointer
	 *
	 * @param vsHandle pointer to volume system structure in sleuthkit
	 */
	public static void closeVs(long vsHandle) {
		closeVsNat(vsHandle);
	}

	/**
	 * frees the fsHandle pointer Currently does not do anything - preserves the
	 * cached object for the duration of the application
	 *
	 * @param fsHandle pointer to file system structure in sleuthkit
	 */
	public static void closeFs(long fsHandle) {
		//@@@ TODO close the fs handle when Case is closed instead
		//currently the fs handle is not being freed, it's cached for duration of the application
		//closeFsNat(fsHandle);
	}

	/**
	 * frees the fileHandle pointer
	 *
	 * @param fileHandle pointer to file structure in sleuthkit
	 */
	public static void closeFile(long fileHandle) {
		closeFileNat(fileHandle);
	}

	/**
	 * Create an index for the given database path.
	 *
	 * @param dbPath The path to the database
	 * @throws TskCoreException if a critical error occurs within TSK core
	 */
	public static void createLookupIndex(String dbPath) throws TskCoreException {
		createLookupIndexNat(dbPath);
	}

	/**
	 * Check if an index exists for the given database path.
	 *
	 * @param dbPath
	 * @return true if index exists
	 * @throws TskCoreException if a critical error occurs within TSK core
	 */
	public static boolean lookupIndexExists(String dbPath) throws TskCoreException {
		return lookupIndexExistsNat(dbPath);
	}

	/**
	 * Set the NSRL database
	 *
	 * @param path The path to the database
	 * @return a handle for that database
	 * @throws TskCoreException if a critical error occurs within TSK core
	 */
	public static int setNSRLDatabase(String path) throws TskCoreException {
		return setDbNSRLNat(path);
	}

	/**
	 * Add the known bad database
	 *
	 * @param path The path to the database
	 * @return a handle for that database
	 * @throws TskCoreException if a critical error occurs within TSK core
	 */
	public static int addKnownBadDatabase(String path) throws TskCoreException {
		return addDbKnownBadNat(path);
	}

	/**
	 * Get the name of the database
	 *
	 * @param path The path to the database
	 * @throws TskCoreException if a critical error occurs within TSK core
	 */
	public static String getDatabaseName(String path) throws TskCoreException {
		return getDbName(path);
	}

	/**
	 * Look up the given hash in the NSRL database
	 *
	 * @param hash
	 * @return the status of the hash in the NSRL
	 * @throws TskCoreException if a critical error occurs within TSK core
	 */
	public static TskData.FileKnown nsrlHashLookup(String hash) throws TskCoreException {
		return TskData.FileKnown.valueOf((byte) nsrlDbLookup(hash));
	}

	/**
	 * Look up the given hash in the known bad database
	 *
	 * @param hash
	 * @param dbHandle previously opened hash db handle
	 * @return the status of the hash in the known bad database
	 * @throws TskCoreException if a critical error occurs within TSK core
	 */
	public static TskData.FileKnown knownBadHashLookup(String hash, int dbHandle) throws TskCoreException {
		return TskData.FileKnown.valueOf((byte) knownBadDbLookup(hash, dbHandle));
	}

	/**
	 * Get the size of the index of the given database
	 *
	 * @param path the path to the database
	 * @return the size of the index or -1 if it doesn't exist
	 * @throws TskCoreException
	 */
	public static int getIndexSize(String path) throws TskCoreException {
		return getIndexSizeNat(path);
	}

	/**
	 * Convert this timezone from long to short form
	 * Convert timezoneLongForm passed in from long to short form
	 *
	 * @param timezoneLongForm the long form (e.g., America/New_York)
	 * @return the short form (e.g., EST5EDT) string representation, or an empty string if
	 * empty long form was passed in
	 */
	private static String timezoneLongToShort(String timezoneLongForm) {
		if (timezoneLongForm  == null || timezoneLongForm.isEmpty()) {
			return "";
		}
		
		String timezoneShortForm = "";
		TimeZone zone = TimeZone.getTimeZone(timezoneLongForm);
		int offset = zone.getRawOffset() / 1000;
		int hour = offset / 3600;
		int min = (offset % 3600) / 60;
		DateFormat dfm = new SimpleDateFormat("z");
		dfm.setTimeZone(zone);
		boolean hasDaylight = zone.useDaylightTime();
		String first = dfm.format(new GregorianCalendar(2010, 1, 1).getTime()).substring(0, 3); // make it only 3 letters code
		String second = dfm.format(new GregorianCalendar(2011, 6, 6).getTime()).substring(0, 3); // make it only 3 letters code
		int mid = hour * -1;
		timezoneShortForm = first + Integer.toString(mid);
		if (min != 0) {
			timezoneShortForm = timezoneShortForm + ":" + (min < 10 ? "0" : "") + Integer.toString(min);
		}
		if (hasDaylight) {
			timezoneShortForm = timezoneShortForm + second;
		}
		return timezoneShortForm;
	}

	/**
	 * Get size of a device (physical, logical device, image) pointed to by
	 * devPath
	 *
	 * @param devPath device path pointing to the device
	 * @return size of the device in bytes
	 * @throws TskCoreException exception thrown if the device size could not be
	 * queried
	 */
	public static long findDeviceSize(String devPath) throws TskCoreException {
		return findDeviceSizeNat(devPath);
	}
}
