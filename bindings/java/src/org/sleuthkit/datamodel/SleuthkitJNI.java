/*
 * Sleuth Kit Data Model
 *
 * Copyright 2011-2016 Basis Technology Corp.
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

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.List;
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

	// Lock used to synchronize image and file system cache
	private static final Object cacheLock = new Object();

	//Native methods
	private static native String getVersionNat();

	private static native void startVerboseLoggingNat(String logPath);

	//database
	private static native long newCaseDbNat(String dbPath) throws TskCoreException;

	private static native long newCaseDbMultiNat(String hostNameOrIP, String portNumber, String userName, String password, int dbTypeOrdinal, String databaseName);

	private static native long openCaseDbMultiNat(String hostNameOrIP, String portNumber, String userName, String password, int dbTypeOrdinal, String databaseName);

	private static native long openCaseDbNat(String path) throws TskCoreException;

	private static native void closeCaseDbNat(long db) throws TskCoreException;

	//hash-lookup database   
	private static native int hashDbOpenNat(String hashDbPath) throws TskCoreException;

	private static native int hashDbNewNat(String hashDbPath) throws TskCoreException;

	private static native int hashDbBeginTransactionNat(int dbHandle) throws TskCoreException;

	private static native int hashDbCommitTransactionNat(int dbHandle) throws TskCoreException;

	private static native int hashDbRollbackTransactionNat(int dbHandle) throws TskCoreException;

	private static native int hashDbAddEntryNat(String filename, String hashMd5, String hashSha1, String hashSha256, String comment, int dbHandle) throws TskCoreException;

	private static native boolean hashDbIsUpdateableNat(int dbHandle);

	private static native boolean hashDbIsReindexableNat(int dbHandle);

	private static native String hashDbPathNat(int dbHandle);

	private static native String hashDbIndexPathNat(int dbHandle);

	private static native String hashDbGetDisplayName(int dbHandle) throws TskCoreException;

	private static native void hashDbCloseAll() throws TskCoreException;

	private static native void hashDbClose(int dbHandle) throws TskCoreException;

	private static native void hashDbCreateIndexNat(int dbHandle) throws TskCoreException;

	private static native boolean hashDbIndexExistsNat(int dbHandle) throws TskCoreException;

	private static native boolean hashDbIsIdxOnlyNat(int dbHandle) throws TskCoreException;

	private static native boolean hashDbLookup(String hash, int dbHandle) throws TskCoreException;

	private static native HashHitInfo hashDbLookupVerbose(String hash, int dbHandle) throws TskCoreException;

	//add image
	private static native long initAddImgNat(long db, String timezone, boolean addUnallocSpace, boolean noFatFsOrphans) throws TskCoreException;

	private static native void runAddImgNat(long process, String deviceId, String[] imgPath, int splits, String timezone) throws TskCoreException, TskDataException; // if runAddImg finishes without being stopped, revertAddImg or commitAddImg MUST be called

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

	private static native int saveFileMetaDataTextNat(long fileHandle, String fileName) throws TskCoreException;

	//close functions
	private static native void closeImgNat(long imgHandle);

	private static native void closeVsNat(long vsHandle);

	private static native void closeFsNat(long fsHandle);

	private static native void closeFileNat(long fileHandle);

	//util functions
	private static native long findDeviceSizeNat(String devicePath) throws TskCoreException;

	private static native String getCurDirNat(long process);

	//Linked library loading
	static {
		LibraryUtils.loadSleuthkitJNI();
	}

	private SleuthkitJNI() {

	}
	
	

	/**
	 * Handle to TSK Case database
	 */
	public static class CaseDbHandle {

		private final long caseDbPointer;
		//map concat. image paths to cached image handle
		private static final Map<String, Long> imageHandleCache = new HashMap<String, Long>();
		//map image and offsets to cached fs handle
		private static final Map<Long, Map<Long, Long>> fsHandleCache = new HashMap<Long, Map<Long, Long>>();

		private CaseDbHandle(long pointer) {
			this.caseDbPointer = pointer;
		}

		/**
		 * Close the case database as well as close all open image and file
		 * system handles.
		 *
		 * @throws TskCoreException exception thrown if critical error occurs
		 *                          within TSK
		 */
		void free() throws TskCoreException {
			synchronized (cacheLock) {
				// close all file system handles 
				// loop over all images for which we have opened a file system
				for (Map<Long, Long> imageToFsMap : fsHandleCache.values()) {
					// for each image loop over all file systems open as part of that image
					for (Long fsHandle : imageToFsMap.values()) {
						// close the file system handle
						closeFsNat(fsHandle);
					}
				}

				// close all open image handles
				for (Long imageHandle : imageHandleCache.values()) {
					closeImgNat(imageHandle);
				}

				// clear both maps
				/*
				 * NOTE: it is possible to close a case while ingest is going in
				 * the background. In this scenario it is possible for an igest
				 * module to try to read from source image. If this happens,
				 * image will be re-opened in a normal manner.
				 */
				fsHandleCache.clear();
				imageHandleCache.clear();
			}

			SleuthkitJNI.closeCaseDbNat(caseDbPointer);
		}

		/**
		 * ****************** Hash Database Methods **********************
		 */
		/**
		 * Start the process of adding a disk image to the case
		 *
		 * @param timezone        Timezone that image was from
		 * @param addUnallocSpace true to create virtual files for unallocated
		 *                        space the image
		 * @param noFatFsOrphans  true if to skip processing of orphans on FAT
		 *                        filesystems
		 *
		 * @return Object that can be used to manage the process.
		 */
		AddImageProcess initAddImageProcess(String timezone, boolean addUnallocSpace, boolean noFatFsOrphans) {
			return new AddImageProcess(timezone, addUnallocSpace, noFatFsOrphans);
		}

		/**
		 * Encapsulates a multi-step process to add a disk image. Adding a disk
		 * image takes a while and this object has objects to manage that
		 * process. Methods within this class are intended to be threadsafe.
		 */
		public class AddImageProcess {

			private final String timezone;
			private final boolean addUnallocSpace;
			private final boolean noFatFsOrphans;
			private volatile long autoDbPointer;

			private AddImageProcess(String timezone, boolean addUnallocSpace, boolean noFatFsOrphans) {
				this.timezone = timezone;
				this.addUnallocSpace = addUnallocSpace;
				this.noFatFsOrphans = noFatFsOrphans;
				autoDbPointer = 0;
			}

			/**
			 * Start the process of adding an image to the case database. MUST
			 * call either commit() or revert() after calling run().
			 *
			 * @param imageFilePaths Full path(s) to the image file(s).
			 *
			 * @throws TskCoreException if a critical error occurs within TSK
			 * @throws TskDataException if a non-critical error occurs within
			 *                          TSK (should be OK to continue)
			 * @deprecated Use run(String dataSourceId, String[] imageFilePaths)
			 * instead
			 */
			@Deprecated
			public void run(String[] imageFilePaths) throws TskCoreException, TskDataException {
				run(null, imageFilePaths);
			}

			/**
			 * Start the process of adding an image to the case database. MUST
			 * call either commit() or revert() after calling run().
			 *
			 * @param deviceId       An ASCII-printable identifier for the
			 *                       device associated with a data source that
			 *                       is intended to be unique across multiple
			 *                       cases (e.g., a UUID).
			 * @param imageFilePaths Full paths to the image files.
			 *
			 * @throws TskCoreException if a critical error occurs within TSK
			 * @throws TskDataException if a non-critical error occurs within
			 *                          TSK (should be OK to continue)
			 */
			public void run(String deviceId, String[] imageFilePaths) throws TskCoreException, TskDataException {
				if (autoDbPointer != 0) {
					throw new TskCoreException("AddImgProcess:run: AutoDB pointer is already set");
				}

				synchronized (this) {
					autoDbPointer = initAddImgNat(caseDbPointer, timezoneLongToShort(timezone), addUnallocSpace, noFatFsOrphans);
				}
				if (autoDbPointer == 0) {
					//additional check in case initAddImgNat didn't throw exception
					throw new TskCoreException("AddImgProcess::run: AutoDB pointer is NULL after initAddImgNat");
				}
				runAddImgNat(autoDbPointer, deviceId, imageFilePaths, imageFilePaths.length, timezone);
			}

			/**
			 * Call while run() is executing in another thread to prematurely
			 * halt the process. Must call revert() in the other thread once the
			 * stopped run() returns.
			 *
			 * @throws TskCoreException exception thrown if critical error
			 *                          occurs within TSK
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
			 *                          occurs within TSK
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
			 *         object and no additional operations can be performed.
			 *         This method is threadsafe.
			 *
			 * @throws TskCoreException exception thrown if critical error
			 *                          occurs within TSK
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
				return autoDbPointer == 0 ? "NO_INFO" : getCurDirNat(autoDbPointer); //NON-NLS
			}
		}
	}

	/**
	 * Creates a new case database. Must call .free() on CaseDbHandle instance
	 * when done.
	 *
	 * @param path Location to create the database at.
	 *
	 * @return Handle for a new TskCaseDb instance.
	 *
	 * @throws TskCoreException exception thrown if critical error occurs within
	 *                          TSK
	 */
	static CaseDbHandle newCaseDb(String path) throws TskCoreException {
		return new CaseDbHandle(newCaseDbNat(path));
	}

	/**
	 * Creates a new case database. Must call .free() on CaseDbHandle instance
	 * when done.
	 *
	 * @param databaseName the name of the database to create
	 * @param info         the connection info class for the database to create
	 *
	 * @return Handle for a new TskCaseDb instance.
	 *
	 * @throws TskCoreException exception thrown if critical error occurs within
	 *                          TSK
	 */
	static CaseDbHandle newCaseDb(String databaseName, CaseDbConnectionInfo info) throws TskCoreException {
		return new CaseDbHandle(newCaseDbMultiNat(info.getHost(), info.getPort(), info.getUserName(), info.getPassword(), info.getDbType().ordinal(), databaseName));
	}

	/**
	 * Opens an existing case database. Must call .free() on CaseDbHandle
	 * instance when done.
	 *
	 * @param path Location of the existing database.
	 *
	 * @return Handle for a new TskCaseDb instance.
	 *
	 * @throws TskCoreException exception thrown if critical error occurs within
	 *                          TSK
	 */
	static CaseDbHandle openCaseDb(String path) throws TskCoreException {
		return new CaseDbHandle(openCaseDbNat(path));
	}

	/**
	 * Opens an existing case database. Must call .free() on CaseDbHandle
	 * instance when done.
	 *
	 * @param databaseName the name of the database to open
	 * @param info         the connection info class for the database to open
	 *
	 * @return Handle for a new TskCaseDb instance.
	 *
	 * @throws TskCoreException exception thrown if critical error occurs within
	 *                          TSK
	 */
	static CaseDbHandle openCaseDb(String databaseName, CaseDbConnectionInfo info) throws TskCoreException {
		return new CaseDbHandle(openCaseDbMultiNat(info.getHost(), info.getPort(), info.getUserName(), info.getPassword(), info.getDbType().ordinal(), databaseName));
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
	 *
	 * @return the image info pointer
	 *
	 * @throws TskCoreException exception thrown if critical error occurs within
	 *                          TSK
	 */
	public static long openImage(String[] imageFiles) throws TskCoreException {
		long imageHandle;

		StringBuilder keyBuilder = new StringBuilder();
		for (int i = 0; i < imageFiles.length; ++i) {
			keyBuilder.append(imageFiles[i]);
		}
		final String imageKey = keyBuilder.toString();

		synchronized (cacheLock) {
			if (CaseDbHandle.imageHandleCache.containsKey(imageKey)) //get from cache
			{
				imageHandle = CaseDbHandle.imageHandleCache.get(imageKey);
			} else {
				//open new handle and cache it
				imageHandle = openImgNat(imageFiles, imageFiles.length);
				CaseDbHandle.fsHandleCache.put(imageHandle, new HashMap<Long, Long>());
				CaseDbHandle.imageHandleCache.put(imageKey, imageHandle);
			}
		}
		return imageHandle;
	}

	/**
	 * Get volume system Handle
	 *
	 * @param imgHandle a handle to previously opened image
	 * @param vsOffset  byte offset in the image to the volume system (usually
	 *                  0)
	 *
	 * @return pointer to a vsHandle structure in the sleuthkit
	 *
	 * @throws TskCoreException exception thrown if critical error occurs within
	 *                          TSK
	 */
	public static long openVs(long imgHandle, long vsOffset) throws TskCoreException {
		return openVsNat(imgHandle, vsOffset);
	}

	//get pointers
	/**
	 * Get volume Handle
	 *
	 * @param vsHandle pointer to the volume system structure in the sleuthkit
	 * @param volId    id of the volume
	 *
	 * @return pointer to a volHandle structure in the sleuthkit
	 *
	 * @throws TskCoreException exception thrown if critical error occurs within
	 *                          TSK
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
	 * @param fsOffset  byte offset to the file system
	 *
	 * @return pointer to a fsHandle structure in the sleuthkit
	 *
	 * @throws TskCoreException exception thrown if critical error occurs within
	 *                          TSK
	 */
	public static long openFs(long imgHandle, long fsOffset) throws TskCoreException {
		long fsHandle;
		synchronized (cacheLock) {
			final Map<Long, Long> imgOffSetToFsHandle = CaseDbHandle.fsHandleCache.get(imgHandle);
			if (imgOffSetToFsHandle.containsKey(fsOffset)) {
				//return cached
				fsHandle = imgOffSetToFsHandle.get(fsOffset);
			} else {
				fsHandle = openFsNat(imgHandle, fsOffset);
				//cache it
				imgOffSetToFsHandle.put(fsOffset, fsHandle);
			}
		}
		return fsHandle;
	}

	/**
	 * Get file Handle
	 *
	 * @param fsHandle fsHandle pointer in the sleuthkit
	 * @param fileId   id of the file
	 * @param attrType file attribute type to open
	 * @param attrId   file attribute id to open
	 *
	 * @return pointer to a file structure in the sleuthkit
	 *
	 * @throws TskCoreException exception thrown if critical error occurs within
	 *                          TSK
	 */
	public static long openFile(long fsHandle, long fileId, TSK_FS_ATTR_TYPE_ENUM attrType, int attrId) throws TskCoreException {
		/*
		 * NOTE: previously attrId used to be stored in AbstractFile as (signed)
		 * short even though it is stored as uint16 in TSK. In extremely rare
		 * occurances attrId can be larger than what a signed short can hold
		 * (2^15). Changes were made to AbstractFile to store attrId as integer.
		 * However, a depricated method still exists in AbstractFile to get
		 * attrId as short. In that method we convert attribute ids that are
		 * larger than 32K to a negative number. Therefore if encountered, we
		 * need to convert negative attribute id to uint16 which is what TSK is
		 * using to store attribute id.
		 */
		return openFileNat(fsHandle, fileId, attrType.getValue(), convertSignedToUnsigned(attrId));
	}
	
	/**
	 * Converts signed integer to an unsigned integer.
	 *
	 * @param val value to be converter
	 *
	 * @return unsigned integer value
	 */
	private static int convertSignedToUnsigned(int val) {
		if (val >= 0) {
			return val;
		}

		return val & 0xffff;	// convert negative value to positive value
	}

	//do reads
	/**
	 * reads data from an image
	 *
	 * @param imgHandle
	 * @param readBuffer buffer to read to
	 * @param offset     byte offset in the image to start at
	 * @param len        amount of data to read
	 *
	 * @return the number of characters read, or -1 if the end of the stream has
	 *         been reached
	 *
	 * @throws TskCoreException exception thrown if critical error occurs within
	 *                          TSK
	 */
	public static int readImg(long imgHandle, byte[] readBuffer, long offset, long len) throws TskCoreException {
		//returned byte[] is the data buffer
		return readImgNat(imgHandle, readBuffer, offset, len);
	}

	/**
	 * reads data from an volume system
	 *
	 * @param vsHandle   pointer to a volume system structure in the sleuthkit
	 * @param readBuffer buffer to read to
	 * @param offset     sector offset in the image to start at
	 * @param len        amount of data to read
	 *
	 * @return the number of characters read, or -1 if the end of the stream has
	 *         been reached
	 *
	 * @throws TskCoreException exception thrown if critical error occurs within
	 *                          TSK
	 */
	public static int readVs(long vsHandle, byte[] readBuffer, long offset, long len) throws TskCoreException {
		return readVsNat(vsHandle, readBuffer, offset, len);
	}

	/**
	 * reads data from an volume
	 *
	 * @param volHandle  pointer to a volume structure in the sleuthkit
	 * @param readBuffer buffer to read to
	 * @param offset     byte offset in the image to start at
	 * @param len        amount of data to read
	 *
	 * @return the number of characters read, or -1 if the end of the stream has
	 *         been reached
	 *
	 * @throws TskCoreException exception thrown if critical error occurs within
	 *                          TSK
	 */
	public static int readVsPart(long volHandle, byte[] readBuffer, long offset, long len) throws TskCoreException {
		//returned byte[] is the data buffer
		return readVolNat(volHandle, readBuffer, offset, len);
	}

	/**
	 * reads data from an file system
	 *
	 * @param fsHandle   pointer to a file system structure in the sleuthkit
	 * @param readBuffer buffer to read to
	 * @param offset     byte offset in the image to start at
	 * @param len        amount of data to read
	 *
	 * @return the number of characters read, or -1 if the end of the stream has
	 *         been reached
	 *
	 * @throws TskCoreException exception thrown if critical error occurs within
	 *                          TSK
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
	 * @param offset     byte offset in the image to start at
	 * @param len        amount of data to read
	 *
	 * @return the number of characters read, or -1 if the end of the stream has
	 *         been reached
	 *
	 * @throws TskCoreException exception thrown if critical error occurs within
	 *                          TSK
	 */
	public static int readFile(long fileHandle, byte[] readBuffer, long offset, long len) throws TskCoreException {
		return readFileNat(fileHandle, readBuffer, offset, len);
	}

	/**
	 * Get human readable (some what) details about a file. This is the same as
	 * the 'istat' TSK tool
	 *
	 * @param fileHandle pointer to file structure in the sleuthkit
	 *
	 * @return text
	 *
	 * @throws TskCoreException if errors occurred
	 */
	public static List<String> getFileMetaDataText(long fileHandle) throws TskCoreException {
		try {
			java.io.File tmp = java.io.File.createTempFile("tsk", ".txt");

			saveFileMetaDataTextNat(fileHandle, tmp.getAbsolutePath());

			FileReader fr = new FileReader(tmp.getAbsolutePath());
			BufferedReader textReader = new BufferedReader(fr);

			List<String> lines = new ArrayList<String>();
			while (true) {
				String line = textReader.readLine();
				if (line == null) {
					break;
				}
				lines.add(line);
			}
			textReader.close();
			fr.close();
			tmp.delete();
			return lines;
		} catch (IOException ex) {
			throw new TskCoreException("Error reading istat output: " + ex.getLocalizedMessage());
		}
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
	 * Create an index for a hash database.
	 *
	 * @param dbHandle A hash database handle.
	 *
	 * @throws TskCoreException if a critical error occurs within TSK core
	 */
	public static void createLookupIndexForHashDatabase(int dbHandle) throws TskCoreException {
		hashDbCreateIndexNat(dbHandle);
	}

	/**
	 * Check if an index exists for a hash database.
	 *
	 * @param dbHandle A hash database handle.
	 *
	 * @return true if index exists
	 *
	 * @throws TskCoreException if a critical error occurs within TSK core
	 */
	public static boolean hashDatabaseHasLookupIndex(int dbHandle) throws TskCoreException {
		return hashDbIndexExistsNat(dbHandle);
	}

	/**
	 * hashDatabaseCanBeReindexed
	 *
	 * @param dbHandle previously opened hash db handle
	 *
	 * @return Does this database have a source database that is different than
	 *         the index?
	 *
	 * @throws TskCoreException if a critical error occurs within TSK core
	 */
	public static boolean hashDatabaseCanBeReindexed(int dbHandle) throws TskCoreException {
		return hashDbIsReindexableNat(dbHandle);
	}

	/**
	 * getHashDatabasePath
	 *
	 * @param dbHandle previously opened hash db handle
	 *
	 * @return Hash db file path
	 *
	 * @throws TskCoreException if a critical error occurs within TSK core
	 */
	public static String getHashDatabasePath(int dbHandle) throws TskCoreException {
		return hashDbPathNat(dbHandle);
	}

	/**
	 * getHashDatabaseIndexPath
	 *
	 * @param dbHandle previously opened hash db handle
	 *
	 * @return Index file path
	 *
	 * @throws TskCoreException if a critical error occurs within TSK core
	 */
	public static String getHashDatabaseIndexPath(int dbHandle) throws TskCoreException {
		return hashDbIndexPathNat(dbHandle);
	}

	public static int openHashDatabase(String path) throws TskCoreException {
		return hashDbOpenNat(path);
	}

	/**
	 * Creates a hash database. Will be of the default TSK hash database type.
	 *
	 * @param path The path to the database
	 *
	 * @return a handle for that database
	 *
	 * @throws TskCoreException if a critical error occurs within TSK core
	 */
	public static int createHashDatabase(String path) throws TskCoreException {
		return hashDbNewNat(path);
	}

	/**
	 * Close the currently open lookup databases. Resets the handle counting.
	 *
	 * @throws TskCoreException exception thrown if critical error occurs within
	 *                          TSK
	 */
	public static void closeAllHashDatabases() throws TskCoreException {
		hashDbCloseAll();
	}

	/**
	 * Close a particular open lookup database. Existing handles are not
	 * affected.
	 *
	 * @throws TskCoreException exception thrown if critical error occurs within
	 *                          TSK
	 */
	public static void closeHashDatabase(int dbHandle) throws TskCoreException {
		hashDbClose(dbHandle);
	}

	/**
	 * Get the name of the database
	 *
	 * @param dbHandle previously opened hash db handle
	 *
	 * @throws TskCoreException if a critical error occurs within TSK core
	 */
	public static String getHashDatabaseDisplayName(int dbHandle) throws TskCoreException {
		return hashDbGetDisplayName(dbHandle);
	}

	/**
	 * Lookup the given hash value and get basic answer
	 *
	 * @param hash     Hash value to search for
	 * @param dbHandle Handle of database to lookup in.
	 *
	 * @return True if hash was found in database.
	 *
	 * @throws TskCoreException
	 */
	public static boolean lookupInHashDatabase(String hash, int dbHandle) throws TskCoreException {
		return hashDbLookup(hash, dbHandle);
	}

	/**
	 * Lookup hash value in DB and return details on results (more time
	 * consuming than basic lookup)
	 *
	 * @param hash     Hash value to search for
	 * @param dbHandle Handle of database to lookup in.
	 *
	 * @return Details on hash if it was in DB or null if it was not found.
	 *
	 * @throws TskCoreException
	 */
	public static HashHitInfo lookupInHashDatabaseVerbose(String hash, int dbHandle) throws TskCoreException {
		return hashDbLookupVerbose(hash, dbHandle);
	}

	/**
	 * Adds a hash value to a hash database.
	 *
	 * @param filename Name of file (can be null)
	 * @param md5      Text of MD5 hash (can be null)
	 * @param sha1     Text of SHA1 hash (can be null)
	 * @param sha256   Text of SHA256 hash (can be null)
	 * @param comment  A comment (can be null)
	 * @param dbHandle Handle to DB
	 *
	 * @throws TskCoreException
	 */
	public static void addToHashDatabase(String filename, String md5, String sha1, String sha256, String comment, int dbHandle) throws TskCoreException {
		hashDbAddEntryNat(filename, md5, sha1, sha256, comment, dbHandle);
	}

	public static void addToHashDatabase(List<HashEntry> hashes, int dbHandle) throws TskCoreException {
		hashDbBeginTransactionNat(dbHandle);
		try {
			for (HashEntry entry : hashes) {
				hashDbAddEntryNat(entry.getFileName(), entry.getMd5Hash(), entry.getSha1Hash(), entry.getSha256Hash(), entry.getComment(), dbHandle);
			}
			hashDbCommitTransactionNat(dbHandle);
		} catch (TskCoreException ex) {
			try {
				hashDbRollbackTransactionNat(dbHandle);
			} catch (TskCoreException ex2) {
				ex2.initCause(ex);
				throw ex2;
			}
			throw ex;
		}
	}

	public static boolean isUpdateableHashDatabase(int dbHandle) throws TskCoreException {
		return hashDbIsUpdateableNat(dbHandle);
	}

	public static boolean hashDatabaseIsIndexOnly(int dbHandle) throws TskCoreException {
		return hashDbIsIdxOnlyNat(dbHandle);
	}

	/**
	 * Convert this timezone from long to short form Convert timezoneLongForm
	 * passed in from long to short form
	 *
	 * @param timezoneLongForm the long form (e.g., America/New_York)
	 *
	 * @return the short form (e.g., EST5EDT) string representation, or an empty
	 *         string if empty long form was passed in
	 */
	private static String timezoneLongToShort(String timezoneLongForm) {
		if (timezoneLongForm == null || timezoneLongForm.isEmpty()) {
			return "";
		}

		String timezoneShortForm;
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
			timezoneShortForm += second;
		}
		return timezoneShortForm;
	}

	/**
	 * Get size of a device (physical, logical device, image) pointed to by
	 * devPath
	 *
	 * @param devPath device path pointing to the device
	 *
	 * @return size of the device in bytes
	 *
	 * @throws TskCoreException exception thrown if the device size could not be
	 *                          queried
	 */
	public static long findDeviceSize(String devPath) throws TskCoreException {
		return findDeviceSizeNat(devPath);
	}
}
