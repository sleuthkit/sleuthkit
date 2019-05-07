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
import java.util.Arrays;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;
import java.util.UUID;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import org.sleuthkit.datamodel.TskData.TSK_FS_ATTR_TYPE_ENUM;

/**
 * A utility class that provides a interface to the SleuthKit via JNI. Supports
 * case management, add image process, reading data off content objects Setting
 * up Hash database parameters and updating / reading values
 *
 * Caches image and filesystem handles and reuses them for the duration of the
 * application
 */
public class SleuthkitJNI {

	/**
	 * Lock to protect against the TSK data structures being closed while
	 * another thread is in the C++ code. Do not use this lock after obtaining
	 * HandleCache.cacheLock. Additionally, the only code that should acquire
	 * the write lock is CaseDbHandle.free().
	 */
	private static final ReadWriteLock tskLock = new ReentrantReadWriteLock();

	/*
	 * Loads the SleuthKit libraries.
	 */
	static {
		LibraryUtils.loadSleuthkitJNI();
	}

	/**
	 * Constructor for the utility class that provides a interface to the
	 * SleuthKit via JNI.
	 */
	private SleuthkitJNI() {
	}

	/**
	 * Utility class to hold the handles for a single case.
	 */
	private static class CaseHandles {
		/*
		 * A SleuthKit image handle cache implemented as a mappng of
		 * concatenated image file paths to image handles.
		 */
		private final Map<String, Long> imageHandleCache = new HashMap<>();

		/*
		 * A SleuthKit file system handles cache implemented as a mapping of
		 * image handles to image offset and file system handle pairs.
		 */
		private final Map<Long, Map<Long, Long>> fsHandleCache = new HashMap<>();

		/*
		 * The collection of open file handles. We will only allow requests
		 * through to the C code if the file handle exists in this collection.
		 */
		private final Set<Long> fileHandleCache = new HashSet<>();

		private final Map<Long, List<Long>> fileSystemToFileHandles = new HashMap<>();
		
		private CaseHandles() {
			// Nothing to do here
		}
	}
	
	/**
	 * Cache of all handles allocated in the JNI layer. Used for: (a) quick
	 * lookup of frequently used handles (e.g. file system and image) (b)
	 * ensuring all handles passed in by clients of SleuthkitJNI are valid. (c)
	 * consistent cleanup of handles on closure.
	 */
	private static class HandleCache {

		/*
		 * A monitor used to guard access to cached Sleuthkit JNI handles.
		 */
		private static final Object cacheLock = new Object();

		private static final Map<Long, CaseHandles> caseHandlesCache = new HashMap<>();

		private static final String INVALID_FILE_HANDLE = "Invalid file handle."; //NON-NLS
		
		/**
		 * Create the empty cache for a new case
		 * 
		 * @param caseDbPointer 
		 */
		private static void createCaseHandleCache(long caseDbPointer) {
			caseHandlesCache.put(caseDbPointer, new CaseHandles());
		}
		
		/**
		 * If there is one case open return its handle.
		 * This is to support deprecated methods that don't have a case parameter.
		 * 
		 * @return the open case pointer
		 * 
		 * @throws TskCoreException If there are no cases open or if multiple cases are open
		 */
		private static long getDefaultCaseDbPointer() throws TskCoreException {
			synchronized (cacheLock) {
				if (caseHandlesCache.keySet().size() > 1) {
					throw new TskCoreException("Can not get default case handle with multiple open cases");
				} else if (caseHandlesCache.keySet().isEmpty()) {
					throw new TskCoreException("Can not get default case handle with no open case");
				}

				return (caseHandlesCache.keySet().iterator().next());
			}
		}
			
		/**
		 * Gets the case handle cache for a given case.
		 * 
		 * @param caseDbPointer
		 * 
		 * @return the case handle cache
		 */
		private static CaseHandles getCaseHandles(long caseDbPointer) {
			synchronized (cacheLock) {
				return caseHandlesCache.get(caseDbPointer);
			}
		}
		
		/**
		 * Removes the case handle cache for a given case.
		 * 
		 * @param caseDbPointer 
		 */
		private static void removeCaseHandlesCache(long caseDbPointer) {
			synchronized (cacheLock) {
				if (caseHandlesCache.containsKey(caseDbPointer)) {
					caseHandlesCache.get(caseDbPointer).fsHandleCache.clear();
					caseHandlesCache.get(caseDbPointer).imageHandleCache.clear();
					caseHandlesCache.get(caseDbPointer).fileHandleCache.clear();
					caseHandlesCache.get(caseDbPointer).fileSystemToFileHandles.clear();
					caseHandlesCache.remove(caseDbPointer);
				}
			}
		}
		
		/**
		 * Searches all the open caches for an image handle.
		 * 
		 * @param imgHandle
		 * 
		 * @return true if the handle is found in any cache, false otherwise
		 */
		private static boolean isImageInAnyCache(long imgHandle) {
			synchronized (cacheLock) {
				for (long caseDbPointer:caseHandlesCache.keySet()) {
					if (caseHandlesCache.get(caseDbPointer).fsHandleCache.keySet().contains(imgHandle)) {
						return true;
					}
				}
				return false;
			}
		}
		
		/**
		 * Add a new file handle to the cache.
		 *
		 * @param fileHandle The new file handle.
		 * @param fsHandle   The file system handle in which the file lives.
		 */
		private static void addFileHandle(long caseDbPointer, long fileHandle, long fsHandle) {
			synchronized (cacheLock) {
				// Add to collection of open file handles.
				getCaseHandles(caseDbPointer).fileHandleCache.add(fileHandle);

				// Add to map of file system to file handles.
				if (getCaseHandles(caseDbPointer).fileSystemToFileHandles.containsKey(fsHandle)) {
					getCaseHandles(caseDbPointer).fileSystemToFileHandles.get(fsHandle).add(fileHandle);
				} else {
					getCaseHandles(caseDbPointer).fileSystemToFileHandles.put(fsHandle, new ArrayList<Long>(Arrays.asList(fileHandle)));
				}
			}
		}

		/**
		 * Removes a file handle from the cache for the given case
		 * 
		 * @param fileHandle
		 * @param skCase     Can be null. If so, the first matching handle will be removed.
		 */
		private static void removeFileHandle(long fileHandle, SleuthkitCase skCase) {
			synchronized (cacheLock) {
				// Remove from collection of open file handles.
				if (skCase != null) {
					getCaseHandles(skCase.getCaseHandle().caseDbPointer).fileHandleCache.remove(fileHandle);
				} else {
					// If we don't know what case the handle is from, delete the first one we find
					for (long caseDbPointer:caseHandlesCache.keySet()) {
						if (caseHandlesCache.get(caseDbPointer).fileHandleCache.contains(fileHandle)) {
							caseHandlesCache.get(caseDbPointer).fileHandleCache.remove(fileHandle);
							return;
						}
					}
				}
			}
		}

		/**
		 * Searches all the open caches for a file handle.
		 * 
		 * @param fileHandle
		 * 
		 * @return true if the handle is found in any cache, false otherwise
		 */
		private static boolean isValidFileHandle(long fileHandle) {
			synchronized (cacheLock) {
				for (long caseDbPointer:caseHandlesCache.keySet()) {
					if (caseHandlesCache.get(caseDbPointer).fileHandleCache.contains(fileHandle)) {
						return true;
					}
				}
				return false;
			}
		}

		private static void closeHandlesAndClearCache(long caseDbPointer) throws TskCoreException {
			synchronized (cacheLock) {
				/*
				 * Close any cached file system handles.
				 */
				for (Map<Long, Long> imageToFsMap : getCaseHandles(caseDbPointer).fsHandleCache.values()) {
					for (Long fsHandle : imageToFsMap.values()) {
						// First close all open file handles for the file system.
						for (Long fileHandle : getCaseHandles(caseDbPointer).fileSystemToFileHandles.get(fsHandle)) {
							closeFile(fileHandle);
						}
						// Then close the file system handle.
						closeFsNat(fsHandle);
					}
				}

				/*
				 * Close any cached image handles.
				 */
				for (Long imageHandle : getCaseHandles(caseDbPointer).imageHandleCache.values()) {
					closeImgNat(imageHandle);
				}

				removeCaseHandlesCache(caseDbPointer);
			}

		}
	}

	/**
	 * Encapsulates a handle to a SleuthKit case database with support for
	 * adding images to the database.
	 */
	public static class CaseDbHandle {

		/*
		 * A pointer to a TskCaseDb object.
		 */
		private final long caseDbPointer;

		/**
		 * Constructs an object that encapsulates a handle to a SleuthKit case
		 * database with support for adding images to the database.
		 *
		 * @param caseDbPointer A pointer to a TskCaseDb object.
		 */
		private CaseDbHandle(long caseDbPointer) {
			this.caseDbPointer = caseDbPointer;
			HandleCache.createCaseHandleCache(caseDbPointer);
		}

		/**
		 * Closes the case database and any open image and file system handles.
		 *
		 * @throws TskCoreException if there is a problem competing the
		 *                          operation.
		 */
		void free() throws TskCoreException {
			tskLock.writeLock().lock();
			try {
				HandleCache.closeHandlesAndClearCache(caseDbPointer);
				SleuthkitJNI.closeCaseDbNat(caseDbPointer);
			} finally {
				tskLock.writeLock().unlock();
			}
		}

		/**
		 * Adds an image to the case database. For finer-grained control of the
		 * process of adding the image, call CaseDbHandle.initAddImageProcess
		 * instead.
		 *
		 * @param deviceObjId      The object id of the device associated with
		 *                         the image.
		 * @param imageFilePaths   The image file paths.
		 * @param timeZone         The time zone for the image.
		 * @param addFileSystems   Pass true to attempt to add file systems
		 *                         within the image to the case database.
		 * @param addUnallocSpace  Pass true to create virtual files for
		 *                         unallocated space. Ignored if addFileSystems
		 *                         is false.
		 * @param skipFatFsOrphans Pass true to skip processing of orphan files
		 *                         for FAT file systems. Ignored if
		 *                         addFileSystems is false.
		 *
		 * @return The object id of the image.
		 *
		 * @throws TskCoreException if there is an error adding the image to
		 *                          case database.
		 */
		long addImageInfo(long deviceObjId, List<String> imageFilePaths, String timeZone, SleuthkitCase skCase) throws TskCoreException {
			try {
				long tskAutoDbPointer = initializeAddImgNat(caseDbPointer, timezoneLongToShort(timeZone), false, false, false);
				runOpenAndAddImgNat(tskAutoDbPointer, UUID.randomUUID().toString(), imageFilePaths.toArray(new String[0]), imageFilePaths.size(), timeZone);
				long id = commitAddImgNat(tskAutoDbPointer);
				skCase.addDataSourceToHasChildrenMap();
				return id;
			} catch (TskDataException ex) {
				throw new TskCoreException("Error adding image to case database", ex);
			}
		}

		/**
		 * Initializes a multi-step process for adding an image to the case
		 * database.
		 *
		 * @param timeZone         The time zone of the image.
		 * @param addUnallocSpace  Pass true to create virtual files for
		 *                         unallocated space.
		 * @param skipFatFsOrphans Pass true to skip processing of orphan files
		 *                         for FAT file systems.
		 * @param imageCopyPath    Path to which a copy of the image should be
		 *                         written. Use the empty string to disable
		 *                         image writing.
		 *
		 * @return An object that can be used to exercise fine-grained control
		 *         of the process of adding the image to the case database.
		 */
		AddImageProcess initAddImageProcess(String timeZone, boolean addUnallocSpace, boolean skipFatFsOrphans, String imageCopyPath, SleuthkitCase skCase) {
			return new AddImageProcess(timeZone, addUnallocSpace, skipFatFsOrphans, imageCopyPath, skCase);
		}

		/**
		 * Encapsulates a multi-step process to add an image to the case
		 * database.
		 */
		public class AddImageProcess {

			private final String timeZone;
			private final boolean addUnallocSpace;
			private final boolean skipFatFsOrphans;
			private final String imageWriterPath;
			private volatile long tskAutoDbPointer;
			private boolean isCanceled;
			private final SleuthkitCase skCase;

			/**
			 * Constructs an object that encapsulates a multi-step process to
			 * add an image to the case database.
			 *
			 * @param timeZone         The time zone of the image.
			 * @param addUnallocSpace  Pass true to create virtual files for
			 *                         unallocated space.
			 * @param skipFatFsOrphans Pass true to skip processing of orphan
			 *                         files for FAT file systems.
			 * @param imageWriterPath  Path that a copy of the image should be
			 *                         written to. Use empty string to disable
			 *                         image writing
			 */
			private AddImageProcess(String timeZone, boolean addUnallocSpace, boolean skipFatFsOrphans, String imageWriterPath, SleuthkitCase skCase) {
				this.timeZone = timeZone;
				this.addUnallocSpace = addUnallocSpace;
				this.skipFatFsOrphans = skipFatFsOrphans;
				this.imageWriterPath = imageWriterPath;
				tskAutoDbPointer = 0;
				this.isCanceled = false;
				this.skCase = skCase;
			}

			/**
			 * Starts the process of adding an image to the case database.
			 * Either AddImageProcess.commit or AddImageProcess.revert MUST be
			 * called after calling AddImageProcess.run.
			 *
			 * @param deviceId       An ASCII-printable identifier for the
			 *                       device associated with the image that
			 *                       should be unique across multiple cases
			 *                       (e.g., a UUID).
			 * @param imageFilePaths Full path(s) to the image file(s).
			 * @param sectorSize     The sector size (use '0' for autodetect).
			 *
			 * @throws TskCoreException if a critical error occurs within the
			 *                          SleuthKit.
			 * @throws TskDataException if a non-critical error occurs within
			 *                          the SleuthKit (should be OK to continue
			 *                          the process)
			 */
			public void run(String deviceId, String[] imageFilePaths, int sectorSize) throws TskCoreException, TskDataException {
				getTSKReadLock();
				try {
					long imageHandle = 0;

					synchronized (this) {
						if (0 != tskAutoDbPointer) {
							throw new TskCoreException("Add image process already started");
						}
						if (!isCanceled) { //with isCanceled being guarded by this it will have the same value everywhere in this synchronized block
							imageHandle = openImage(imageFilePaths, sectorSize, false, caseDbPointer);
							tskAutoDbPointer = initAddImgNat(caseDbPointer, timezoneLongToShort(timeZone), addUnallocSpace, skipFatFsOrphans);
						}
						if (0 == tskAutoDbPointer) {
							throw new TskCoreException("initAddImgNat returned a NULL TskAutoDb pointer");
						}
					}
					if (imageHandle != 0) {
						runAddImgNat(tskAutoDbPointer, deviceId, imageHandle, timeZone, imageWriterPath);
					}
				} finally {
					releaseTSKReadLock();
				}
			}

			/**
			 * Stops the process of adding the image to the case database that
			 * was started by calling AddImageProcess.run.
			 * AddImageProcess.revert should be called after calling
			 * AddImageProcess.stop.
			 *
			 * @throws TskCoreException if a critical error occurs within the
			 *                          SleuthKit.
			 */
			public synchronized void stop() throws TskCoreException {
				getTSKReadLock();
				try {
					isCanceled = true;
					if (tskAutoDbPointer != 0) {
						stopAddImgNat(tskAutoDbPointer);
					}
				} finally {
					releaseTSKReadLock();
				}
			}

			/**
			 * Rolls back the process of adding an image to the case database
			 * that was started by calling AddImageProcess.run.
			 *
			 * @throws TskCoreException if a critical error occurs within the
			 *                          SleuthKit.
			 */
			public synchronized void revert() throws TskCoreException {
				getTSKReadLock();
				try {
					if (tskAutoDbPointer == 0) {
						throw new TskCoreException("AddImgProcess::revert: AutoDB pointer is NULL");
					}

					revertAddImgNat(tskAutoDbPointer);
					// the native code deleted the object
					tskAutoDbPointer = 0;
				} finally {
					releaseTSKReadLock();
				}
			}

			/**
			 * Completes the process of adding an image to the case database
			 * that was started by calling AddImageProcess.run.
			 *
			 * @return The object id of the image that was added.
			 *
			 * @throws TskCoreException if a critical error occurs within the
			 *                          SleuthKit.
			 */
			public synchronized long commit() throws TskCoreException {
				getTSKReadLock();
				try {
					if (tskAutoDbPointer == 0) {
						throw new TskCoreException("AddImgProcess::commit: AutoDB pointer is NULL");
					}

					long id = commitAddImgNat(tskAutoDbPointer);

					skCase.addDataSourceToHasChildrenMap();

					// the native code deleted the object
					tskAutoDbPointer = 0;
					return id;
				} finally {
					releaseTSKReadLock();
				}
			}

			/**
			 * Gets the file system directory currently being processed by the
			 * SleuthKit.
			 *
			 * @return The directory
			 */
			public synchronized String currentDirectory() {
				return tskAutoDbPointer == 0 ? "" : getCurDirNat(tskAutoDbPointer); //NON-NLS
			}

			/**
			 * Starts the process of adding an image to the case database.
			 * Either commit() or revert() MUST be called after calling run().
			 *
			 * @param imageFilePaths Full path(s) to the image file(s).
			 *
			 * @throws TskCoreException if a critical error occurs within the
			 *                          SleuthKit.
			 * @throws TskDataException if a non-critical error occurs within
			 *                          the SleuthKit (should be OK to continue
			 *                          the process)
			 *
			 * @deprecated Use run(String dataSourceId, String[] imageFilePaths)
			 * instead
			 */
			@Deprecated
			public void run(String[] imageFilePaths) throws TskCoreException, TskDataException {
				run(null, imageFilePaths, 0);
			}

			/**
			 * Starts the process of adding an image to the case database.
			 * Either AddImageProcess.commit or AddImageProcess.revert MUST be
			 * called after calling AddImageProcess.run.
			 *
			 * @param deviceId       An ASCII-printable identifier for the
			 *                       device associated with the image that
			 *                       should be unique across multiple cases
			 *                       (e.g., a UUID).
			 * @param imageFilePaths Full path(s) to the image file(s).
			 *
			 * @throws TskCoreException if a critical error occurs within the
			 *                          SleuthKit.
			 * @throws TskDataException if a non-critical error occurs within
			 *                          the SleuthKit (should be OK to continue
			 *                          the process)
			 */
			public void run(String deviceId, String[] imageFilePaths) throws TskCoreException, TskDataException {
				run(deviceId, imageFilePaths, 0);
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
	 *
	 * @param logPath the log file path
	 */
	public static void startVerboseLogging(String logPath) {
		startVerboseLoggingNat(logPath);
	}

	/**
	 * Open the image and return the image info pointer.
	 *
	 * @param imageFiles the paths to the images
	 * @param skCase     the case this image belongs to
	 *
	 * @return the image info pointer
	 *
	 * @throws TskCoreException exception thrown if critical error occurs within
	 *                          TSK
	 */
	public static long openImage(String[] imageFiles, SleuthkitCase skCase) throws TskCoreException {
		if (skCase == null) {
			throw new TskCoreException("SleuthkitCase can not be null");
		}
		return openImage(imageFiles, 0, true, skCase.getCaseHandle().caseDbPointer);
	}

	/**
	 * Open the image with a specified sector size and return the image info
	 * pointer.
	 *
	 * @param imageFiles the paths to the images
	 * @param sSize      the sector size (use '0' for autodetect)
	 * @param skCase     the case this image belongs to
	 *
	 * @return the image info pointer
	 *
	 * @throws TskCoreException exception thrown if critical error occurs within
	 *                          TSK
	 */
	public static long openImage(String[] imageFiles, int sSize, SleuthkitCase skCase) throws TskCoreException {
		if (skCase == null) {
			throw new TskCoreException("SleuthkitCase can not be null");
		}
		return openImage(imageFiles, sSize, true, skCase.getCaseHandle().caseDbPointer);
	}
	
	/**
	 * Open the image and return the image info pointer. This is a temporary
	 * measure to allow ingest of multiple local disks on the same drive letter.
	 * We need to clear the cache to make sure cached data from the first drive
	 * is not used.
	 *
	 * @param imageFiles the paths to the images
	 * @param sSize      the sector size (use '0' for autodetect)
	 * @param useCache   true if the image handle cache should be used, false to
	 *                   always go to TSK to open a fresh copy
	 * @param caseDbPointer The caseDbPointer for this case. Can be null to support deprecated methods.
	 *
	 * @return the image info pointer
	 *
	 * @throws TskCoreException exception thrown if critical error occurs within
	 *                          TSK
	 */
	private static long openImage(String[] imageFiles, int sSize, boolean useCache, Long caseDbPointer) throws TskCoreException {

		getTSKReadLock();
		try {
			long imageHandle;

			StringBuilder keyBuilder = new StringBuilder();
			for (int i = 0; i < imageFiles.length; ++i) {
				keyBuilder.append(imageFiles[i]);
			}
			final String imageKey = keyBuilder.toString();

			synchronized (HandleCache.cacheLock) {
				Long nonNullCaseDbPointer = caseDbPointer;
				if (nonNullCaseDbPointer == null) {
					nonNullCaseDbPointer = HandleCache.getDefaultCaseDbPointer();
				}
				
				// If we're getting a fresh copy, remove any existing cache references
				if (!useCache && HandleCache.getCaseHandles(nonNullCaseDbPointer).imageHandleCache.containsKey(imageKey)) {
					long tempImageHandle = HandleCache.getCaseHandles(nonNullCaseDbPointer).imageHandleCache.get(imageKey);
					HandleCache.getCaseHandles(nonNullCaseDbPointer).fsHandleCache.remove(tempImageHandle);
					HandleCache.getCaseHandles(nonNullCaseDbPointer).imageHandleCache.remove(imageKey);
				}

				if (useCache && HandleCache.getCaseHandles(nonNullCaseDbPointer).imageHandleCache.containsKey(imageKey)) //get from cache
				{
					imageHandle = HandleCache.getCaseHandles(nonNullCaseDbPointer).imageHandleCache.get(imageKey);
				} else {
					//open new handle and cache it
					imageHandle = openImgNat(imageFiles, imageFiles.length, sSize);
					HandleCache.getCaseHandles(nonNullCaseDbPointer).fsHandleCache.put(imageHandle, new HashMap<Long, Long>());
					HandleCache.getCaseHandles(nonNullCaseDbPointer).imageHandleCache.put(imageKey, imageHandle);
				}
			}
			return imageHandle;
		} finally {
			releaseTSKReadLock();
		}
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
		getTSKReadLock();
		try {
			if(! imgHandleIsValid(imgHandle)) {
				throw new TskCoreException("Image handle " + imgHandle + " is closed");
			}
			return openVsNat(imgHandle, vsOffset);
		} finally {
			releaseTSKReadLock();
		}
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
		getTSKReadLock();
		try {
			//returned long is ptr to vs Handle object in tsk
			return openVolNat(vsHandle, volId);
		} finally {
			releaseTSKReadLock();
		}
	}

	/**
	 * Get file system Handle Opened handle is cached (transparently) so it does
	 * not need be reopened next time for the duration of the application
	 *
	 * @param imgHandle pointer to imgHandle in sleuthkit
	 * @param fsOffset  byte offset to the file system
	 * @param skCase    the case containing the file system
	 *
	 * @return pointer to a fsHandle structure in the sleuthkit
	 *
	 * @throws TskCoreException exception thrown if critical error occurs within
	 *                          TSK
	 */
	public static long openFs(long imgHandle, long fsOffset, SleuthkitCase skCase) throws TskCoreException {
		getTSKReadLock();
		try {
			long fsHandle;
			synchronized (HandleCache.cacheLock) {
				long caseDbPointer;
				if (skCase == null) {
					caseDbPointer = HandleCache.getDefaultCaseDbPointer();
				} else {
					caseDbPointer = skCase.getCaseHandle().caseDbPointer;
				}
				final Map<Long, Long> imgOffSetToFsHandle = HandleCache.getCaseHandles(caseDbPointer).fsHandleCache.get(imgHandle);
				if (imgOffSetToFsHandle == null) {
					throw new TskCoreException("Missing image offset to file system handle cache for image handle " + imgHandle);
				}
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
		} finally {
			releaseTSKReadLock();
		}
	}

	/**
	 * Get file Handle
	 *
	 * @param fsHandle fsHandle pointer in the sleuthkit
	 * @param fileId   id of the file
	 * @param attrType file attribute type to open
	 * @param attrId   file attribute id to open
	 * @param skCase   the case associated with this file
	 *
	 * @return pointer to a file structure in the sleuthkit
	 *
	 * @throws TskCoreException exception thrown if critical error occurs within
	 *                          TSK
	 */
	public static long openFile(long fsHandle, long fileId, TSK_FS_ATTR_TYPE_ENUM attrType, int attrId, SleuthkitCase skCase) throws TskCoreException {
		/*
		 * NOTE: previously attrId used to be stored in AbstractFile as (signed)
		 * short even though it is stored as uint16 in TSK. In extremely rare
		 * occurrences attrId can be larger than what a signed short can hold
		 * (2^15). Changes were made to AbstractFile to store attrId as integer.
		 * However, a depricated method still exists in AbstractFile to get
		 * attrId as short. In that method we convert attribute ids that are
		 * larger than 32K to a negative number. Therefore if encountered, we
		 * need to convert negative attribute id to uint16 which is what TSK is
		 * using to store attribute id.
		 */
		getTSKReadLock();
		try {
			long fileHandle = openFileNat(fsHandle, fileId, attrType.getValue(), convertSignedToUnsigned(attrId));
			synchronized (HandleCache.cacheLock) {
				long caseDbPointer;
				if (skCase == null) {
					caseDbPointer = HandleCache.getDefaultCaseDbPointer();
				} else {
					caseDbPointer = skCase.getCaseHandle().caseDbPointer;
				}
				HandleCache.addFileHandle(caseDbPointer, fileHandle, fsHandle);
			}
			return fileHandle;
		} finally {
			releaseTSKReadLock();
		}
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
	
	/**
	 * Test that the given image handle is valid.
	 * @param imgHandle
	 * @return true if it is valid, false otherwise
	 */
	private static boolean imgHandleIsValid(long imgHandle) {
		synchronized(HandleCache.cacheLock) {
			return HandleCache.isImageInAnyCache(imgHandle);
		}
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
		getTSKReadLock();
		try {
			if(! imgHandleIsValid(imgHandle)) {
				throw new TskCoreException("Image handle " + imgHandle + " is closed");
			}
			//returned byte[] is the data buffer
			return readImgNat(imgHandle, readBuffer, offset, len);
		} finally {
			releaseTSKReadLock();
		}
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
		getTSKReadLock();
		try {
			return readVsNat(vsHandle, readBuffer, offset, len);
		} finally {
			releaseTSKReadLock();
		}
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
		getTSKReadLock();
		try {
			//returned byte[] is the data buffer
			return readVolNat(volHandle, readBuffer, offset, len);
		} finally {
			releaseTSKReadLock();
		}
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
		getTSKReadLock();
		try {
			//returned byte[] is the data buffer
			return readFsNat(fsHandle, readBuffer, offset, len);
		} finally {
			releaseTSKReadLock();
		}
	}

	/**
	 * enum used to tell readFileNat whether the offset is from the beginning of
	 * the file or from the beginning of the slack space.
	 */
	private enum TSK_FS_FILE_READ_OFFSET_TYPE_ENUM {
		START_OF_FILE(0),
		START_OF_SLACK(1);

		private final int val;

		TSK_FS_FILE_READ_OFFSET_TYPE_ENUM(int val) {
			this.val = val;
		}

		int getValue() {
			return val;
		}
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
		getTSKReadLock();
		try {
			if (!HandleCache.isValidFileHandle(fileHandle)) {
				throw new TskCoreException(HandleCache.INVALID_FILE_HANDLE);
			}

			return readFileNat(fileHandle, readBuffer, offset, TSK_FS_FILE_READ_OFFSET_TYPE_ENUM.START_OF_FILE.getValue(), len);
		} finally {
			releaseTSKReadLock();
		}
	}

	/**
	 * reads data from the slack space of a file
	 *
	 * @param fileHandle pointer to a file structure in the sleuthkit
	 * @param readBuffer pre-allocated buffer to read to
	 * @param offset     byte offset in the slack to start at
	 * @param len        amount of data to read
	 *
	 * @return the number of characters read, or -1 if the end of the stream has
	 *         been reached
	 *
	 * @throws TskCoreException exception thrown if critical error occurs within
	 *                          TSK
	 */
	public static int readFileSlack(long fileHandle, byte[] readBuffer, long offset, long len) throws TskCoreException {
		getTSKReadLock();
		try {
			if (!HandleCache.isValidFileHandle(fileHandle)) {
				throw new TskCoreException(HandleCache.INVALID_FILE_HANDLE);
			}

			return readFileNat(fileHandle, readBuffer, offset, TSK_FS_FILE_READ_OFFSET_TYPE_ENUM.START_OF_SLACK.getValue(), len);
		} finally {
			releaseTSKReadLock();
		}
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
		getTSKReadLock();
		try {
			if (!HandleCache.isValidFileHandle(fileHandle)) {
				throw new TskCoreException(HandleCache.INVALID_FILE_HANDLE);
			}

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
		} finally {
			releaseTSKReadLock();
		}
	}

	/**
	 * frees the fileHandle pointer
	 *
	 * @param fileHandle pointer to file structure in sleuthkit
	 */
	public static void closeFile(long fileHandle) {
		closeFile(fileHandle, null);
	}
	
	/**
	 * frees the fileHandle pointer
	 *
	 * @param fileHandle pointer to file structure in sleuthkit
	 * @param skCase     the case containing the file
	 */
	public static void closeFile(long fileHandle, SleuthkitCase skCase) {		
		getTSKReadLock();
		try {
			synchronized (HandleCache.cacheLock) {
				if (!HandleCache.isValidFileHandle(fileHandle)) {
					// File handle is not open so this is a no-op.
					return;
				}
				closeFileNat(fileHandle);
				HandleCache.removeFileHandle(fileHandle, skCase);
			}
		} finally {
			releaseTSKReadLock();
		}
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

	/**
	 * Open a hash database for lookups
	 * @param path Path to Hash DB or index file
	 * @return Handle open db
	 * @throws TskCoreException if there is an error opening the DB
	 */
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
	 * @param dbHandle Handle of database to close.
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
	 * @param dbHandle Previously opened hash db handle.
	 *
	 * @return The display name.
	 *
	 * @throws TskCoreException if a critical error occurs within TSK core
	 */
	public static String getHashDatabaseDisplayName(int dbHandle) throws TskCoreException {
		return hashDbGetDisplayName(dbHandle);
	}

	/**
	 * Lookup the given hash value and get basic answer
	 *
	 * @param hash     Hash value to search for.
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
	 * Fills in any gaps in the image created by image writer.
	 *
	 * @param imgHandle The image handle.
	 *
	 * @return 0 if no errors occurred; 1 otherwise.
	 *
	 * @throws TskCoreException exception thrown if critical error occurs within
	 *                          TSK
	 */
	public static int finishImageWriter(long imgHandle) throws TskCoreException {
		getTSKReadLock();
		try {
			if(! imgHandleIsValid(imgHandle)) {
				throw new TskCoreException("Image handle " + imgHandle + " is closed");
			}
			return finishImageWriterNat(imgHandle);
		} finally {
			releaseTSKReadLock();
		}
	}

	/**
	 * Get the current progress of the finish image process (0-100)
	 *
	 * @param imgHandle
	 *
	 * @return Percentage of blocks completed (0-100)
	 */
	public static int getFinishImageProgress(long imgHandle) {
		getTSKReadLock();
		try {
			if (imgHandleIsValid(imgHandle)) {
				return getFinishImageProgressNat(imgHandle);
			} else {
				return 0;
			}
		} finally {
			releaseTSKReadLock();
		}
	}

	/**
	 * Cancel the finish image process
	 *
	 * @param imgHandle
	 */
	public static void cancelFinishImage(long imgHandle) {
		getTSKReadLock();
		try {
			if (imgHandleIsValid(imgHandle)) {
				cancelFinishImageNat(imgHandle);
			}
		} finally {
			releaseTSKReadLock();
		}
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

	public static boolean isImageSupported(String imagePath) {
		return isImageSupportedNat(imagePath);
	}

	/**
	 * Get a read lock for the C++ layer. Do not get this lock after obtaining
	 * HandleCache.cacheLock.
	 */
	private static void getTSKReadLock() {
		tskLock.readLock().lock();
	}

	/**
	 * Release the read lock
	 */
	private static void releaseTSKReadLock() {
		tskLock.readLock().unlock();
	}

	//free pointers
	/**
	 * frees the imgHandle pointer currently does not close the image -
	 * imgHandle should only be freed as part of CaseDbHandle.free().
	 *
	 * @param imgHandle to close the image
	 */
	@Deprecated
	public static void closeImg(long imgHandle) {
		//closeImgNat(imgHandle); 
	}

	/**
	 * frees the vsHandle pointer - currently does nothing
	 *
	 * @param vsHandle pointer to volume system structure in sleuthkit
	 */
	@Deprecated
	public static void closeVs(long vsHandle) {
		//		closeVsNat(vsHandle);  TODO JIRA-3829 
	}

	/**
	 * frees the fsHandle pointer Currently does not do anything - fsHandle
	 * should only be freed as part of CaseDbHandle.free().
	 *
	 * @param fsHandle pointer to file system structure in sleuthkit
	 */
	@Deprecated
	public static void closeFs(long fsHandle) {
		//closeFsNat(fsHandle);
	}
	
	/**
	 * Open the image and return the image info pointer.
	 *
	 * @param imageFiles the paths to the images
	 *
	 * @return the image info pointer
	 *
	 * @throws TskCoreException exception thrown if critical error occurs within
	 *                          TSK
	 * @deprecated Use the version with the SleuthkitCase argument
	 */
	@Deprecated
	public static long openImage(String[] imageFiles) throws TskCoreException {
		
		return openImage(imageFiles, 0, true, null);
	}

	/**
	 * Open the image with a specified sector size and return the image info
	 * pointer.
	 *
	 * @param imageFiles the paths to the images
	 * @param sSize      the sector size (use '0' for autodetect)
	 *
	 * @return the image info pointer
	 *
	 * @throws TskCoreException exception thrown if critical error occurs within
	 *                          TSK
	 * @deprecated Use the version with the SleuthkitCase argument
	 */
	@Deprecated
	public static long openImage(String[] imageFiles, int sSize) throws TskCoreException {
		return openImage(imageFiles, sSize, true, null);
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
	 * @deprecated Use the version with the SleuthkitCase argument
	 */
	@Deprecated
	public static long openFs(long imgHandle, long fsOffset) throws TskCoreException {
		return openFs(imgHandle, fsOffset, null);
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
	 * @deprecated Use the version with the SleuthkitCase argument
	 */
	@Deprecated
	public static long openFile(long fsHandle, long fileId, TSK_FS_ATTR_TYPE_ENUM attrType, int attrId) throws TskCoreException {
		return openFile(fsHandle, fileId, attrType, attrId, null);
	}	
	

	private static native String getVersionNat();

	private static native void startVerboseLoggingNat(String logPath);

	private static native long newCaseDbNat(String dbPath) throws TskCoreException;

	private static native long newCaseDbMultiNat(String hostNameOrIP, String portNumber, String userName, String password, int dbTypeOrdinal, String databaseName);

	private static native long openCaseDbMultiNat(String hostNameOrIP, String portNumber, String userName, String password, int dbTypeOrdinal, String databaseName);

	private static native long openCaseDbNat(String path) throws TskCoreException;

	private static native void closeCaseDbNat(long db) throws TskCoreException;

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

	private static native long initAddImgNat(long db, String timezone, boolean addUnallocSpace, boolean skipFatFsOrphans) throws TskCoreException;

	private static native long initializeAddImgNat(long db, String timezone, boolean addFileSystems, boolean addUnallocSpace, boolean skipFatFsOrphans) throws TskCoreException;

	private static native void runOpenAndAddImgNat(long process, String deviceId, String[] imgPath, int splits, String timezone) throws TskCoreException, TskDataException;

	private static native void runAddImgNat(long process, String deviceId, long a_img_info, String timeZone, String imageWriterPath) throws TskCoreException, TskDataException;

	private static native void stopAddImgNat(long process) throws TskCoreException;

	private static native void revertAddImgNat(long process) throws TskCoreException;

	private static native long commitAddImgNat(long process) throws TskCoreException;

	private static native long openImgNat(String[] imgPath, int splits, int sSize) throws TskCoreException;

	private static native long openVsNat(long imgHandle, long vsOffset) throws TskCoreException;

	private static native long openVolNat(long vsHandle, long volId) throws TskCoreException;

	private static native long openFsNat(long imgHandle, long fsId) throws TskCoreException;

	private static native long openFileNat(long fsHandle, long fileId, int attrType, int attrId) throws TskCoreException;

	private static native int readImgNat(long imgHandle, byte[] readBuffer, long offset, long len) throws TskCoreException;

	private static native int readVsNat(long vsHandle, byte[] readBuffer, long offset, long len) throws TskCoreException;

	private static native int readVolNat(long volHandle, byte[] readBuffer, long offset, long len) throws TskCoreException;

	private static native int readFsNat(long fsHandle, byte[] readBuffer, long offset, long len) throws TskCoreException;

	private static native int readFileNat(long fileHandle, byte[] readBuffer, long offset, int offset_type, long len) throws TskCoreException;

	private static native int saveFileMetaDataTextNat(long fileHandle, String fileName) throws TskCoreException;

	private static native void closeImgNat(long imgHandle);

	private static native void closeVsNat(long vsHandle);

	private static native void closeFsNat(long fsHandle);

	private static native void closeFileNat(long fileHandle);

	private static native long findDeviceSizeNat(String devicePath) throws TskCoreException;

	private static native String getCurDirNat(long process);

	private static native boolean isImageSupportedNat(String imagePath);

	private static native int finishImageWriterNat(long a_img_info);

	private static native int getFinishImageProgressNat(long a_img_info);

	private static native void cancelFinishImageNat(long a_img_info);

}
