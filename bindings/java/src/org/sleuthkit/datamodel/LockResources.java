/*
 * Sleuth Kit Data Model
 *
 * Copyright 2024 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.datamodel;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;

/**
 * The resources associated with the file lock for the TSK database.
 */
class LockResources implements AutoCloseable {

	private static final String LOCK_FILE_PREFIX = ".lock_";

	private File lockFile = null;
	private RandomAccessFile lockFileRaf = null;
	private FileChannel lockFileChannel = null;
	private FileLock lockFileLock = null;

	/**
	 * Constructor.
	 *
	 * @param lockFile        The lock file File reference.
	 * @param lockFileRef     The lock file random access file reference.
	 * @param lockFileChannel The lock file file channel.
	 * @param lockFileLock    The lock file file lock.
	 */
	LockResources(File lockFile, RandomAccessFile lockFileRaf, FileChannel lockFileChannel, FileLock lockFileLock) {
		this.lockFile = lockFile;
		this.lockFileRaf = lockFileRaf;
		this.lockFileChannel = lockFileChannel;
		this.lockFileLock = lockFileLock;
	}

	/**
	 * Try to acquire a lock to the lock file in the case directory.
	 *
	 * @param caseDir         The case directory that the autopsy.db is in.
	 * @param dbName          The name of the database.
	 * @param applicationName The name of the application (max is 500
	 *                        characters).
	 *
	 * @return The lock file resources to be closed.
	 *
	 * @throws IllegalAccessException
	 * @throws IOException
	 */
	static LockResources tryAcquireFileLock(String caseDir, String dbName, String applicationName) throws ConcurrentDbAccessException, IOException, OverlappingFileLockException {
		// get the lock file path
		String lockFileName = LOCK_FILE_PREFIX + (dbName == null ? "tskdb" : dbName);
		File lockFile = new File(caseDir, lockFileName);
		// make directories leading up to that
		lockFile.getParentFile().mkdirs();

		// if the lock file exists
		if (lockFile.isFile() && !lockFile.canWrite()) {
			// get the random access file as read only
			RandomAccessFile lockFileRaf = new RandomAccessFile(lockFile, "r");
			throw ConcurrentDbAccessException.createForFile(lockFile.getAbsolutePath(), lockFileRaf);
		} else {
			RandomAccessFile lockFileRaf = new RandomAccessFile(lockFile, "rw");
			FileChannel lockFileChannel = lockFileRaf.getChannel();
			FileLock lockFileLock = lockFileChannel == null
					? null
					: lockFileChannel.tryLock(1024L, 1L, false);

			if (lockFileLock != null) {
				lockFileRaf.setLength(0);
				String limitedAppName = applicationName.length() > 500 ? applicationName.substring(0, 500) : applicationName;
				lockFileRaf.writeChars(limitedAppName);
				return new LockResources(lockFile, lockFileRaf, lockFileChannel, lockFileLock);
			} else {
				throw ConcurrentDbAccessException.createForFile(lockFile.getAbsolutePath(), lockFileRaf);
			}
		}
	}

	@Override
	public void close() throws Exception {
		// close lock file resources in reverse acquisition order
		if (this.lockFileLock != null) {
			this.lockFileLock.close();
			this.lockFileLock = null;
		}

		if (this.lockFileChannel != null) {
			this.lockFileChannel.close();
			this.lockFileChannel = null;
		}

		if (this.lockFileRaf != null) {
			this.lockFileRaf.close();
			this.lockFileRaf = null;
		}

		if (this.lockFile != null) {
			this.lockFile.delete();
			this.lockFile = null;
		}
	}
}
