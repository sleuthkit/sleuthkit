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

import java.io.IOException;
import java.io.RandomAccessFile;

/**
 * An exception thrown if the database is currently in use.
 */
public class ConcurrentDbAccessException extends TskCoreException {

	private final String conflictingApplicationName;

	/**
	 * Creates a ConcurrentDbAccessException from the lock file path and the
	 * random access file of that path whose contents are the application name.
	 *
	 * @param lockFilePath The lock file path.
	 * @param lockFileRaf  The lock file random access file.
	 *
	 * @return The exception
	 *
	 * @throws IOException
	 */
	static ConcurrentDbAccessException createForFile(String lockFilePath, RandomAccessFile lockFileRaf) throws IOException {
		StringBuffer buffer = new StringBuffer();
		while (lockFileRaf.getFilePointer() < lockFileRaf.length()) {
			buffer.append(lockFileRaf.readLine() + System.lineSeparator());
		}
		String conflictingApplication = buffer.toString().trim();
		String message = "Unable to acquire lock on "
				+ lockFilePath
				+ "."
				+ ((conflictingApplication != null && conflictingApplication.trim().length() > 0)
				? ("  Database is already open in " + conflictingApplication + ".")
				: "");

		return new ConcurrentDbAccessException(message, conflictingApplication);
	}

	/**
	 * Constructor.
	 *
	 * @param message                    The exception message.
	 * @param conflictingApplicationName The conflicting application name (or
	 *                                   null if unknown).
	 */
	ConcurrentDbAccessException(String message, String conflictingApplicationName) {
		super(message);
		this.conflictingApplicationName = conflictingApplicationName;
	}

	/**
	 * @return The conflicting application name (or null if unknown).
	 */
	public String getConflictingApplicationName() {
		return conflictingApplicationName;
	}
}
