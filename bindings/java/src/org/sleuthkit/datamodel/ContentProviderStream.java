/*
 * SleuthKit Java Bindings
 *
 * Copyright 2023 Basis Technology Corp.
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

/**
 * Custom provider for content bytes.
 */
@SuppressWarnings("try")
public interface ContentProviderStream extends AutoCloseable {

	/**
	 * Reads data that this content object is associated with (file contents,
	 * volume contents, etc.).
	 *
	 * @param buf    a character array of data (in bytes) to copy read data to
	 * @param offset byte offset in the content to start reading from
	 * @param len    number of bytes to read into buf.
	 *
	 * @return num of bytes read, or -1 on error
	 *
	 * @throws TskCoreException if critical error occurred during read in the
	 *                          tsk core
	 */
	public int read(byte[] buf, long offset, long len) throws TskCoreException;
}
