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
 * Interface for all content from the sleuthkit.
 * @author alawrence
 */
public interface Content {

	/**
	 * read data from the content in the sleuthkit
	 * @param offset offset to start reading from
	 * @param len amount of data to read (in bytes)
	 * @return a character array of data (in bytes)
	 */
	public byte[] read(long offset, long len) throws TskException;

	/**
	 * get the size of the content
	 * @return size of the content
	 */
	public long getSize();
}
