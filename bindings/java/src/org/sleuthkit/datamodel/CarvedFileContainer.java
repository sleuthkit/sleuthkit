/*
 * Sleuth Kit Data Model
 *
 * Copyright 2012-2016 Basis Technology Corp.
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

import java.util.List;

/**
 * Contains a representation of a carved file.
 */
public final class CarvedFileContainer {

	private final String mCarvedFileName;
	private final long mCarvedFileSize;
	private final long mContainerId;
	private final List<TskFileRange> mRangeData;

	/**
	 * @param carvedFileName The name of the carved file as a String
	 * @param carvedFileSize The size of the carved file in bytes
	 * @param containerId    The obj_id of the unallocated space block
	 *                       'container' where the carved file was found.
	 * @param rangeData      The actual offset ranges inside the unallocated
	 *                       space block 'container' where the carved file
	 *                       resides.
	 */
	public CarvedFileContainer(String carvedFileName, long carvedFileSize, long containerId, List<TskFileRange> rangeData) {
		mCarvedFileName = carvedFileName;
		mCarvedFileSize = carvedFileSize;
		mContainerId = containerId;
		mRangeData = rangeData;
	}

	public String getName() {
		return mCarvedFileName;
	}

	public long getSize() {
		return mCarvedFileSize;
	}

	public long getId() {
		return mContainerId;
	}

	public List<TskFileRange> getRanges() {
		return mRangeData;
	}
}
