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

import java.util.List;

/**
 * @deprecated Use CarvingResult instead. 
 */
@Deprecated
public final class CarvedFileContainer {

	private final String mCarvedFileName;
	private final long mCarvedFileSize;
	private final long mContainerId;
	private final List<TskFileRange> mRangeData;

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
