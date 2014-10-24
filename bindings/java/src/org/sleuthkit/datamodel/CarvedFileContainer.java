package org.sleuthkit.datamodel;

import java.util.List;

public final class CarvedFileContainer {

	private String mCarvedFileName;
	private long mCarvedFileSize;
	private long mContainerId;
	private List<TskFileRange> mRangeData;

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
