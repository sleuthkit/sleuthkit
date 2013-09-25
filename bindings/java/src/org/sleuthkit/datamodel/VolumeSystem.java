/*
 * Autopsy Forensic Browser
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

import java.util.ArrayList;
import java.util.List;
import org.sleuthkit.datamodel.TskData.TSK_VS_TYPE_ENUM;

/**
 * Represents a volume system. Populated based on data in database.
 */
public class VolumeSystem extends AbstractContent {

	private volatile long volumeSystemHandle = 0;
	private long type, imgOffset, blockSize;

	/**
	 * Constructor most inputs are from the database
	 *
	 * @param db case database handle
	 * @param obj_id the unique content object id for the volume system
	 * @param name name of the volume system
	 * @param type type of the volume system
	 * @param imgOffset offset of the volume system with respect to image
	 * @param blockSize block size of this volume system
	 */
	protected VolumeSystem(SleuthkitCase db, long obj_id, String name, long type, long imgOffset, long blockSize) {
		super(db, obj_id, name);
		this.type = type;
		this.imgOffset = imgOffset;
		this.blockSize = blockSize;
	}

	@Override
	public int read(byte[] readBuffer, long offset, long len) throws TskCoreException {
		synchronized (this) {
			if (volumeSystemHandle == 0) {
				volumeSystemHandle = SleuthkitJNI.openVs(getImage().getImageHandle(), imgOffset);
			}
		}
		return SleuthkitJNI.readVs(volumeSystemHandle, readBuffer, offset, len);
	}

	@Override
	public long getSize() {
		return 0;
	}

	/**
	 * get the type
	 *
	 * @return type
	 */
	public TSK_VS_TYPE_ENUM getType() {
		return TskData.TSK_VS_TYPE_ENUM.valueOf(type);
	}

	/**
	 * get the byte offset
	 *
	 * @return byte offset
	 */
	public long getOffset() {
		return imgOffset;
	}

	/**
	 * get the block size
	 *
	 * @return block size
	 */
	public long getBlockSize() {
		return blockSize;
	}

	/**
	 * get the volume system Handle pointer Open a new handle if needed,
	 * otherwise resuse the existing handle.
	 *
	 * @return volume system Handle pointer
	 * @throws TskException
	 */
	protected synchronized long getVolumeSystemHandle() throws TskCoreException {
		if (volumeSystemHandle == 0) {
			volumeSystemHandle = SleuthkitJNI.openVs(getImage().getImageHandle(), imgOffset);
		}

		return volumeSystemHandle;
	}

	@Override
	public void close() {
		if (volumeSystemHandle != 0) {
			synchronized (this) {
				if (volumeSystemHandle != 0) {
					SleuthkitJNI.closeVs(volumeSystemHandle);
					volumeSystemHandle = 0;
				}
			}
		}
	}

	@Override
	public void finalize() throws Throwable {
		try {
			close();
		} finally {
			super.finalize();
		}
	}

	@Override
	public <T> T accept(SleuthkitItemVisitor<T> v) {
		return v.visit(this);
	}

	@Override
	public <T> T accept(ContentVisitor<T> v) {
		return v.visit(this);
	}

	@Override
	public List<Content> getChildren() throws TskCoreException {
		return getSleuthkitCase().getVolumeSystemChildren(this);
	}

	@Override
	public List<Long> getChildrenIds() throws TskCoreException {
		return getSleuthkitCase().getVolumeSystemChildrenIds(this);
	}

	@Override
	public Image getImage() throws TskCoreException {
		return getParent().getImage();
	}

	/**
	 * @return a list of Volumes that are direct children of this VolumeSystem
	 * @throws TskCoreException
	 */
	public List<Volume> getVolumes() throws TskCoreException {
		List<Volume> volumes = new ArrayList<Volume>();
		for (Content child : getChildren()) {
			if (child instanceof Volume) {
				volumes.add((Volume) child);
			}
		}
		return volumes;
	}

	@Override
	public String toString(boolean preserveState) {
		return super.toString(preserveState) + "VolumeSystem [\t" + "blockSize " + blockSize + "\t" + "imgOffset " + imgOffset + "\t" + "type " + type + "]\t";
	}
}
