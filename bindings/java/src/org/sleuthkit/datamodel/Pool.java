/*
 * Sleuth Kit Data Model
 * 
 * Copyright 2011-2017 Basis Technology Corp.
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
import org.sleuthkit.datamodel.TskData.TSK_DB_POOL_TYPE_ENUM;

/**
 * Represents a volume system. Populated based on data in database.
 */
public class Pool extends AbstractContent {

	private volatile long poolHandle = 0;
	private long type, imgOffset;

	/**
	 * Constructor most inputs are from the database
	 *
	 * @param db        case database handle
	 * @param obj_id    the unique content object id for the volume system
	 * @param name      name of the volume system
	 * @param type      type of the volume system
	 * @param imgOffset offset of the volume system with respect to image
	 */
	protected Pool(SleuthkitCase db, long obj_id, String name, long type, long imgOffset) {
		super(db, obj_id, name);
		this.type = type;
		this.imgOffset = imgOffset;
		System.out.println("### made a pool! Image offset " + imgOffset + "\n");
	}

	@Override
	public int read(byte[] readBuffer, long offset, long len) throws TskCoreException {
		synchronized (this) {
			if (poolHandle == 0) {
				getPoolHandle();
			}
		}
		return SleuthkitJNI.readPool(poolHandle, readBuffer, offset, len);
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
	public TSK_DB_POOL_TYPE_ENUM getType() {
		return TskData.TSK_DB_POOL_TYPE_ENUM.valueOf(type);
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
	 * Lazily loads the internal pool structure: won't be loaded until
	 * this is called and maintains the handle to it to reuse it
	 *
	 * @return a pool pointer from the sleuthkit
	 *
	 * @throws TskCoreException exception throw if an internal tsk core error
	 *                          occurs
	 */
	long getPoolHandle() throws TskCoreException {
		if (poolHandle == 0) {
			synchronized (this) {
				if (poolHandle == 0) {
					Content dataSource = getDataSource();
					if ((dataSource != null) && (dataSource instanceof Image)) {
						Image image = (Image) dataSource;
						poolHandle = SleuthkitJNI.openPool(image.getImageHandle(), imgOffset, getType().getPoolType(), getSleuthkitCase());
					} else {
						throw new TskCoreException("Data Source of pool is not an image");
					}
				}
			}
		}
		return this.poolHandle;
	}

	@Override
	public void close() {
		//if (volumeSystemHandle != 0) {
		//	synchronized (this) {
		//		if (volumeSystemHandle != 0) {
		//			// SleuthkitJNI.closeVs(volumeSystemHandle); // closeVs is currently a no-op
		//			volumeSystemHandle = 0;
		//		}
		//	}
		//}
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
		return getSleuthkitCase().getPoolChildren(this);
	}

	@Override
	public List<Long> getChildrenIds() throws TskCoreException {
		return getSleuthkitCase().getPoolChildrenIds(this);
	}


	@Override
	public String toString(boolean preserveState) {
		return super.toString(preserveState) + "Pool [\t" + "imgOffset " + imgOffset + "\t" + "type " + type + "]\t"; //NON-NLS
	}
}
