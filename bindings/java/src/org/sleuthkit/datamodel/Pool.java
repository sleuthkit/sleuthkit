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

import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.sleuthkit.datamodel.TskData.TSK_POOL_TYPE_ENUM;

/**
 * Represents a pool. Populated based on data in database.
 */
public class Pool extends AbstractContent {

	private static final Logger logger = Logger.getLogger(Pool.class.getName());
	private volatile long poolHandle = 0;
	private final long type;

	/**
	 * Constructor most inputs are from the database
	 *
	 * @param db        case database handle
	 * @param obj_id    the unique content object id for the pool
	 * @param name      name of the pool
	 * @param type      type of the pool
	 */
	protected Pool(SleuthkitCase db, long obj_id, String name, long type) {
		super(db, obj_id, name);
		this.type = type;
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
		try {
			return getParent().getSize();
		} catch (TskCoreException ex) {
			logger.log(Level.SEVERE, "Error getting parent of pool with obj ID {0}", getId());
			return 0;
		}
	}

	/**
	 * get the type
	 *
	 * @return type
	 */
	public TSK_POOL_TYPE_ENUM getType() {
		return TskData.TSK_POOL_TYPE_ENUM.valueOf(type);
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
		// Note that once poolHandle is set, it will never be changed or reset to zero
		if (poolHandle == 0) {
			synchronized (this) {
				if (poolHandle == 0) {
					Content dataSource = getDataSource();
					if ((dataSource != null) && (dataSource instanceof Image)) {
						Image image = (Image) dataSource;
						poolHandle = SleuthkitJNI.openPool(image.getImageHandle(), getPoolOffset(image), getSleuthkitCase());
					} else {
						throw new TskCoreException("Data Source of pool is not an image");
					}
				}
			}
		}
		return this.poolHandle;
	}
	
	/**
	 * Get the offset of the pool from the parent object.
	 * Needs to be in bytes.
	 * 
	 * @return the offset to the pool
	 */
	private long getPoolOffset(Image image) throws TskCoreException {
		if (this.getParent() instanceof Image) {
			// If the parent is an image, then the pool starts at offset zero
			return 0;
		} else if (this.getParent() instanceof Volume) {
			// If the parent is a volume, then the pool starts at the volume offset
			Volume parent = (Volume)this.getParent();
			if (parent.getParent() instanceof VolumeSystem) {
				// uses block size from parent volume system
				return parent.getStart() * ((VolumeSystem) parent.getParent()).getBlockSize(); // Offset needs to be in bytes
			} else {
				// uses sector size from parent image (old behavior fallback)
				return parent.getStart() * image.getSsize(); // Offset needs to be in bytes
			}
		}
		throw new TskCoreException("Pool with object ID " + this.getId() + " does not have Image or Volume parent");
	}

	@Override
	public void close() {
		// Pools will be closed during case closing by the JNI code.
	}

	@SuppressWarnings("deprecation")
	@Override
	protected void finalize() throws Throwable {
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
		return super.toString(preserveState) + "Pool [\t" + "type " + type + "]\t"; //NON-NLS
	}
}
