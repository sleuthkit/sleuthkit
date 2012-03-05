/*
 * Sleuth Kit Data Model
 *
 * Copyright 2012 Basis Technology Corp.
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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * FsContent reader with content caching support
 * The cache life-cycle is managed externally
 * E.g. it needs to be cleared when case is changed
 */
 class FsContentCache {

	static final long MAX_ENTRY_SIZE = 51200; //max size of file to cache
	static final int MAX_NUM_ENTRIES = 1000;  //most recent files cached
	
	private Map<Long, CacheEntry> cache = null;
	private List<Long> queue = null; 
	private int cached = 0;
	
	private static FsContentCache instance = null;
	
	public synchronized static FsContentCache getInstance() {
		if (instance == null)
			instance = new FsContentCache();
		return instance;
	}

	private FsContentCache() {
		cache = new HashMap<Long, CacheEntry>();
		queue = new ArrayList<Long>();
	}
	
	

	/**
	 * Read a file contents from cache.  If not in cache, read the file and put in cache.
	 * @param file FsContent to read and cache
	 * @param fileHandle valid fileHandle to open file associated with FsContent
	 * @param offset offset to read from
	 * @param len length in bytes to read
	 * @return byte array with file contents
	 * @throws TskException 
	 */
	byte[] read(FsContent file, long fileHandle, long offset, long len) throws TskException {
		final long fileSize = file.getSize();
		if (fileSize > MAX_ENTRY_SIZE) {
			//do not cache
			return SleuthkitJNI.readFile(fileHandle, offset, len);
		}

		//check if in cache
		final long contentID = file.getId();
		CacheEntry cf = cache.get(contentID);
		byte[] data = null;
		if (cf == null) {
			//read entire file and put in cache
			data = SleuthkitJNI.readFile(fileHandle, 0, fileSize);
			cf = add(data, contentID, fileSize);
		} else {
			data = cf.data;
		}
		//++cf.numRead;

		//trim data array to return
		byte[] ret = null;
		if (offset == 0 && len == fileSize) {
			ret = data;
		} else {
			int newSize = data.length < (int)len ? data.length : (int)len;
			final int left = data.length - (int)offset;
			if (left < newSize) 
				newSize = left;
			ret = new byte[newSize];
			System.arraycopy(data, (int) offset, ret, 0, newSize);
		}

		return ret;
	}

	/**
	 * Clear cache
	 */
	public void clear() {
		cache.clear();
		queue.clear();
		cached = 0;
		//logger.log(Level.INFO, "Cache cleared, " + this.toString());
	}

	/**
	 * Get number of files currently stored in cache
	 * @return 
	 */
	int getCurNumCachedFiles() {
		return cached;
	}

	/**
	 * get total size of all files stored in cache
	 * @return 
	 */
	long getCurCacheSize() {
		long total = 0;
		for (CacheEntry e : cache.values()) {
			total += e.size;
		}
		return total;
	}

	@Override
	public String toString() {
		return "FsContentCache{" + "cached=" + cached + "size=" + getCurCacheSize() + '}';
	}
	
	private CacheEntry add(byte[] data, long contentID, long size) {
		CacheEntry entry = new CacheEntry(data, size);
		//remove oldest if too big
		if (cached > MAX_NUM_ENTRIES) {
			//remove eldest entry
			Long eldest = queue.remove(0);
			cache.remove(eldest);
			--cached;
		}

		cache.put(contentID, entry);
		queue.add(contentID);
		++cached;
		//logger.log(Level.INFO, "Added to cache. " + this.toString());
		return entry;
	}

	private static class CacheEntry {

		byte[] data = null;
		long size = 0;
		//int numRead = 0;

		CacheEntry(byte[] data, long size) {
			this.data = data;
			this.size = size;
		}
	}
}
