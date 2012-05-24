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

import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/**
 *
 * @author dfickling
 */
public class LayoutContent extends AbstractContent{
	
	private List<TskFileLayoutRange> ranges;
	private LayoutContentParent parent;
	private TskData.TSK_DB_FILES_TYPE_ENUM type;
	
	public LayoutContent(SleuthkitCase db, long obj_id, TskData.TSK_DB_FILES_TYPE_ENUM type) {
		super(db, obj_id);
		this.type = type;
	}

	@Override
	public int read(byte[] buf, long offset, long len) throws TskException {
		long realLen = Math.min(len, calcSize()-offset);
		int currentUnallocatedFileOffset = 0;
		int bytesRead = 0;
		Iterator<TskFileLayoutRange> it = getRanges().iterator();
		while(it.hasNext()) {
			TskFileLayoutRange range = it.next();
			if (bytesRead < realLen) { // we have to read
				
				if (currentUnallocatedFileOffset + range.getByteLen() < offset) { // if we aren't yet able to read, continue
					currentUnallocatedFileOffset += range.getByteLen(); // should be last range maybe?
					continue;
				} else { // We're in a range object that we should read from
					long offsetInRange = 0; // how far into the current range object to start reading
					if(offset - currentUnallocatedFileOffset > 0){ // only start at an offset if this is the first range we're reading from
						offsetInRange = (offset - currentUnallocatedFileOffset);
					}
					long offsetInImage = offsetInRange + range.getByteStart(); // how far into the image to start reading
					int lenToRead = (int) Math.min((range.getByteLen() - offsetInRange), (realLen-bytesRead)); // how much we can read this time
					byte[] currentBuffer = new byte[lenToRead]; // the buffer for the current range object
					SleuthkitJNI.readImg(getParent().getImageHandle(), currentBuffer, offsetInImage, lenToRead); //TODO: makes sure this returns same as lenToRead
					System.arraycopy(currentBuffer, 0, buf, bytesRead, lenToRead); // copy what we just read into the main buffer
					bytesRead += lenToRead; // assuming the above method call works correctly
					currentUnallocatedFileOffset += range.getByteLen(); // should be last range maybe?
				}
			} else {
				break;
			}
		}
		return bytesRead;
	}
	
	/**
	 * set the parent class, will be called by the parent
	 * @param p parent
	 */
	protected void setParent(LayoutContentParent p){
		parent = p;
	}
	
	private List<TskFileLayoutRange> getRanges() throws TskException{
		if(ranges == null) {
			ranges = db.getFileLayoutRanges(this.getId());
		}
		return ranges;
	}
	
	public LayoutContentParent getParent(){
		return parent;
	}

	@Override
	public long getSize() {
		return calcSize();
	}
	
	private long calcSize() {
		int size = 0;
		try {
			for (TskFileLayoutRange range : getRanges()) {
				size += range.getByteLen();
			}
		}catch (TskException ex) {
		}
		return size;
	}

	@Override
	public <T> T accept(ContentVisitor<T> v) {
		return v.visit(this);
	}

	@Override
	public boolean isOnto() {
		return false;
	}

	@Override
	public List<Content> getChildren() throws TskException {
		return Collections.<Content>emptyList();
	}

	@Override
	public <T> T accept(SleuthkitItemVisitor<T> v) {
		return v.visit(this);
	}

	@Override
	public List<LayoutContent> getLayoutChildren(TskData.TSK_DB_FILES_TYPE_ENUM type) throws TskException {
		throw new UnsupportedOperationException("Not supported yet.");
	}
	
	public TskData.TSK_DB_FILES_TYPE_ENUM getType() {
		return type;
	}
	
}
