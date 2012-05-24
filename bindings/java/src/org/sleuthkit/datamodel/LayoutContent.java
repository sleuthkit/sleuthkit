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
        int offsetInThisLayoutContent = 0; // current offset in this LayoutContent
        int bytesRead = 0; // Bytes read so far
        Iterator<TskFileLayoutRange> it = getRanges().iterator();
        while(it.hasNext()) {
            TskFileLayoutRange range = it.next();
            if (bytesRead < len) { // we haven't read enough yet
                if (offset < offsetInThisLayoutContent + range.getByteLen()) { // if we are in a range object we want to read from
                    long offsetInRange = 0; // how far into the current range object to start reading
                    if(bytesRead == 0){ // we haven't read anything yet so we want to read from the correct offset in this range object
                        offsetInRange = offset - offsetInThisLayoutContent; // start reading from the correct offset
                    }
                    long offsetInImage = range.getByteStart() + offsetInRange; // how far into the image to start reading
                    long lenToRead = Math.min(range.getByteLen() - offsetInRange, len-bytesRead); // how much we can read this time
                    int lenRead = readImgToOffset(this.getParent().getImageHandle(), buf, bytesRead, offsetInImage, (int) lenToRead);
                    bytesRead += lenRead;
                    if(lenToRead != lenRead) { // If image read failed or was cut short
                        break;
                    }
                }
				offsetInThisLayoutContent += range.getByteLen();
            } else { // we're done reading
                break;
            }
        }
        return bytesRead;
    }
    
	/*
	 * Read bytes from an image into a buffer, starting at given position in buffer
	 * 
	 * @param imgHandle		the image to read from
	 * @param buf			the array to read into
	 * @param offsetInBuf	where to start in the array
	 * @param offsetInImage	where to start in the image
	 * @param lenToRead		how far to read in the image
	 */
    private int readImgToOffset(long imgHandle, byte[] buf, int offsetInBuf, long offsetInImage, int lenToRead) throws TskException {
        byte[] currentBuffer = new byte[lenToRead]; // the buffer for the current range object
        int lenRead = SleuthkitJNI.readImg(imgHandle, currentBuffer, offsetInImage, lenToRead);
        System.arraycopy(currentBuffer, 0, buf, offsetInBuf, lenToRead); // copy what we just read into the main buffer
        return lenRead;
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
