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
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Layout file object representation of a layout file stored in tsk_files table.
 * Layout files are not fs files, but "virtual" files created from blocks of data (e.g. unallocated)
 * that are treated as files for convenience and uniformity.
 * 
 * Because layout files are not real fs files, they only utilize a subset of meta-data attributes.
 * A layout file normally contains 1 or more entry in tsk_file_layout table 
 * that define ordered byte block ranges, with respect to the image.
 * 
 * The class also supports reads of layout files, reading blocks across ranges in a sequence
 */
public class LayoutFile extends AbstractFile{
	
	//layout ranges associated with this file
	private List<TskFileRange> ranges;
	
    private Content parent;
	
	protected LayoutFile(SleuthkitCase db, long obj_id, String name, TskData.TSK_DB_FILES_TYPE_ENUM type) {
		super(db, obj_id, name, type);
	}
	
	/**
     * Set the parent class, will be called by the parent
	 * 
     * @param p parent
     */
    protected void setParent(Content p){
        parent = p;
    }
	
	/**
	 * Get number of file layout ranges associated with this layout file
	 * @return number of file layout ranges objects associated
	 */
	public int getNumParts() {
		int size = 0;
		try {
			size = getRanges().size();
		} catch (TskCoreException ex) {
			Logger.getLogger(LayoutFile.class.getName()).log(Level.INFO, "Error getting layout content ranges for size", ex);
		}
		return size;
	}

	

	@Override
	public List<TskFileRange> getRanges() throws TskCoreException {
		if(ranges == null) {
            ranges = getSleuthkitCase().getFileRanges(this.getId());
        }
        return ranges;
	}


	@Override
	public List<Content> getChildren() throws TskCoreException {
		return Collections.<Content>emptyList();
	}

	@Override
    public long getSize() {
        return calcSize();
    }
	
	@Override
	public boolean isDir(){
        return false;
    }
	
	@Override
	public boolean isFile() {
		return true;
	}
    
	/**
	 * Calculate the size from all ranges / blocks
	 * @return total content size in bytes
	 */
    private long calcSize() {
        long size = 0;
        try {
            for (TskFileRange range : getRanges()) {
                size += range.getByteLen();
            }
        }catch (TskCoreException ex) {
			Logger.getLogger(LayoutFile.class.getName()).log(Level.INFO, "boo", ex);
        }
        return size;
    }
	

	@Override
    public int read(byte[] buf, long offset, long len) throws TskCoreException {
        long offsetInThisLayoutContent = 0; // current offset in this LayoutContent
        int bytesRead = 0; // Bytes read so far
        Iterator<TskFileRange> it = getRanges().iterator();
        while(it.hasNext()) {
            TskFileRange range = it.next();
            if (bytesRead < len) { // we haven't read enough yet
                if (offset < offsetInThisLayoutContent + range.getByteLen()) { // if we are in a range object we want to read from
                    long offsetInRange = 0; // how far into the current range object to start reading
                    if(bytesRead == 0){ // we haven't read anything yet so we want to read from the correct offset in this range object
                        offsetInRange = offset - offsetInThisLayoutContent; // start reading from the correct offset
                    }
                    long offsetInImage = range.getByteStart() + offsetInRange; // how far into the image to start reading
                    long lenToRead = Math.min(range.getByteLen() - offsetInRange, len-bytesRead); // how much we can read this time
                    int lenRead = readImgToOffset(getImage().getImageHandle(), buf, bytesRead, offsetInImage, (int) lenToRead);
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
	
	/**
	 * Convert an internal offset to an image offset
	 * @param layoutOffset the offset in this layout file
	 * @return the corresponding offset in the image
	 */
	public long convertToImgOffset(long layoutOffset) {
		throw new UnsupportedOperationException("Not supported yet!");
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
    private int readImgToOffset(long imgHandle, byte[] buf, int offsetInBuf, long offsetInImage, int lenToRead) throws TskCoreException {
        byte[] currentBuffer = new byte[lenToRead]; // the buffer for the current range object
        int lenRead = SleuthkitJNI.readImg(imgHandle, currentBuffer, offsetInImage, lenToRead);
        System.arraycopy(currentBuffer, 0, buf, offsetInBuf, lenToRead); // copy what we just read into the main buffer
        return lenRead;
    }


	@Override
	public <T> T accept(ContentVisitor<T> v) {
		return v.visit(this);
	}

	

	@Override
	public <T> T accept(SleuthkitItemVisitor<T> v) {
		return v.visit(this);
	}
	
	/**
	 * Get parent content object (either filesystem, or volume)
	 * @return the parent content object
	 */
	public Content getParent() {
		return parent;
	}
	

	@Override
	public Image getImage() throws TskCoreException{
		return getParent().getImage();
	}
	
	@Override
	public boolean isVirtual() {
		return true;
	}
}
