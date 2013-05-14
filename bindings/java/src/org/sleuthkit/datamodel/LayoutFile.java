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
import org.sleuthkit.datamodel.TskData.FileKnown;
import org.sleuthkit.datamodel.TskData.TSK_DB_FILES_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_ATTR_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_META_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_FLAG_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_TYPE_ENUM;

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
	
	protected LayoutFile(SleuthkitCase db, long objId, String name, 
			TSK_DB_FILES_TYPE_ENUM fileType, 
			TSK_FS_NAME_TYPE_ENUM dirType, TSK_FS_META_TYPE_ENUM metaType, 
			TSK_FS_NAME_FLAG_ENUM dirFlag, short metaFlags, 
			long size, String md5Hash, FileKnown knownState, String parentPath) {
		super(db, objId, TSK_FS_ATTR_TYPE_ENUM.TSK_FS_ATTR_TYPE_DEFAULT, (short)0, name, fileType, 0L, dirType, metaType, dirFlag, metaFlags, size, 0L, 0L, 0L, 0L, (short)0, 0, 0, md5Hash, knownState, parentPath);
		//this.size = calcSize(); //update calculated size
	}

	/**
	 * Get number of file layout ranges associated with this layout file
	 * @return number of file layout ranges objects associated
	 */
	public int getNumParts() {
		int numParts = 0;
		try {
			numParts = getRanges().size();
		} catch (TskCoreException ex) {
			Logger.getLogger(LayoutFile.class.getName()).log(Level.INFO, "Error getting layout content ranges for size", ex);
		}
		return numParts;
	}

	
	@Override
	public List<Content> getChildren() throws TskCoreException {
		return getSleuthkitCase().getAbstractFileChildren(this, TskData.TSK_DB_FILES_TYPE_ENUM.DERIVED);
	}

	@Override
	public List<Long> getChildrenIds() throws TskCoreException {
		return getSleuthkitCase().getAbstractFileChildrenIds(this, TskData.TSK_DB_FILES_TYPE_ENUM.DERIVED);
	}
    
	/**
	 * Calculate the size from all ranges / blocks
	 * @return total content size in bytes
	 */
    private long calcSize() {
        long calcSize = 0;
        try {
            for (TskFileRange range : getRanges()) {
                calcSize += range.getByteLen();
            }
        }catch (TskCoreException ex) {
			Logger.getLogger(LayoutFile.class.getName()).log(Level.SEVERE, "Error calculating layout file size from ranges", ex);
        }
        return calcSize;
    }

	@Override
	public void close() {
		//nothing to be closed
	}
	
	@Override
    protected int readInt(byte[] buf, long offset, long len) throws TskCoreException {
        long offsetInThisLayoutContent = 0; // current offset in this LayoutContent
        int bytesRead = 0; // Bytes read so far
		
        for (TskFileRange range : getRanges()) {
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

	@Override
	public Image getImage() throws TskCoreException{
		return getParent().getImage();
	}

	
	@Override
	public boolean isRoot() {
		return false;
	}
	@Override
	public String toString(boolean preserveState){
		return super.toString(preserveState) + "LayoutFile [\t" + "]\t";
	}
}
