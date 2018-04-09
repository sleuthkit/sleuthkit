/*
 * SleuthKit Java Bindings
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

import java.util.logging.Level;
import java.util.logging.Logger;
import org.sleuthkit.datamodel.TskData.FileKnown;
import org.sleuthkit.datamodel.TskData.TSK_DB_FILES_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_ATTR_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_META_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_FLAG_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_TYPE_ENUM;

/**
 * A representation of a layout file that has been added to a case. Layout files
 * are not file system files, but "virtual" files created from blocks of data
 * (e.g. unallocated) that are treated as files for convenience and uniformity.
 *
 * Because layout files are not real file system files, they only utilize a
 * subset of meta-data attributes. A layout file normally contains one or more
 * entry in tsk_file_layout table that define ordered byte block ranges, with
 * respect to the image.
 *
 * The class also supports reads of layout files, reading blocks across ranges
 * in a sequence.
 */
public class LayoutFile extends AbstractFile {

	private long imageHandle = -1;

	/**
	 * Constructs a representation of a layout file that has been added to a
	 * case. Layout files are not file system files, but "virtual" files created
	 * from blocks of data (e.g. unallocated) that are treated as files for
	 * convenience and uniformity.
	 *
	 * @param db                 The case database to which the file has been
	 *                           added.
	 * @param objId              The object id of the file in the case database.
	 * @param dataSourceObjectId The object id of the data source for the file.
	 * @param name               The name of the file.
	 * @param fileType           The type of the file.
	 * @param dirType            The type of the file, usually as reported in
	 *                           the name structure of the file system. May be
	 *                           set to TSK_FS_NAME_TYPE_ENUM.UNDEF.
	 * @param metaType           The type of the file, usually as reported in
	 *                           the metadata structure of the file system. May
	 *                           be set to
	 *                           TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_UNDEF.
	 * @param dirFlag            The allocated status of the file, usually as
	 *                           reported in the name structure of the file
	 *                           system.
	 * @param metaFlags          The allocated status of the file, usually as
	 *                           reported in the metadata structure of the file
	 *                           system.
	 * @param size               The size of the file.
	 * @param md5Hash            The MD5 hash of the file, null if not yet
	 *                           calculated.
	 * @param knownState         The known state of the file from a hash
	 *                           database lookup, null if not yet looked up.
	 * @param parentPath         The path of the parent of the file.
	 * @param mimeType           The MIME type of the file, null if it has not
	 *                           yet been determined.
	 */
	LayoutFile(SleuthkitCase db,
			long objId,
			long dataSourceObjectId,
			String name,
			TSK_DB_FILES_TYPE_ENUM fileType,
			TSK_FS_NAME_TYPE_ENUM dirType, TSK_FS_META_TYPE_ENUM metaType,
			TSK_FS_NAME_FLAG_ENUM dirFlag, short metaFlags,
			long size,
			String md5Hash, FileKnown knownState,
			String parentPath, String mimeType) {
		super(db, objId, dataSourceObjectId, TSK_FS_ATTR_TYPE_ENUM.TSK_FS_ATTR_TYPE_DEFAULT, 0, name, fileType, 0L, 0, dirType, metaType, dirFlag, metaFlags, size, 0L, 0L, 0L, 0L, (short) 0, 0, 0, md5Hash, knownState, parentPath, mimeType, SleuthkitCase.extractExtension(name));
	}

	/**
	 * Gets the number of file layout ranges associated with this layout file.
	 *
	 * @return The number of file layout ranges.
	 */
	public int getNumParts() {
		int numParts = 0;
		try {
			numParts = getRanges().size();
		} catch (TskCoreException ex) {
			Logger.getLogger(LayoutFile.class.getName()).log(Level.SEVERE, String.format("Error getting layout ranges for layout file (objId = %d)", getId()), ex); //NON-NLS
		}
		return numParts;
	}

	/**
	 * Indicates whether or not this layout file is the root of a file system,
	 * always returns false.
	 *
	 * @return False.
	 */
	@Override
	public boolean isRoot() {
		return false;
	}

	/**
	 * Does nothing, a layout file cannot be directly opened, read, or closed.
	 * Use the readInt method to get layout file content.
	 */
	@Override
	public void close() {
	}

	/**
	 * Reads bytes from the layout ranges associated with this file.
	 *
	 * @param buf    Buffer to read into.
	 * @param offset Start position in the file.
	 * @param len    Number of bytes to read.
	 *
	 * @return Number of bytes read.
	 *
	 * @throws TskCoreException if there is a problem reading the file.
	 */
	@Override
	protected int readInt(byte[] buf, long offset, long len) throws TskCoreException {
		long offsetInThisLayoutContent = 0; // current offset in this LayoutContent
		int bytesRead = 0; // Bytes read so far

		if (imageHandle == -1) {
			Content dataSource = getDataSource();
			if ((dataSource != null) && (dataSource instanceof Image)) {
				Image image = (Image) dataSource;
				imageHandle = image.getImageHandle();
			} else {
				throw new TskCoreException("Data Source of LayoutFile is not Image");
			}
		}

		for (TskFileRange range : getRanges()) {
			if (bytesRead < len) { // we haven't read enough yet
				if (offset < offsetInThisLayoutContent + range.getByteLen()) { // if we are in a range object we want to read from
					long offsetInRange = 0; // how far into the current range object to start reading
					if (bytesRead == 0) { // we haven't read anything yet so we want to read from the correct offset in this range object
						offsetInRange = offset - offsetInThisLayoutContent; // start reading from the correct offset
					}
					long offsetInImage = range.getByteStart() + offsetInRange; // how far into the image to start reading
					long lenToRead = Math.min(range.getByteLen() - offsetInRange, len - bytesRead); // how much we can read this time
					int lenRead = readImgToOffset(imageHandle, buf, bytesRead, offsetInImage, (int) lenToRead);
					bytesRead += lenRead;
					if (lenToRead != lenRead) { // If image read failed or was cut short
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
	 * Reads bytes from an image into a buffer, starting at given position in
	 * buffer.
	 *
	 * @param imgHandle	    The image to read from.
	 * @param buf	          The array to read into.
	 * @param offsetInBuf	  Where to start in the array.
	 * @param offsetInImage	Where to start in the image.
	 * @param lenToRead	    How far to read in the image.
	 *
	 * @return the number of characters read, or -1 if the end of the stream has
	 *         been reached
	 *
	 * @throws TskCoreException exception thrown if critical error occurs within
	 *                          TSK
	 */
	private int readImgToOffset(long imgHandle, byte[] buf, int offsetInBuf, long offsetInImage, int lenToRead) throws TskCoreException {
		byte[] currentBuffer = new byte[lenToRead]; // the buffer for the current range object
		int lenRead = SleuthkitJNI.readImg(imgHandle, currentBuffer, offsetInImage, lenToRead);
		System.arraycopy(currentBuffer, 0, buf, offsetInBuf, lenToRead); // copy what we just read into the main buffer
		return lenRead;
	}

	/**
	 * Accepts a content visitor (Visitor design pattern).
	 *
	 * @param visitor A ContentVisitor supplying an algorithm to run using this
	 *                file as input.
	 *
	 * @return The output of the algorithm.
	 */
	@Override
	public <T> T accept(ContentVisitor<T> visitor) {
		return visitor.visit(this);
	}

	/**
	 * Accepts a Sleuthkit item visitor (Visitor design pattern).
	 *
	 * @param visitor A SleuthkitItemVisitor supplying an algorithm to run using
	 *                this file as input.
	 *
	 * @return The output of the algorithm.
	 */
	@Override
	public <T> T accept(SleuthkitItemVisitor<T> visitor) {
		return visitor.visit(this);
	}

	/**
	 * Provides a string representation of this file.
	 *
	 * @param preserveState True if state should be included in the string
	 *                      representation of this object.
	 */
	@Override
	public String toString(boolean preserveState) {
		return super.toString(preserveState) + "LayoutFile [\t" + "]\t"; //NON-NLS
	}

	/**
	 * Constructs a representation of a layout file that has been added to a
	 * case. Layout files are not file system files, but "virtual" files created
	 * from blocks of data (e.g. unallocated) that are treated as files for
	 * convenience and uniformity.
	 *
	 * @param db         The case database to which the file has been added.
	 * @param objId      The object id of the file in the case database.
	 * @param name       The name of the file.
	 * @param fileType   The type of the file.
	 * @param dirType    The type of the file, usually as reported in the name
	 *                   structure of the file system. May be set to
	 *                   TSK_FS_NAME_TYPE_ENUM.UNDEF.
	 * @param metaType   The type of the file, usually as reported in the
	 *                   metadata structure of the file system. May be set to
	 *                   TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_UNDEF.
	 * @param dirFlag    The allocated status of the file, usually as reported
	 *                   in the name structure of the file system.
	 * @param metaFlags  The allocated status of the file, usually as reported
	 *                   in the metadata structure of the file system.
	 * @param size       The size of the file.
	 * @param md5Hash    The MD5 hash of the file, null if not yet calculated.
	 * @param knownState The known state of the file from a hash database
	 *                   lookup, null if not yet looked up.
	 * @param parentPath The path of the parent of the file.
	 *
	 * @deprecated Do not make subclasses outside of this package.
	 */
	@Deprecated
	@SuppressWarnings("deprecation")
	protected LayoutFile(SleuthkitCase db, long objId, String name,
			TSK_DB_FILES_TYPE_ENUM fileType,
			TSK_FS_NAME_TYPE_ENUM dirType, TSK_FS_META_TYPE_ENUM metaType,
			TSK_FS_NAME_FLAG_ENUM dirFlag, short metaFlags,
			long size, String md5Hash, FileKnown knownState, String parentPath) {
		this(db, objId, db.getDataSourceObjectId(objId), name, fileType, dirType, metaType, dirFlag, metaFlags, size, md5Hash, knownState, parentPath, null);
	}
}
