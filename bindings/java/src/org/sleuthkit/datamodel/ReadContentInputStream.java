/*
 * Autopsy Forensic Browser
 *
 * Copyright 2011-2013 Basis Technology Corp.
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

import java.io.IOException;
import java.io.InputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * InputStream to read bytes from a Content object's data
 */
public class ReadContentInputStream extends InputStream {

	private long position;
	private long length;
	private Content content;
	private static final Logger logger = Logger.getLogger(ReadContentInputStream.class.getName());

	public ReadContentInputStream(Content content) {
		this.content = content;
		this.position = 0;
		this.length = content.getSize();
	}

	@Override
	public int read() throws IOException {
		byte[] buff = new byte[1];
		return (read(buff) != -1) ? buff[0] : -1;
	}

	@Override
	public int read(byte[] b) throws IOException {
		return read(b, 0, b.length);
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException {

		final int buffLen = b.length;
		//must return 0 for zero-length arrays
		if (buffLen == 0 || len == 0) {
			return 0;
		}

		//would get an error from TSK if we try to read an empty file
		if (length == 0) {
			return -1;
		}

		//check args more
		if (off < 0 || off >= buffLen) {
			return -1;
		}

		if (position >= length) {
			//eof, no data remains to be read
			return -1;
		}

		//read into the user buffer
		int lenToRead = (int) Math.min(length - position, buffLen - off);
		lenToRead = Math.min(lenToRead, len);

		byte[] retBuf = null;
		if (off == 0) {
			//write directly to user buffer
			retBuf = b;
		} else {
			//write to a temp buffer, then copy to user buffer
			retBuf = new byte[lenToRead];
		}
		try {
			final int lenRead = content.read(retBuf, position, lenToRead);

			if (lenRead == 0 || lenRead == -1) {
				//error or no more bytes to read, report EOF
				return -1;
			} else {
				position += lenRead;

				//if read into user-specified offset, copy back from temp buffer to user
				if (off != 0) {
					System.arraycopy(retBuf, 0, b, off, lenRead);
				}

				return lenRead;
			}
		} catch (TskCoreException ex) {
			logger.log(Level.WARNING, ("Error reading content into stream: "
					+ content.getId()) + ": " + content.getName()
					+ ", at offset " + position + ", length to read: " + lenToRead, ex);
			throw new IOException(ex);
		}

	}
	
	@Override
	public int available() throws IOException {
		if (position > length) {
			return 0;
		}
        return (int)(length - position);
    }

	@Override
	public long skip(long n) throws IOException {
		//more efficient skip() implementation than superclass
		//as it does not involve reads
		long toSkip = Math.min(n, length - position);  //allow to skip to EOF
		position += toSkip;
		return toSkip;
		//0 1 2 3 4 5      len: 6
	}

	@Override
	public void close() throws IOException {
		super.close(); 
		//nothing to be done currently, file handles are closed when content is gc'ed
	}

	@Override
	public boolean markSupported() {
		return false;
	}
	
	/// additional methods to facilitate stream seeking
	
	/**
	 * Get total length of the stream
	 * @return number of bytes that can be read from this stream
	 */
	public long getLength() {
		return length;
	}
	
	/**
	 * Get current position in the stream
	 * @return current offset in bytes
	 */
	public long getCurPosition() {
		return position;
	}
	
	/**
	 * Set new current position in the stream, up to and including EOF
	 * @param newPosition new position in the stream to be set
	 * @return the actual position set, which can be less than position passed in
	 * if EOF has been reached
	 */
	public long seek(long newPosition) {
		if (newPosition < 0) {
			throw new IllegalArgumentException ("Illegal negative new position in the stream");
		}
		
		position = Math.min(newPosition, length);
		return position;
		
	}
	
}
