/*
 * SleuthKit Java Bindings
 *
 * Copyright 2011-2016 Basis Technology Corp.
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

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * Output stream wrapper for encoding files being written to disk. The idea is
 * to prevent malicious files from getting extracted onto the user's hard drive
 * in their original form. The encoding type used here should match the one used
 * to create the derived file database entry for this file.
 */
public class EncodedFileOutputStream extends BufferedOutputStream {

	private final TskData.EncodingType type;
	private long encodedDataLength;

	/**
	 * Create an encoded output stream using the specified encoding.
	 *
	 * @param out
	 * @param type
	 *
	 * @throws IOException
	 */
	public EncodedFileOutputStream(OutputStream out, TskData.EncodingType type) throws IOException {
		super(out);
		this.type = type;
		encodedDataLength = 0;
		writeHeader();
	}

	/**
	 * Create an encoded output stream using the specified encoding and buffer
	 * size.
	 *
	 * @param out
	 * @param size
	 * @param type
	 *
	 * @throws IOException
	 */
	public EncodedFileOutputStream(OutputStream out, int size, TskData.EncodingType type) throws IOException {
		super(out, size);
		this.type = type;
		writeHeader();
	}

	private void writeHeader() throws IOException {
		// We get the encoded header here so it will be in plaintext after encoding
		write(EncodedFileUtil.getEncodedHeader(type), 0, EncodedFileUtil.getHeaderLength());
		encodedDataLength -= EncodedFileUtil.getHeaderLength();
	}

	@Override
	public void write(int b) throws IOException {
		super.write((int) EncodedFileUtil.encodeByte((byte) b, type));
		encodedDataLength++;
	}

	@Override
	public void write(byte[] b,
			int off,
			int len)
			throws IOException {
		byte[] encodedData = new byte[b.length];
		for (int i = 0; i < b.length; i++) {
			encodedData[i] = EncodedFileUtil.encodeByte(b[i], type);
		}

		super.write(encodedData, off, len);
		encodedDataLength += len;
	}
	
	/**
	 * Get the number of bytes written to the file, excluding header bytes.
	 * This is needed for storing the original length of the file in the
	 * tsk_files table in cases where we don't know the size in advance.
	 * 
	 * @return the number of bytes written to the stream, excluding the header.
	 */
	public long getBytesWritten() {
		return encodedDataLength;
	} 
}