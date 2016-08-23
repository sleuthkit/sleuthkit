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

import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.Arrays;

/**
 * Utility methods to support encoding/decoding files written to disk.
 */
class EncodedFileUtil {
	
	final static private int HEADER_LENGTH = 32;  // All headers must be this long
	final static private String XOR1_HEADER =  "TSK_CONTAINER_XOR1_xxxxxxxxxxxxx";
	
	/**
	 * Get the header for the given encoding type.
	 * @param type
	 * @return
	 * @throws IOException 
	 */
	static String getHeader(TskData.EncodingType type) throws IOException{
		switch (type){
			case XOR1:
				return XOR1_HEADER;
			default:
				throw new IOException("Can not get header for " + type.toString());
		}
	}
	
	/**
	 * Get the encoded version of the given type's header.
	 * Used by EncodedFileStream so that after the header is fed through the encoding
	 * scheme, the original plaintext header will appear at the beginning of the file.
	 * This should not be used for testing which encoding scheme was used on a file.
	 * @param type
	 * @return
	 * @throws IOException 
	 */
	static byte [] getEncodedHeader(TskData.EncodingType type) throws IOException{
		if(type.equals(TskData.EncodingType.NONE)){
			throw new IOException("Can not get encoded header for " + type.toString());
		}
		byte [] encHeader = new byte[HEADER_LENGTH];
		byte [] plainHeader = getHeader(type).getBytes();

		for(int i = 0;i < HEADER_LENGTH;i++){
			encHeader[i] = encodeByte(plainHeader[i], type);
		}
		return encHeader;
	}
	
	/**
	 * Returns the length of the encoded header.
	 * This is a fixed length to allow easier detection.
	 * @return 
	 */
	static int getHeaderLength(){
		return HEADER_LENGTH;
	}
	
	/**
	 * Encode a byte using the given encoding scheme.
	 * @param b
	 * @param type
	 * @return
	 * @throws IOException 
	 */
	static byte encodeByte(byte b, TskData.EncodingType type) throws IOException{
		switch (type){
			case XOR1:
				return ((byte)(b ^ 0xca)); 
			default:
				throw new IOException("Can not encode byte with encoding type " + type.toString());
		}
    }
	
	/**
	 * Decode a byte using the given encoding scheme.
	 * @param b
	 * @param type
	 * @return
	 * @throws IOException 
	 */
	static byte decodeByte(byte b, TskData.EncodingType type) throws IOException{
		switch (type){
			case XOR1:
				return ((byte)(b ^ 0xca)); 
			default:
				throw new IOException("Can not decode byte with encoding type " + type.toString());
		}
    }	
	
	/**
	 * Determine whether a file was encoded and which type of encoding was used.
	 * @param fileHandle
	 * @return 
	 * @throws IOException
	 */
	static TskData.EncodingType getEncoding(RandomAccessFile fileHandle){
		try{
			long curOffset = fileHandle.getFilePointer();
			if (curOffset != 0) {
				fileHandle.seek(0);
			}
			byte[] header = new byte[HEADER_LENGTH];
			int bytesRead = fileHandle.read(header, 0, HEADER_LENGTH);
			if(bytesRead != HEADER_LENGTH){
				return TskData.EncodingType.NONE;
			}

			return(getTypeFromHeader(header));
		} catch (IOException ex){
			return TskData.EncodingType.NONE;
		}
	}
	
	/**
	 * Compare the buffer containing the potential header against the encoding headers.
	 * @param header
	 * @return 
	 */
	static private TskData.EncodingType getTypeFromHeader(byte[] header){
		if(header.length != HEADER_LENGTH){
			return TskData.EncodingType.NONE;
		}
		
		if(Arrays.equals(header, XOR1_HEADER.getBytes())){
			return TskData.EncodingType.XOR1;
		} else {
			return TskData.EncodingType.NONE;
		}
		
	}
}
