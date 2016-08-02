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
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.util.Arrays;


public class EncodedFileUtil {
	
	final static private int HEADER_LENGTH = 32;  // All headers must be this long
	final static private String XOR1_HEADER =  "AUTOPSY_CONTAINER_XOR1_xxxxxxxxx";
	
	static EncodingType getDefaultEncoding(){
		return EncodingType.XOR1;
	}
	
	static String getHeader(EncodingType type) throws IOException{
		switch (type){
			case XOR1:
				return XOR1_HEADER;
			default:
				throw new IOException("Attempting to get header for EncodingType.NONE");
		}
	}
	
	static byte [] getEncodedHeader(EncodingType type) throws IOException{
		if(type.equals(EncodingType.NONE)){
			throw new IOException("Attempting to encode a file with EncodingType.NONE");
		}
		byte [] encHeader = new byte[HEADER_LENGTH];
		byte [] plainHeader = getHeader(type).getBytes();

		for(int i = 0;i < HEADER_LENGTH;i++){
			encHeader[i] = encodeByte(plainHeader[i], type);
		}
		return encHeader;
	}
	
	static int getHeaderLength(){
		return HEADER_LENGTH;
	}
	
	static byte encodeByte(byte b, EncodingType type) throws IOException{
		switch (type){
			case XOR1:
				return ((byte)(b ^ 0xa5)); 
			default:
				throw new IOException("Attempting to encode byte with EncodingType.NONE");
		}
    }
	
	static EncodingType getEncoding(RandomAccessFile fileHandle){
		try{
			long curOffset = fileHandle.getFilePointer();
			if (curOffset != 0) {
				fileHandle.seek(0);
			}
			byte[] header = new byte[HEADER_LENGTH];
			int bytesRead = fileHandle.read(header, 0, HEADER_LENGTH);
			if(bytesRead != HEADER_LENGTH){
				return EncodingType.NONE;
			}
			
			return(getTypeFromHeader(header));
		} catch (IOException ex){
			// Add stuff
			ex.printStackTrace(); // FIX FIX FIX
			return EncodingType.NONE;
		}
	}
	
	static private EncodingType getTypeFromHeader(byte[] header){
		if(header.length != HEADER_LENGTH){
			return EncodingType.NONE;
		}
		
		if(Arrays.equals(header, XOR1_HEADER.getBytes())){
			return EncodingType.XOR1;
		} else {
			return EncodingType.NONE;
		}
		
	}
	
	static public void encodeFile(String sourcePath, String destPath) throws IOException{
		encodeFile(sourcePath, destPath, getDefaultEncoding());
	}
	
	static public void encodeFile(String sourcePath, String destPath, EncodingType type) throws IOException{
		
		FileInputStream in = new FileInputStream(sourcePath);
		try {
			OutputStream out = new EncodedFileStream(new BufferedOutputStream(new FileOutputStream(destPath)));
			try {
				// Transfer bytes from in to out
				byte[] buf = new byte[1024];
				int len;
				while ((len = in.read(buf)) > 0) {
					out.write(buf, 0, len);
				}
			} finally {
				out.close();
			}
		} finally {
			in.close();
		}
		
	}
	
	public enum EncodingType{
		XOR1,
		NONE;
	}
}
