/*
 * Sleuth Kit Data Model
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

/**
 * Class links to sleuthkit c/c++ libraries to read data from image files
 * @author alawrence
 */
public class SleuthkitJNI {
	//Native methods
	private static native String getVersionNat();
	//loaddb
	private static native long loaddbNat(String[] imgPath, int splits, String outDir) throws TskException;
	private static native long startloaddbNat(String timezone) throws TskException;
	private static native void runloaddbNat(long process, String[] imgPath, int splits, String outDir) throws TskException;;
	private static native void stoploaddbNat(long process) throws TskException;;
	//open functions
	private static native long openImageNat(String[] imgPath, int splits) throws TskException;
	private static native long openVsNat(long imgHandle, long vsOffset) throws TskException;
	private static native long openVolNat(long vsHandle, long volId) throws TskException;
	private static native long openFsNat(long imgHandle, long fsId) throws TskException;
	private static native long openFileNat(long fsHandle, long fileId) throws TskException;

	//read functions
	private static native byte[] readImgNat(long imgHandle, long offset, long len) throws TskException;
	private static native byte[] readVsNat(long vsHandle, long offset, long len) throws TskException;
	private static native byte[] readVolNat(long volHandle, long offset, long len) throws TskException;
	private static native byte[] readFsNat(long fsHandle, long offset, long len) throws TskException;
	private static native byte[] readFileNat(long fileHandle, long offset, long len) throws TskException;

	//close functions
	private static native void closeImgNat(long imgHandle);
	private static native void closeVsNat(long vsHandle);
	private static native void closeFsNat(long fsHandle);
	private static native void closeFileNat(long fileHandle);

	static {
		System.loadLibrary("zlib1");
		System.loadLibrary("libewf");
		System.loadLibrary("tsk_jni");
	}


	public SleuthkitJNI(){}

	/**
	 * get the sleuthkit version string
	 * @return the version string
	 */
	public static String getVersion(){
		return getVersionNat();
	}

	/**
	 * open the image and return the image info pointer
	 * @param imageDirs the paths to the images
	 * @return the image info pointer
	 * @throws TskException
	 */
	public static long openImage(String[] imageDirs) throws TskException{
		return openImageNat(imageDirs, imageDirs.length);
	}

	/**
	 * create the sqlite database for the given image
	 * @param imgPaths paths to the image splits
	 * @param outDir the directory to write the database to
	 * @throws TskException
	 */
	public static void makeDb(String[] imgPaths, String outDir) throws TskException{
		loaddbNat(imgPaths, imgPaths.length, outDir);
	}

	/**
	 * create a process pointer for loaddb (this process can be started and stopped)
	 * @param timezone timezone of the image
	 * @return a pointer to a process
	 * @throws TskException
	 */
	public static long makeLoaddbProcess(String timezone) throws TskException{
		return startloaddbNat(timezone);
	}

	/**
	 * start the given loaddb process
	 * @param process pointer to an open process
	 * @param imgPaths paths to the image to make the database from
	 * @param outDir directory to write the database to
	 * @throws TskException
	 */
	public static void runLoaddbProcess(long process, String[] imgPaths, String outDir) throws TskException{
		runloaddbNat(process, imgPaths, imgPaths.length, outDir);
	}

	/**
	 * cancels the given loaddb process
	 * @param process pointer to a running process
	 * @throws TskException
	 */
	public static void stopLoaddbProcess(long process) throws TskException{
		stoploaddbNat(process);
	}
	/**
	 * Get volume system Handle
	 * @param vsOffset byte offset in the image to the volume system (usually 0)
	 * @return pointer to a vsHandle structure in the sleuthkit
	 */
	public static long openVs(long imgHandle, long vsOffset) throws TskException{
		return openVsNat(imgHandle, vsOffset);
	}

	//get pointers
	/**
	 * Get volume Handle
	 * @param vsHandle pointer to the volume system structure in the sleuthkit
	 * @param volId id of the volume
	 * @return pointer to a volHandle structure in the sleuthkit
	 */
	public static long openVsPart(long vsHandle, long volId) throws TskException{
		//returned long is ptr to vs Handle object in tsk
		return openVolNat(vsHandle, volId);
	}

	/**
	 * get file system Handle
	 * @param fsOffset byte offset to the file system
	 * @return pointer to a fsHandle structure in the sleuthkit
	 */
	public static long openFs(long imgHandle, long fsOffset) throws TskException{
		return openFsNat(imgHandle, fsOffset);
	}

	/**
	 * get file Handle
	 * @param fsHandle fsHandle pointer in the sleuthkit
	 * @param fileId id of the file
	 * @return pointer to a file structure in the sleuthkit
	 */
	public static long openFile(long fsHandle, long fileId) throws TskException{
		return openFileNat(fsHandle, fileId);
	}

	//do reads
	/**
	 * reads data from an image
	 * @param offset byte offset in the image to start at
	 * @param len amount of data to read
	 * @return an array of characters (bytes of data)
	 */
	public static byte[] readImg(long imgHandle, long offset, long len) throws TskException{
		//returned byte[] is the data buffer
		return readImgNat(imgHandle, offset, len);
	}
	/**
	 * reads data from an volume system
	 * @param vsHandle pointer to a volume system structure in the sleuthkit
	 * @param offset sector offset in the image to start at
	 * @param len amount of data to read
	 * @return an array of characters (bytes of data)
	 */
	public static byte[] readVs(long vsHandle, long offset, long len) throws TskException{
		return readVsNat(vsHandle, offset, len);
	}
	/**
	 * reads data from an volume
	 * @param volHandle pointer to a volume structure in the sleuthkit
	 * @param offset byte offset in the image to start at
	 * @param len amount of data to read
	 * @return an array of characters (bytes of data)
	 */
	public static byte[] readVsPart(long volHandle, long offset, long len) throws TskException{
		//returned byte[] is the data buffer
		return readVolNat(volHandle, offset, len);
	}
	/**
	 * reads data from an file system
	 * @param fsHandle pointer to a file system structure in the sleuthkit
	 * @param offset byte offset in the image to start at
	 * @param len amount of data to read
	 * @return an array of characters (bytes of data)
	 */
	public static byte[] readFs(long fsHandle, long offset, long len) throws TskException{
		//returned byte[] is the data buffer
		return readFsNat(fsHandle, offset, len);
	}
	/**
	 * reads data from an file
	 * @param fileHandle pointer to a file structure in the sleuthkit
	 * @param offset byte offset in the image to start at
	 * @param len amount of data to read
	 * @return an array of characters (bytes of data)
	 */
	public static byte[] readFile(long fileHandle, long offset, long len) throws TskException{
		//returned byte[] is the data buffer
		return readFileNat(fileHandle, offset, len);
	}

	//free pointers
	/**
	 * frees the imgHandle pointer
	 */
	public static void closeImg(long imgHandle){
		closeImgNat(imgHandle);
	}
	/**
	 * frees the vsHandle pointer
	 * @param vsHandle pointer to volume system structure in sleuthkit
	 */
	public static void closeVs(long vsHandle){
		closeVsNat(vsHandle);
	}

	/**
	 * frees the fsHandle pointer
	 * @param fsHandle pointer to file system structure in sleuthkit
	 */
	public static void closeFs(long fsHandle){
		closeFsNat(fsHandle);
	}
	/**
	 * frees the fileHandle pointer
	 * @param fileHandle pointer to file structure in sleuthkit
	 */
	public static void closeFile(long fileHandle){
		closeFileNat(fileHandle);
	}
}
