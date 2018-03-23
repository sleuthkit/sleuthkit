/*
 * Sleuth Kit Data Model
 * 
 * Copyright 2013 Basis Technology Corp.
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

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;

/**
 * Collection of methods to load libraries embedded in the TSK Datamodel Jar
 * file.
 *
 * @author jwallace
 */
public class LibraryUtils {

	public static final String[] EXTS = new String[]{".so", ".dylib", ".dll", ".jnilib"}; //NON-NLS

	/**
	 * The libraries the TSK Datamodel needs.
	 */
	public enum Lib {

		MSVCP("msvcp100", ""), //NON-NLS
		MSVCR("msvcr100", ""), //NON-NLS
		ZLIB("zlib", "z"), //NON-NLS
		LIBEWF("libewf", "ewf"), //NON-NLS
		LIBVMDK("libvmdk", "vmdk"), //NON-NLS
		LIBVHDI("libvhdi", "vhd"), //NON-NLS
		TSK_JNI("libtsk_jni", "tsk_jni"); //NON-NLS

		private final String name;
		private final String unixName;

		Lib(String name, String unixName) {
			this.name = name;
			this.unixName = unixName;
		}

		public String getLibName() {
			return this.name;
		}

		public String getUnixName() {
			return this.unixName;
		}
	}

	/**
	 * Load the Sleuthkit JNI.
	 *
	 * @return true if library was found and loaded
	 */
	public static boolean loadSleuthkitJNI() {
		boolean loaded = LibraryUtils.loadNativeLibFromTskJar(Lib.TSK_JNI);
		if (!loaded) {
			System.out.println("SleuthkitJNI: failed to load " + Lib.TSK_JNI.getLibName()); //NON-NLS
		} else {
			System.out.println("SleuthkitJNI: loaded " + Lib.TSK_JNI.getLibName()); //NON-NLS
		}
		return loaded;
	}

	/**
	 * Get the name of the current platform.
	 *
	 * @return a platform identifier, formatted as "OS_ARCH/OS_NAME"
	 */
	private static String getPlatform() {
		String os = System.getProperty("os.name").toLowerCase();
		if (LibraryUtils.isWindows()) {
			os = "win"; //NON-NLS
		} else if (LibraryUtils.isMac()) {
			os = "mac"; //NON-NLS
		} else if (LibraryUtils.isLinux()) {
			os = "linux"; //NON-NLS
		}
		// os.arch represents the architecture of the JVM, not the os
		String arch = System.getProperty("os.arch");
		return arch.toLowerCase() + "/" + os.toLowerCase();
	}

	/**
	 * Is the platform Windows?
	 *
	 * @return
	 */
	private static boolean isWindows() {
		return System.getProperty("os.name").toLowerCase().contains("windows"); //NON-NLS
	}

	/**
	 * Is the platform Mac?
	 *
	 * @return
	 */
	private static boolean isMac() {
		return System.getProperty("os.name").toLowerCase().contains("mac"); //NON-NLS
	}

	/**
	 * Is the platform Linux?
	 *
	 * @return
	 */
	private static boolean isLinux() {
		return System.getProperty("os.name").equals("Linux"); //NON-NLS
	}

	/**
	 * Attempt to extract and load the specified native library.
	 *
	 * @param library
	 *
	 * @return
	 */
	private static boolean loadNativeLibFromTskJar(Lib library) {
		String libName = library.getLibName();
		String userName = System.getProperty("user.name");
		// find the library in the jar file
		StringBuilder pathInJarBase = new StringBuilder();
		pathInJarBase.append("/NATIVELIBS/"); //NON-NLS
		pathInJarBase.append(getPlatform());
		pathInJarBase.append("/");
		pathInJarBase.append(libName);

		URL urlInJar = null;
		String libExt = null;
		for (String ext : EXTS) {
			urlInJar = SleuthkitJNI.class.getResource(pathInJarBase.toString() + ext);
			if (urlInJar != null) {
				libExt = ext;
				break;
			}
		}

		if (urlInJar == null) {
			System.out.println("Library not found in jar (" + libName + ")"); //NON-NLS
			return false;
		}
		StringBuilder pathToTempFile = new StringBuilder();
		pathToTempFile.append(System.getProperty("java.io.tmpdir"));
		pathToTempFile.append(java.io.File.separator);
		pathToTempFile.append(libName);
		pathToTempFile.append("_");
		pathToTempFile.append(userName);
		pathToTempFile.append(libExt);
		// copy library to temp folder and load it
		try {
			java.io.File tempLibFile = new java.io.File(pathToTempFile.toString()); //NON-NLS
			System.out.println("Temp Folder for Libraries: " + tempLibFile.getParent()); //NON-NLS

			// cycle through the libraries and delete them. 
			// we used to copy dlls into here. 
			// delete any than may still exist from previous installations. 
			// Dec 2013
			for (Lib l : Lib.values()) {
				String ext = getExtByPlatform();
				// try the windows version
				java.io.File f = new java.io.File(l.getLibName() + ext);
				//System.out.println(f.getName());
				if (f.exists()) {
					f.delete();
				} else {
					// try the unix version
					java.io.File fUnix = new java.io.File(l.getUnixName() + ext);
					//System.out.println(fUnix.getName());
					if (fUnix.exists()) {
						fUnix.delete();
					}
				}
			}

			// Delete old file
			if (tempLibFile.exists()) {
				if (tempLibFile.delete() == false) {
					System.out.println("Error deleting old native library.  Is the app already running? (" + tempLibFile.toString() + ")"); //NON-NLS
					return false;
				}
			}

			// copy it
			InputStream in = urlInJar.openStream();
			OutputStream out = new FileOutputStream(tempLibFile);

			byte[] buffer = new byte[1024];
			int length;
			while ((length = in.read(buffer)) > 0) {
				out.write(buffer, 0, length);
			}
			in.close();
			out.close();

			// load it
			System.load(tempLibFile.getAbsolutePath());
		} catch (IOException e) {
			// Loading failed.
			System.out.println("Error loading library: " + e.getMessage()); //NON-NLS
			return false;
		}
		return true;
	}

	private static String getExtByPlatform() {
		if (isWindows()) {
			return ".dll"; //NON-NLS
		} else if (isMac()) {
			return ".dylib"; //NON-NLS
		} else {
			return ".so"; //NON-NLS
		}
	}
}
