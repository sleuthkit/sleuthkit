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
import java.util.Arrays;
import java.util.List;

/**
 * Collection of methods to load libraries embedded in the TSK Datamodel Jar file.
 * 
 * @author jwallace
 */
public class LibraryUtils {
	
	public static final String[] EXTS = new String[] { ".so", ".dylib", ".dll", ".jnilib" };
	
	public static final Lib[] CRT_LIBS = new Lib[] { Lib.MSVCP, Lib.MSVCR };
	
	public static final Lib[] OTHER_LIBS = new Lib[] { Lib.ZLIB, Lib.LIBEWF };

	/**
	 * The libraries the TSK Datamodel needs.
	 */
	public enum Lib {
		MSVCP ("msvcp100", ""),
		MSVCR ("msvcr100", ""),
		ZLIB ("zlib", "z"),
		LIBEWF ("libewf", "ewf"),
		TSK_JNI ("libtsk_jni", "tsk_jni");
		
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
	 * Load all libraries needed for the current platform except the TSK JNI.
	 * 
	 * @return 
	 */
	public static boolean loadAuxilliaryLibs() {
		System.out.println("Java lib path: " + System.getProperty("java.library.path"));
		boolean loaded = true;
        if (LibraryUtils.isWindows()) {
            loaded = LibraryUtils.loadCRTLibs();
		}
		
		if (! LibraryUtils.isLinux()) {
			
			for(LibraryUtils.Lib lib : LibraryUtils.getLibs()) {
				loaded = LibraryUtils.loadLibFromJar(lib);
				if (!loaded) {
					System.out.println("SleuthkitJNI: failed to load " + lib.getLibName());
				} else {
					System.out.println("SleuthkitJNI: loaded " + lib.getLibName());
				}
			}
		} else {
			System.out.println("In unix path.");
			// Unix platform
			for (Lib lib : LibraryUtils.getLibs()) {
				try {
					System.out.println("Lib name: " + lib.getUnixName());
					System.loadLibrary(lib.getUnixName());
					System.out.println("SleuthkitJNI: loaded " + lib.getLibName());
				} catch (UnsatisfiedLinkError e) {
					loaded = false;
					System.out.println("SleuthkitJNI: failed to load " + lib.getLibName());
				}
			}
		}
		return loaded;
	}
	
	/**
	 * Load the Sleuthkit JNI.
	 * 
	 * @return 
	 */
	public static boolean loadSleuthkitJNI() {
		boolean loaded = LibraryUtils.loadLibFromJar(Lib.TSK_JNI);
		if (!loaded) {
			System.out.println("SleuthkitJNI: failed to load " + Lib.TSK_JNI.getLibName());
		} else {
			System.out.println("SleuthkitJNI: loaded " + Lib.TSK_JNI.getLibName());
		}
		return loaded;
	}
	
	/** Load the CRT Libraries.
	 * 
	 * @return 
	 */
	private static boolean loadCRTLibs() {
		boolean loaded = true;
		try { 
			// on windows force loading ms crt dependencies first
			// in case linker can't find them on some systems
			// Note: if shipping with a different CRT version, this will only print a warning
			// and try to use linker mechanism to find the correct versions of libs.
			// We should update this if we officially switch to a new version of CRT/compiler
			for(LibraryUtils.Lib crt : LibraryUtils.getCRTLibs()) {
				loaded = LibraryUtils.loadLibFromJar(crt);
				if(!loaded) {
					System.out.println("SleuthkitJNI: failed to load " + crt.getLibName());
				} else {
					System.out.println("SleuthkitJNI: loaded " + crt.getLibName());
				}
			}
		} catch (UnsatisfiedLinkError e1) {
			System.out.println(e1.toString());
			try {
				//Try to load from system path.
				System.out.println("Can't find CRT libraries, attempting to load from System.loadLibrary");
				System.loadLibrary("msvcr100");
				System.loadLibrary("msvcp100");
				loaded = true;
			} catch (UnsatisfiedLinkError e2) {
				System.out.println("SleuthkitJNI: error loading CRT libraries, " + e2.toString());
				loaded = false;
			}
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
		if(LibraryUtils.isWindows()) {
			os = "win";
		} else if(LibraryUtils.isMac()) {
			os = "mac";
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
		return System.getProperty("os.name").toLowerCase().contains("windows");
	}

	/**
	 * Is the platform Mac?
	 * 
	 * @return 
	 */
	private static boolean isMac() {
		return System.getProperty("os.name").toLowerCase().contains("mac");
	}
	
	/**
	 * Is the platform Linux?
	 * 
	 * @return
	 */
	private static boolean isLinux() {
		return System.getProperty("os.name").equals("Linux");
	}
	
    /**
	 * Attempt to extract and load the specified library.
	 * 
	 * @param library
	 * @return 
	 */
	private static boolean loadLibFromJar(Lib library) {
		StringBuilder path = new StringBuilder();
		path.append("/NATIVELIBS/");
		path.append(getPlatform());
		
		String libName = library.getLibName();
		
		path.append("/");
		path.append(libName);
		
		URL libraryURL = null;
		String libExt = null;
		for(String ext : EXTS) {
			libraryURL = SleuthkitJNI.class.getResource(path.toString() +  ext);
			if (libraryURL != null) {
				libExt = ext;
				break;
			}
		}
		
		if(libraryURL == null) {
			return false;
		}
		
		// copy library to temp folder and load it
		try {
			java.io.File libTemp = new java.io.File(System.getProperty("java.io.tmpdir") + libName + libExt);

			if(libTemp.exists()) {
				// Delete old file
				libTemp.delete();
			}

			InputStream in = libraryURL.openStream();
			OutputStream out = new FileOutputStream(libTemp);

			byte[] buffer = new byte[1024];
			int length;
			while((length = in.read(buffer)) > 0) {
				out.write(buffer, 0, length);
			}
			in.close();
			out.close();

			System.load(libTemp.getAbsolutePath());
		} catch (IOException e) {
			// Loading failed.
			return false;
		} 
		return true;
	} 
	
	private static Lib[] getCRTLibs() {
		return CRT_LIBS;
	}
	
	private static Lib[] getLibs() {
		return OTHER_LIBS;
	}
}
