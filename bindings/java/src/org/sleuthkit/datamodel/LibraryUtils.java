/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.datamodel;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;

/**
 * Collection of methods to load libraries embedded in the TSK Datamodel Jar file.
 * 
 * @author jwallace
 */
public class LibraryUtils {
	
	public static final String[] EXTS = new String[] { ".so", ".dylib", ".dll", ".jnilib" };
	/**
	 * The libraries the TSK Datamodel needs.
	 */
	public enum Lib {
		ZLIB ("zlib"),
		LIBEWF ("libewf"),
		TSK_JNI ("tsk_jni");
		
		private final String name;
		Lib(String name) {
			this.name = name;
		}
		
		public String getLibName() {
			return this.name;
		}
	}
	
	/**
	 * Get the name of the current platform.
	 * 
	 * @return a platform identifier, formatted as "OS_ARCH/OS_NAME"
	 */
	public static String getPlatform() {
		String os = System.getProperty("os.name").toLowerCase();
		if(os.contains("win")) {
			os = "win";
		} else if(os.contains("mac")) {
			os = "mac";
		} else {
			os = "unix";
		}
		// os.arch represents the architecture of the JVM, not the os
		String arch = System.getProperty("os.arch");
		System.out.println(arch.toLowerCase() + "/" + os.toLowerCase());
		return arch.toLowerCase() + "/" + os.toLowerCase();
	}
	
	/**
	 * Is the platform Windows?
	 * 
	 * @return 
	 */
	public static boolean isWindows() {
		return System.getProperty("os.name").toLowerCase().contains("windows");
	}
	
	/**
	 * Attempt to load the specified library.
	 * 
	 * @param library
	 * @return 
	 */
	public static void loadLibrary(Lib library) {
		StringBuilder path = new StringBuilder();
		path.append("/NATIVELIBS/");
		path.append(getPlatform());
		
		String libName = library.getLibName();
		if(library == Lib.TSK_JNI && isWindows()) {
			libName = "lib" + libName;
		}
		
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
		
		if(libraryURL != null) {
			// copy library to temp folder and load it
			try {
				java.io.File libTemp = new java.io.File(System.getProperty("java.io.tmpdir") + libName + libExt);
				libTemp.deleteOnExit();
				
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
				
				libTemp.delete();
			} catch (IOException e) {
				// Loading failed.
			} 
		}
	}
}
