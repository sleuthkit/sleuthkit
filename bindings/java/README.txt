Sleuth Kit Java Bindings

Overview

The core functionality of the Sleuth Kit is in the C/C++ library.
The functionality is made available to Java applications by using
JNI.  The theory is that a SQLite database is created by the C++
library and then it is queried by native Java code. JNI methods
exist to make the database and to read file content (and other raw
data that is too large to fit into the database).

To use the Java bindings, you must have the Sleuth Kit datamodel
JAR file compiled and have compiled the associated dynamic library
from the C/C++ code.


Requirements:
* Java JDK
* Ant
* Jar files as listed in ivy.xml (which will get downloaded automatically)

The following jar files must be on the classpath for building and
running.  Version details can be found in ivy.xml.  They will be 
automatically downloaded if you do not compile in offline mode. 
* sqlite-jdbc
* postgresql-jdbc
* c3p0



Building the Dynamic Library (for JNI)

The win32 Visual Studio solution has a tsk_jni project that will
build the JNI dll.  To use this project, you will need to have
JDK_HOME environment variable set to the root directory of JDK.

On non-windows environments, it should just build as part of running
./configure and make.   If the needed Java components are not found,
it will not be built. 

This library will depend on libewf, zlib, and other libraries that
TSK was built to depend on. In Windows, the core of TSK (libtsk)
is a static library that is fully embedded in the libtsk_jni.dll
file. On non-Windows environments, libtsk_jni will depend on the 
libtsk dynamic library.



Building The Jar File

Build with the default ant target (by running 'ant').  This will
download the required libraries (using ivy) and place the jar file
in the dist folder along with the needed dll and library files.



Using the Jar file and Library

There are two categories of things that need to be in the right place:
- The Jar file needs to be on the CLASSPATH.  
- The libewf and zlib dynamic libraries need to be loadable. The TSK 
  JNI native library is inside of the Jar file and it will depend on the 
  libewf and zlib libraries.  On a Unix-like platform, that means that
  if you did a 'make install' with libewf and zlib, you should be OK.
  On Windows, you should copy these dlls to a place that is found based
  on the rules of Windows library loading. Note that these locations are
  based on the rules of Windows loading them and not necessarily based on 
  java's loading paths. 

Refer to the javadocs for details on using the API:
    http://sleuthkit.org/sleuthkit/docs/jni-docs/


------------
Brian Carrier
Jan 2014

