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


Building the Dynamic Library (for JNI)

The win32 Visual Studio solution has a tsk_jni project that will
build the JNI dll.  To use this project, you will need to have
JDK_HOME environment variable set to the root directory of JDK.

On non-windows environments, it should just build as part of running
./configure and make.   If the needed Java components are not found,
it will not be built. 



Building The Jar File

Build with the default ant target (by running 'ant').  This will
download the required libraries (using ivy) and place the jar file
in the dist folder along with the needed dll and library files.


Using the Jar file and Library

Make sure the Jar file is in your CLASSPATH. The dynamic library
will also need to be available when the program is run.  Typically
that means that it must be in the path.  Refer to the javadocs for 
details on using the API

------------
Brian Carrier
Nov 11, 2011

