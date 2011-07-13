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


Building The Jar File

You will need:
* The sqlitejdbc Jar file:
    http://www.xerial.org/maven/repository/artifact/org/xerial/sqlite-jdbc/ (newest version is at the BOTTOM)
* Java JDK
* Ant

Place the JAR file in the 'lib' folder.

Build with the default ant target (by running 'ant')


Building the Dynamic Library (for JNI)

To build the .dll build the win32 visual studio project. You will
need to have a version of JDK for the .dll to build. You will need
to set the JDK_HOME environment variable If it is not already set.


Using the Jar file and Library

Make sure the Jar file is in your CLASSPATH. The dynamic library
will also need to be available when the program is run.  Typically
that means that it must be in the path.

