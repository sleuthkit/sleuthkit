To build the java bindings first download the sqlitejdbc .jar files http://www.xerial.org/maven/repository/artifact/org/xerial/sqlite-jdbc/ (newest version is at the BOTTOM)

Put the .jar files in sleuthkit/bindings/java/lib

use the Ant target build.xml in sleuthkit/bindings/java/  

To set up Ant download it from: http://ant.apache.org/ then follow the directions in the Ant Manual (http://ant.apache.org/manual/index.html) for installation

To build the .dll build the win32 visual studio project. You will need to have a version of JDK for the .dll to build. You will need to set the JDK_HOME environment variable If it is not already set. 

To use these bindings you will need to move the .dll to the appropriate location to be found by your java compiler. This will be specific to your IDE or should be specified on the command line if using a command linem compiler.
To build the java bindings first download the sqlitejdbc .jar files http://www.xerial.org/maven/repository/artifact/org/xerial/sqlite-jdbc/ (newest version is at the BOTTOM)

Put the .jar files in sleuthkit/bindings/java/lib

use the Ant target build.xml in sleuthkit/bindings/java/  

To set up Ant download it from: http://ant.apache.org/ then follow the directions in the Ant Manual (http://ant.apache.org/manual/index.html) for installation

To build the .dll build the win32 visual studio project. You will need to have a version of JDK for the .dll to build. You will need to set the JDK_HOME environment variable If it is not already set. 

To use these bindings you will need to move the .dll to the appropriate location to be found by your java compiler. This will be specific to your IDE or should be specified on the command line if using a command linem compiler.