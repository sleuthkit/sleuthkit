                          The Sleuth Kit
                        Win32 README File

                http://www.sleuthkit.org/sleuthkit

                     Last Modified: Feb 2012

====================================================================
The Sleuth Kit (TSK) runs on Windows.  If you simply want the
executables, you can download them from the www.sleuthkit.org
website.

If you want to build your own executables, you have two options.
One is to use Microsoft Visual Studio.  The VS solution file is in
the win32 directory.  Refer to the BUILDING.txt file in that directory
for details.

You can also compile Windows executables using mingw32.  If you're
using mingw32 on Linux, simply give the "--host=i586-mingw32msvc"
argument when running the './configure' script and use 'make' to
compile.  If you're using mingw32 on Windows, './configure' and
'make' will work directly.

Note that to compile the Java bindings  you will need to have a JDK
to be installed, and by default the Oracle JDK on Windows is installed
in a path such as C:\Program Files\Java\jdk1.6.0_16\.  GNU autotools
(which is used if you do a mingw32 compile, but not a Visual Studio
compile) do not handle paths containing spaces, so you will need
to copy the JDK to a directory without spaces in the name, such as
C:\jdk1.6.0_16\, then add C:\jdk1.6.0_16\bin to $PATH before running
'./configure'

Note also that libtool may fail on mingw32 on Windows if
C:\Windows\system32 is on $PATH before /usr/bin.  The fix is to have
the C:\Windows directories at the _end_ of your mingw $PATH.

-------------------------------------------------------------------
carrier <at> sleuthkit <dot> org
Brian Carrier
