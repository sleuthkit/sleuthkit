                          The Sleuth Kit
                        Win32 README File

                http://www.sleuthkit.org/sleuthkit

                     Last Modified: Sept 2008

====================================================================
The Sleuth Kit (TSK) runs on Windows.  If you simply want the
executables, you can download them from the www.sleuthkit.org
website.

If you want to build your own executables, you have two options.
One is to use Microsoft Visual Studio.  The VS solution file is in
the win32 directory.  Refer to the BUILDING.txt file in that directory
for details.

You can also compile Windows executables on Linux using mingw32.
Simply give the "--host=i586-mingw32msvc" argument when running the
'./configure' script and use 'make' to compile.

-------------------------------------------------------------------
carrier <at> sleuthkit <dot> org
Brian Carrier
