                          The Sleuth Kit
                        Windows Executables

                http://www.sleuthkit.org/sleuthkit

               Brian Carrier [carrier@sleuthkit.org]

                     Last Updated: Sept 2008


======================================================================

This zip file contains the Microsoft Windows executables for The Sleuth
Kit.  The full source code (including Visual Studio Solution files) and 
documentation can be downloaded from:

http://www.sleuthkit.org

These are distributed under the IBM Public License and the Common 
Public License, which can be found in the licenses folder. 


CURRENT LIMITATIONS

The tools do not currently support globbing, which means that you 
cannot use 'fls img.*' on a split image.  Windows does not automatically
 expand the '*' to all file names. 

These programs can be run on a live system, if you use the 
\\.\PhysicalDrive0 syntax.  Note though, that you may get errors or the
file system type may not be detected because the data being read is out 
of sync with cached versions of the data.  

Unicode characters are not always properly displayed in the command
shell.

The AFF image formats are not supported. 
