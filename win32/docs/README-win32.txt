                          The Sleuth Kit
                        Windows Executables

                http://www.sleuthkit.org/sleuthkit

               Brian Carrier [carrier@sleuthkit.org]

                     Last Updated: Dec 2009


======================================================================

This zip file contains the Microsoft Windows executables for The Sleuth
Kit.  The full source code (including Visual Studio Solution files) and 
documentation can be downloaded from:

http://www.sleuthkit.org

These are distributed under the IBM Public License and the Common 
Public License, which can be found in the licenses folder. 


NOTES

The dll files in the zip file are required to run the executables. They
must be either in the same directory as the executables or in the path.

mactime.pl requires a Windows port of Perl to be installed. If you have 
the ".pl" extension associated with Perl, you should be able to run
"mactime.pl" from the command line. Otherwise, you may need to run it
as "perl mactime.pl".  Examples of Windows ports of Perl include:
- ActivePerl (http://www.activestate.com/activeperl/)
- Strawberry Perl (http://strawberryperl.com/)


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
