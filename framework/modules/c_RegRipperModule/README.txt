Reg Ripper Module
Sleuth Kit Framework C++ Module
May 2012


This module is for the C++ Sleuth Kit Framework.


DESCRIPTION

This module is a report/post-processing module that runs the RegRipper 
executable against the common set of Windows registry files (i.e., NTUSER, 
SYSTEM, SAM and SOFTWARE).

This module allows you to extract information from the system's registry.

DEPLOYMENT REQUIREMENTS

This module requires that RegRipper be installed on the system. You can 
download it from:

    http://regripper.wordpress.com/


USAGE

Add this module to a post-processing/reporting pipeline.  See the TSK 
Framework documents for information on adding the module 
to the pipeline:

    http://www.sleuthkit.org/sleuthkit/docs/framework-docs/


This module takes optional configuration arguments in a semi-colon separated 
list of arguments:

	-e Path to the RegRipper executable
	-o Path to directory in which to place RegRipper output

If the executable path is omitted the module will look for RegRipper/rip.exe
in the program directory. If the executable is not found there, it will try
to find it using the system PATH environment variable.

If the output directory path is omitted, the module will store the results in
a "RegRipper" directory in the module output directory specified in the framework 
system properties.   

This module currently pulls out operating system information and posts it to
the blackboard. The OS name and version will be available with the base version
of RegRipper. If you want to get the processor architecture as well place the 
included RegRipper plugin (processorarchitecture.pl) in the RegRipper plugins
directory and update the "system" file in that directory to include
"processorarchitecture" as it's own line.


NON-WINDOWS PLATFORMS

The module executable path argument (`-e`) may point to the RegRipper perl file
instead of the Windows executable, e.g. `-e /foobar/rrv2.5/rip.pl`.

If necessary, the executable path may include the interpreter command itself,
e.g. `-e perl /foobar/rrv2.5/rip.pl`.

Requirements:

* Perl is installed.
* You have downloaded and unzipped:
    * RegRipper
    * RegRipper plugins (regripperplugins)
    * Parse-Win32Registry (http://search.cpan.org/~jmacfarla/Parse-Win32Registry-0.40/)
    
The RegRipper script (rip.pl) may need modification to run on your system.
RegRipper Plugins must be copied to a `plugins` subdirectory relative to where
rip.pl exists. Parse-Win32Registry must be properly installed for Perl to find
it. If that is not possible, a workaround is to provide it as an argument to
Perl, e.g. `perl -p /foo/Parse-Win32Registry-1.0/lib /foobar/rrv2.5/rip.pl`.


RESULTS

The RegRipper output will be located in the location as described in the 
previous section. Currently, the module does not interpret any of the results.
It simply runs the tool.  It will save the analysis results from each 
hive to its own text file. Errors from RegRipper will be logged to 
RegRipperErrors.txt in the output directory.


TODO
- Make the module find RegRipper if is in the module's configuration directory.
