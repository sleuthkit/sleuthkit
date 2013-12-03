Interesting Files Module
Sleuth Kit Framework C++ Module
May 2012


This module is for the C++ Sleuth Kit Framework.


DESCRIPTION

This module is a post-processing module that looks for files
matching criteria specified in a module configuration file. 
This module is useful for identifying all files of a given
type (based on extension) or given name or contained in a 
directory of a given name. 

DEPLOYMENT REQUIREMENTS

This module requires a configuration file (discussed below).
The location of the configuration file can be passed as an
argument to the module. 
If the location is not passed as an argument the module will 
look for a file named "interesting_files.xml" in a folder named 
"InterestingFilesModule" located in the modules folder.

USAGE

Add this module to a post-processing/reporting pipeline.  See the TSK 
Framework documents for information on adding the module 
to the pipeline:

    http://www.sleuthkit.org/sleuthkit/docs/framework-docs/

The module takes the path to the configuration file as an argument. 
The configuration file is an XML document that defines interesting
file sets in terms of search criteria.  Here is a sample: 

<?xml version="1.0" encoding="utf-8"?>
<INTERESTING_FILES ignoreKnown="0">
    <INTERESTING_FILE_SET name="HTMLFilesType" description="Files with extension .htm*">
        <EXTENSION typeFilter="file">.htm*</EXTENSION>
    </INTERESTING_FILE_SET>
    <INTERESTING_FILE_SET name="Password" description="Files with password in the name">
        <NAME typeFilter="file">*password*</NAME>
    </INTERESTING_FILE_SET>
    <INTERESTING_FILE_SET name="HTMLFiles" description="Files named file.htm or file.html">
        <NAME typeFilter="file">file.htm</NAME>
        <NAME typeFilter="file">file.html</NAME>
    </INTERESTING_FILE_SET>
    <INTERESTING_FILE_SET name="TextFiles" description="Files with .txt extensions">
        <EXTENSION typeFilter="file">.txt</EXTENSION>
    </INTERESTING_FILE_SET>
    <INTERESTING_FILE_SET name="JPEGFiles" description="JPEG files">
        <EXTENSION typeFilter="file">.jpg</EXTENSION>
        <EXTENSION typeFilter="file">.jpeg</EXTENSION>
    </INTERESTING_FILE_SET>
    <INTERESTING_FILE_SET name="SuspiciousFolders" description="Contents of suspicious folders">
        <NAME typeFilter="dir">/DIR1/</NAME>
        <NAME typeFilter="dir">/DIR2/</NAME>
      </INTERESTING_FILE_SET>
    <INTERESTING_FILE_SET name="SuspiciousDocs" description="Suspicious files">
        <NAME typeFilter="file">readme.txt</NAME>
        <NAME typeFilter="file" pathFilter="installer\installs">install.doc</NAME>
        <EXTENSION>.bak</EXTENSION>
    </INTERESTING_FILE_SET>
</INTERESTING_FILES>

Each 'INTERESTING_FILE_SET' element must be given a unique name using its
'name' attribute.  If this attribute is omitted, the module generates a 
default name (e.g., Unamed_1, Unamed_2, etc.). 

The 'description' attribute of 'INTERESTING_FILE_SET' element is optional.  
Its intended use is to describe why the search is important.  It could 
let the end user know what next step to take if this search is successful.

Each 'INTERESTING_FILE_SET' element may contain any number of 'NAME' and/or 
'EXTENSION' elements.

A 'NAME' element says search the file names for a file or directory with a 
name that matches the element text.  The match must be an exact length, 
case insensitive match.  For example, the string "bomb" will not match "abomb". 

An 'EXTENSION' element says search the end of file names for the element text. 
If the leading "." is omitted the module will add it. 

Wildcard is supported in both 'NAME' and 'EXTENSION' elements. The asterisk
character '*' is used to represent a match of zero or more characters.

'NAME' and 'EXTENSION' elements may be qualified with optional 'typeFilter'
attributes. Valid values for 'typeFilter' are 'file' (for regular files) and 
'dir' (for directories).  If no 'typeFilter' is specified, directories and
*any* type of file are valid matches.  For example, in the sample above, the
search named "SuspiciousFiles" will find files and directories that end in
".bak", including files and directories named ".bak". 

'NAME' and 'EXTENSION' elements may be qualified with optional 'pathFilter'
attributes. Matches with this filter must contain the specified string as
a sub-string of the file or directory path.

Known files (e.g. files in the NSRL) can be ignored by providing the 
'ignoreKnown' attribute either on the top level 'INTERESTING_FILES' element
or on one or more 'INTERESTING_FILE_SET' elements.
The following valid values for the 'ignoreKnown' attribute are based on the
TskImgDB::KNOWN_STATUS enumeration in TskImgDB.h.

  0 - All known files (both good and bad)
  1 - Known good files
  2 - Known bad (or notable) files
  3 - Unknown files

The ability to ignore known files depends on the existence of a hash database
along with hash calculation and lookup modules.
  
RESULTS

The result of the lookup is written to the blackboard as an artifact. 
You can use the SaveInterestingFiles module to save the identified 
files to a local directory. 




