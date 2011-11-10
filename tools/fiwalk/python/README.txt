Image Redaction Project.

This program redacts disk image files. 

inputs:
	* The disk image file
	* A set of rules that describe what to redact, and how to redact it.

Rule File format:

The readaction command file consists of commands. 
Each command has an "condition" and an "action"

  [condition] [action]

Conditions:
  FILENAME <afilename> - a file with the given name
  FILEPAT  <a file pattern> - any give with a given pattern
  DIRNAME  <a directory> - any file in the directory 
  MD5 <a md5> - any file with the given md5
  SHA1 <a sha1> - any file with the given sha1 
  CONTAINS <a string> - any file that contains <a string>

Actions:
  SCRUB MATCH - Scrubs the pattern where it occures
  SCRUB SECTOR - Scrubs the block where the patern occures
  SCRUB FILE - Scrubs the file in which the pattern occures

Actions:
   FILL 0x44	- overwrite by filling with character 0x44 ('D')
   ENCRYPT      - encrypts the data
   FUZZ		- fuz the binary, but not the strings

Examples:

Example file:
===============

MD5 3482347345345 SCRUB FILE
MATCH simsong@acm.org SCRUB FILE
MATCH foobar SCRUB BLOCK
================================================================
Other actions in file:

KEY 12342343  (an encryption key)


================================================================
iverify:
 this program can read an fiwalk XML file and an image file.
 It can produce:
  * A simple report of which are present and which are not.
  * An annotate XML file of which files are present.

  * iverify can read multiple input files and produce a single xml output file
