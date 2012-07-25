                       Sleuth Kit Framework

                        Binary Distribution


                           July 2012


OVERVIEW


This document describes the binary distribution of The Sleuth Kit (TSK)
Framework.  The framework makes it easier to develop end-to-end digital
forensics systems that analyze disk images.  It provides a plug-in
infrastructure that allows you to have modules to do various types of
file analysis.  The binary distribution of the framework comes with
pre-compiled tools that use the framework, including a basic set of
"official" modules.   You can find other third-party modules that you
can also use with the framework.

NOTE: This is not an SDK package that would be used to develop systems
that leverage the framework.  The binary distribution package provides
access to the tsk_anlayzeimg tool that allows you to analyze a disk
image using the framework and other pre-compiled programs.



FRAMEWORK BASICS

Refer to the documentation on the sleuthkit.org website for the 
framework basics. 

	http://www.sleuthkit.org/sleuthkit/docs/framework-docs



FRAMEWORK SETUP

The framework and pipeline configuration files are both in the bin
directory.  The analysis modules are all located in the modules
folder.   If you want to add more modules to the system, then you can 
copy them into that folder and update the pipeline configuration file.


The README documents for each of the modules can be found in the docs
folder. 



USING THE FRAMEWORK

The framework will be most useful when it starts to get incorporated into
more tools and starts to have more modules written for it.  For now, the
easiest way to use the framework is using tsk_analyzeimg.  It will take
a disk image as input, populate a SQLite datbase, and run the pipelines
on its contents. You can run the standard set of modules on an image or
you can add other third-party modules.  It can optionally carve data with
scalpel.  See the tsk_analyzeimg help file for more details. 



LICENSES

The source code that make up the framework contains:
- IBM Public License (original TCT code)
- Common Public License (most of TSK)
- LGPL (libewf)
- ZLIB License (zlib, via libewf)
- Boost Software License (POCO)

-----------------------------------------------------------------------
Brian Carrier
carrier <at> sleuthkit <dot> org
