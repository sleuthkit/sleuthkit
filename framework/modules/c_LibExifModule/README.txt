c_LibExifModule
Sleuth Kit Framework C++ Module
August 2012
===============

C++ Sleuth Kit Framework module that wraps libexif to pull out EXIF data.

DESCRIPTION

This module is a file analysis module that will check JPEG files for
an exif header, then parse any found headers for metadata of interest.
Any metadata of interest will be posted to the blackboard.

DEPLOYMENT REQUIREMENTS

This module does not have any specific deployment requirements.

USAGE

Add this module to a file analysis pipeline. See the TSK
Framework documents for information on adding the module
to the pipeline:

    http://www.sleuthkit.org/sleuthkit/docs/framework-docs/

RESULTS

All results will be posted to the blackboard as TSK_METADATA_EXIF artifacts.
Currently, it extracts dates, author, device, and GPS information. 

TODO
- Make metadata of interest configurable. Ie: allow the module to be configured
to pull out exif data other than the attributes we have hard coded.

LICENSES

This module uses libexif 0.6.20 (http://libexif.sourceforge.net).
libexif is licensed under the GNU LESSER GENERAL PULIC LICENSE Version 2.1 (LGPL).

See http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html#TOC1