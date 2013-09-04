File Type Detection Based on Signature Module
Sleuth Kit Framework C++ Module
July 2012. Updated Dec 2012.

This module is for the C++ Sleuth Kit Framework.


DESCRIPTION

This module is a file analysis module that examines the file content
to determine its type (i.e. PDF, JPEG).  It does this based on file
signatures in libmagic.

DEPLOYMENT REQUIREMENTS

This module has the following deployment requirements for each platform.

Linux:

1. libmagic1
2. libmagic-dev

Install libmagic1 and libmagic-dev packages, or download the source from one of these places:
    ftp://ftp.astron.com/pub/file/
    https://github.com/glensc/file
If downloaded from the FTP site, the source archive name will be something like "file-5.11.tar.gz".

Win32:

1. libmagic-1.dll must be in the same folder as the module.
2. The magic file "magic.mgc" must be in a folder named
   "FileTypeSigModule" in your modules folder.

See also "README_BuildingLibMagicWin32.txt".

USAGE

Add this module to a file analysis pipeline.  See the TSK 
Framework documents for information on adding the module 
to the pipeline:

    http://www.sleuthkit.org/sleuthkit/docs/framework-docs/

This module takes no configuration arguments.  

RESULTS

The result of the signature check is written to an attribute
in the blackboard.

LICENSES

This module uses libmagic.  It has the following license requirements:

$File: COPYING,v 1.1 2008/02/05 19:08:11 christos Exp $
Copyright (c) Ian F. Darwin 1986, 1987, 1989, 1990, 1991, 1992, 1994, 1995.
Software written by Ian F. Darwin and others;
maintained 1994- Christos Zoulas.

This software is not subject to any export provision of the United States
Department of Commerce, and may be exported to any country or planet.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice immediately at the beginning of the file, without modification,
   this list of conditions, and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
 
THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
SUCH DAMAGE.
