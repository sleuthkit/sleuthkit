Zip Exraction Module
Sleuth Kit Framework C++ Module
May 2012


This module is for the C++ Sleuth Kit Framework.


DESCRIPTION

This module extracts the files stored inside of ZIP files. This
enables you to find all possible files with evidence. Files 
extracted from ZIP files are scheduled so that they can later be
analyzed in a file analysis pipeline.

DEPLOYMENT REQUIREMENTS

This module does not have any specific deployment requirements.

USAGE

Add this module to a file analysis pipeline.  See the TSK 
Framework documents for information on adding the module 
to the pipeline:

    http://www.sleuthkit.org/sleuthkit/docs/framework-docs/

This module takes no configuration arguments.  

RESULTS

The files are extracted, added to the database, and scheduled
for analysis. 