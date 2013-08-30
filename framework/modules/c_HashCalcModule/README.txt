Hash Calculation Module
Sleuth Kit Framework C++ Module
May 2012


This module is for the C++ Sleuth Kit Framework.


DESCRIPTION

This module is a file analysis module that calculates 
MD5 or SHA-1 hash values of file content.  Hash values
are used to detect known files and are used to later show
that file content has not changed. 


DEPLOYMENT REQUIREMENTS

This module does not have any specific deployment requirements.


USAGE

Add this module to a file analysis pipeline.  See the TSK 
Framework documents for information on adding the module 
to the pipeline:

    http://www.sleuthkit.org/sleuthkit/docs/framework-docs/

By default, the module will only calculate the MD5 hash.
To configure the module to calculate SHA-1 or both values,
then pass either "MD5" or "SHA1" in the pipeline config file.
If you want to specify that both be calculated, then specify
both strings in any order and with spaces or commas in between. 


RESULTS

The hash values are stored in the central database. 

