Entropy Calculation Module
Sleuth Kit Framework C++ Module
May 2012


This module is for the C++ Sleuth Kit Framework.


DESCRIPTION

This module is a file analysis module that performs an 
entropy calculation for the contents of a given file. Entropy
shows how random the file is and can be used to detect 
encrypted or compressed files.

DEPLOYMENT REQUIREMENTS

This module does not have any specific deployment requirements.

USAGE

Add this module to a file analysis pipeline.  See the TSK 
Framework documents for information on adding the module 
to the pipeline:

    http://www.sleuthkit.org/sleuthkit/docs/framework-docs/

This module takes no configuration arguments.  

RESULTS

The result of the calculation is written to an attribute
in the blackboard.
