Tsk Hash Lookup Module
Sleuth Kit Framework C++ Module
May 2012


This module is for the C++ Sleuth Kit Framework.


DESCRIPTION

This module is a file analysis module that looks up a file's MD5 
hash value in one or more hash databases that have been indexed using the
Sleuth Kit's hfind tool.  Hash databases are used to identify files that are
'known' and previously seen.  Known files can be both good (such as standard 
OS files) or bad (such as contraband).

DEPLOYMENT REQUIREMENTS

The module requires that at least one hash database indexed using the Sleuth 
Kit's hfind tool is specified in its arguments.  See the link below for instructions
on using the Sleuthkit's hfind tool to create an NSRL database index file.

  http://www.sleuthkit.org/informer/sleuthkit-informer-7.html#nsrl 


USAGE

Add this module to a file analysis pipeline.  See the TSK 
Framework documents for information on adding the module 
to the pipeline:

    http://www.sleuthkit.org/sleuthkit/docs/framework-docs/


This module takes a semi-colon delimited list of arguments:

     -k <path> The path of a 'known' files hash database.
     -b <path> The path of a 'known bad' or 'notable' files hash database.
               Multiple 'known bad' hash sets may be specified.
     -s        A flag directing the module to issue a pipeline stop request if
               a hash set hit occurs.


RESULTS

Each hash set hit that is found is posted to the blackboard. If directed to do
so, the module will also stop the file analysis pipeline for the file when a hit 
occurs.

TODO:
 - Make a downstream module to issue stop requests after reading results 
   from the blackboard. This would allow for multiple decision making criteria
   and would support the ability to insert additional processing between the 
   look up and the decision.
