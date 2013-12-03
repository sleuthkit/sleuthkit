Tsk Summary Report Module
Sleuth Kit Framework C++ Module
May 2012

This module is for the C++ Sleuth Kit Framework.


DESCRIPTION

This module is a post-processing module that creates a generic HTML report based on data in
the blackboard.  This report will show the results from previously run analysis 
modules.  This report is intended to be used by developers so that they can 
see what their modules are posting to the blackboard and for users who want a
very generic report.  In the future, module writers will hopefully make more
customized reports. 

This report has one table per artifact type that was found during the analysis.  
Each table will have a column for each attribute.  There is a row for each
artifact.

DEPLOYMENT REQUIREMENTS

This module does not have any specific deployment requirements.

USAGE

Add this module to a post-processing analysis pipeline.  See the TSK 
Framework documents for information on adding the module to the pipeline:

    http://www.sleuthkit.org/sleuthkit/docs/framework-docs/

This module takes no configuration arguments.  


RESULTS

The HTML report is saved to the "Reports" folder in the output directory as defined
in the framework for that session.


TODO:
 - Add parameters to allow for selective artifact/attribute lookup for more custom
   reports.
 - Add a table of contents showing the artifact types and the counts of artifacts
   with links to the tables for easier navigation.



