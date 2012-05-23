% tsk_validatepipeline(1) user manual
% Brian Carrier
% May 2012

# NAME

tsk_validatepipeline - Process a TSK framework pipeline configuration file to ensure that it is valid and all modules can be found. 

# SYNOPSIS

tsk_validatepipeline framework_config_file pipeline_config_file

# DESCRIPTION

tsk_validatepipeline is a command line tool for the Sleuth Kit (TSK) Framework that enables you to validate if a pipeline configuration file has valid syntax and that all modules can be loaded.  This tool is useful if you are using the framework in an automated or distributed environment where the pipeline is run without user interaction and you want to verify that the configuration file is correct before adding it to the system.

Refer to the [online docs](http://www.sleuthkit.org/sleuthkit/docs/framework-docs/) for more details on the framework and the pipelines.


# CONTACT

The Sleuth Kit source code and documentation can be downloaded from: 
<http://www.sleuthkit.org/>.

Send documentation updates to &lt; doc-updates at sleuthkit dot org &gt;.
