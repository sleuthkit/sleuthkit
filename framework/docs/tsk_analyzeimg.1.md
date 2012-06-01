% tsk_analyzeimg(1) user manual
% Brian Carrier
% May 2012

# NAME

tsk_analyzeimg - Process a disk image using the TSK framework and pipelines.

# SYNOPSIS

tsk_anlyzeimg [-c *framework_config_file*] [-p *pipeline_config_file*] [-d *outdir*] [-vV] image_name

# DESCRIPTION

tsk_anlayzeimg is a command line tool that uses the Sleuth Kit Framework to analyze a disk image. The types of analysis that will occur will depend on what modules have been loaded into the pipelines. tsk_analyzeimg runs a file analysis pipeline on each file in the disk image and runs a post-processing pipeline after all files have been analyzed.

tsk_analyzeimg uses simple implementations of the framework services. It stores data in a SQLite database and uses a simple first in, first out queing method for the scheduler.

Refer to the [online docs](http://www.sleuthkit.org/sleuthkit/docs/framework-docs/) for more details on the framework and the pipelines.


# OPTIONS

-c *framework_config_file*
:   Location of the framework configuration file.  If not specified, then the current directory will be searched for one. 

-p *pipeline_config_file*
:   Location of the pipeline configuration file.  This specifies what modules  are run in each pipeline.  If not specified, then the current directory and the module directory as specified in the framework_config_file will be searched.  If specified, this overrides a pipeline config file that is specified in the framework config file. 

-d *outdir*
:   Location where output from analysis should be stored.  If not specified, then a directory with a name similar to the input image will be created in the directory with the input image. 

-V
:   Print version.

-v
:   Enable verbose mode.


# CONTACT

The Sleuth Kit source code and documentation can be downloaded from: 
<http://www.sleuthkit.org/>.

Send documentation updates to &lt; doc-updates at sleuthkit dot org &gt;.
