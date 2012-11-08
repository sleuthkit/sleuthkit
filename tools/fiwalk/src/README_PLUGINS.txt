The fiwalk plugin system 
=======================


fiwalk has a plug-in system that allows arbitrary programs to be run
on every file in a disk image that is being extracted.

The plugins to run are specified by a configuration file. 

Two plugin systems have been designed:

    dgi - The plug-in runs as a stand-alone Unix executable.
          argv[1] of the plugin is the name of the file to run on.
	  This file is created in the /tmp directory before the plugin
          is run and is removed when the plugin is finished.  The
          plugin outputs what it finds as "name: value" pairs to
          stdout.

    jvm - A Java virtual machine interface. fiwalk communicates with
          the jvm using a TCP socket. In this way only one instance of
          the plugin needs to be created.  However, the JVM interface
          hasn't been created yet. Sorry.

You'll probably be using the dgi interface.

Here is a configuration file:

	  #
	  # Configuration file for fiwalk
	  #


	  #*.jpeg	dgi	java -classpath ../plugins/plugins.jar jpeg_extract
	  #*.jpeg	jvm	../plugins/jpeg_extract.jar jpeg_extract

	  *.jpeg	dgi	../plugins/jpeg_extract
	  *.jpg		dgi	../plugins/jpeg_extract
	  *.pdf		dgi	java -classpath ../plugins/plugins.jar Libextract_plugin
	  *.gif		dgi	java -classpath ../plugins/plugins.jar Libextract_plugin
	  *.mp3		dgi	java -classpath ../plugins/plugins.jar Libextract_plugin
	  *.doc		dgi	java -classpath ../plugins/plugins.jar word_extract
	  *.xls		dgi	java -classpath ../plugins/plugins.jar word_extract
	  *.ppt		dgi	java -classpath ../plugins/plugins.jar word_extract
	  *.docx	dgi	python ../plugins/docx_extractor.py
	  *.xlsx	dgi	python ../plugins/docx_extractor.py
	  *.pptx	dgi	python ../plugins/docx_extractor.py
	  *.odt		dgi	python ../plugins/odf_extractor.py
	  *.ods		dgi	python ../plugins/odf_extractor.py
	  *.odp		dgi	python ../plugins/odf_extractor.py

The configuration file that you are using is specified with the "-c" option.

Comments being with "#"

Notice that filenames are trusted. However, you can specify a plugin
that matches "*" and it will match every filename.

Notice also that plugins can be written in a scripting language if you
specify the interperter as the first word after dgi.

Here is a simple plugin that would just count the number of words in a
file.


	#!/bin/sh
	echo "Words: " `wc $1`


(Put this in a file called word-count-plugin.sh and make it executable.)

And here is a config file that would cause all of the words in all of
the files to be counted.


        # A silly plugin file
        # run the word count on everything.
        #
	*    dgi	word-count-plugin.sh

