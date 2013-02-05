bin_PROGRAMS = jpeg_extract 
jpeg_extract_SOURCES = jpeg_extract.cpp

EXTRA_DIST = jpeg_extract.java word_extract.java Libextract_plugin.java ficonfig.txt\
    docx_extractor.py docx_grep.py odf_extractor.py

plugins.jar: jpeg_extract.class word_extract.class Libextract_plugin.class
	jar cfv plugins.jar jpeg_extract.class word_extract.class Libextract_plugin.class

jpeg_extract.class: jpeg_extract.java 
	javac jpeg_extract.java

word_extract.class: word_extract.java 
	javac word_extract.java

Libextract_plugin.class: Libextract_plugin.java 
	javac Libextract_plugin.java
