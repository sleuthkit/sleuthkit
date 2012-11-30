#!/usr/bin/python
# This is a python program
# See: http://www.diveintopython.org/xml_processing/index.html
# http://python.active-venture.com/lib/dom-example.html

# Author: James Migletz
# Filename: odf_extractor.py
# Date:   6 May 08
# Description: This program parses Open Office documents
# and extracts metadata from the files.

# Usage: odf_extractor filename.od*
 
import xml.dom.minidom
import sys
from subprocess import *

def process_xml(xmlString):
    if(len(xmlString)==0): return
    # print "xml=",xmlString
    xml_dom = xml.dom.minidom.parseString(xmlString)
    # print xml_dom.toprettyxml(" ")
     
    #output the metadata

    createdDate = xml_dom.getElementsByTagName("meta:creation-date")
    if createdDate and createdDate[0].hasChildNodes(): 
        print "CreatedDate: ",createdDate[0].firstChild.wholeText

    date = xml_dom.getElementsByTagName("dc:date")
    if date and date[0].hasChildNodes(): 
        print "Last-Modified: ",date[0].firstChild.wholeText

    creator = xml_dom.getElementsByTagName("dc:creator")   
    if creator and creator[0].hasChildNodes():
        print "Creator: ",creator[0].firstChild.wholeText

    initialCreator = xml_dom.getElementsByTagName("meta:initial-creator")
    if initialCreator and initialCreator[0].hasChildNodes():
        print "Initial Creator: ",initialCreator[0].firstChild.wholeText

    revisionNum = xml_dom.getElementsByTagName("meta:editing-cycles")
    if revisionNum and revisionNum[0].hasChildNodes():
        print "Revision: ",revisionNum[0].firstChild.wholeText

    application = xml_dom.getElementsByTagName("meta:generator")
    if application and application[0].hasChildNodes():
        print "Generator: ",application[0].firstChild.wholeText  

    try:
        documentStats = xml_dom.getElementsByTagName("meta:document-statistic")
        collectAll("Number-of-Characters: ", documentStats, 'meta:character-count')
        collectAll("Number-of-Words: ", documentStats, 'meta:word-count')
        collectAll("Number-of-Paragraphs: ", documentStats, 'meta:paragraph-count')
        collectAll("Number-of-Pages: ", documentStats, 'meta:page-count') 
        collectAll("Number-of-Images: ", documentStats, 'meta:image-count') 
        collectAll("Number-of-Objects: ", documentStats, 'meta:object-count') 
        collectAll("Number-of-Tables: ", documentStats, 'meta:table-count') 
    except IndexError:
        pass 

def collectAll(label, tag_array, tag_name):
    val = tag_array[0].getAttribute(tag_name)
    if val:
          print label + val  

def process(fn):
    try:
       """Process a file fn"""
       unzip_output = Popen(['unzip','-l',fn],stdout=PIPE).stdout.read()
       files = unzip_output.split("\n")
       files = files[3:-3]
       files = [x[28:] for x in files] # now we have a list of all the files in the zip archive
       for f in files:
           if f.endswith(".xml"):
              null = open("/dev/null","w")
              process_xml(Popen(['unzip','-p',fn,f],stdout=PIPE,stderr=null).stdout.read())
    except IOError, err:
           print "Error opening ", fn, err
           sys.exit()
        
    

if (len(sys.argv) < 2):
   print "Usage: odf_extractor filename.od*"
   sys.exit()
else:
   if(__name__=="__main__"):
       process(sys.argv[1])

