#!/usr/bin/python
# Authors:     James Migletz and Simson Garfinkel
# Description: Program extracts metadata from 
# Microsoft Office 2007 packages. Extraction works on
# .docx, .xlsx, and .pptx file types
# To Do:
# Incorporate recursive call to handled embedded docx files


#
# Filename:    docx_extractor.py
# Date:        27 Apr 2008
#
# See: http://www.diveintopython.org/xml_processing/index.html
# http://python.active-venture.com/lib/dom-example.html

import xml.dom.minidom
import sys
from subprocess import *
debug = False

# Only for future reference
# This prints all the methods that company[0].firstChild can respond to
        # It's another XML minidom object...
        #print dir(company[0].firstChild)
        #print dir(company[0])

def process_xml(xmlString):
    
    if(len(xmlString)==0): return
    # print "xml=",xmlString
    xml_dom = xml.dom.minidom.parseString(xmlString)
    if debug:
        u = xml_dom.toprettyxml(" ")
	print u.encode('ascii','replace')

    # try to find a paragraph revision ID
    # links settings.xml and styles.xml
    try:
        rsid = xml_dom.getElementsByTagName("w:p")[0].getAttribute('w:rsidR')

        if rsid and not(rsid in revisionIdArray):
               revisionIdArray.append(rsid)
	       drillDownOutput("Paragraph-Revision-ID", len(revisionIdArray), rsid)
     
    except IndexError:
        pass  

    # try to find a default paragraph revision ID
    # links to settings.xml and styles.xml
    try:
        rsidDef = xml_dom.getElementsByTagName("w:p")[0].getAttribute('w:rsidRDefault')

        if rsidDef and not(rsidDef in idDefaultArray):
               idDefaultArray.append(rsidDef)
	       drillDownOutput("Paragraph-Revision-ID-Default", len(revisionIdArray), rsidDef)

    except IndexError:
        pass    

    #try to find property text
    #if empty -- ignore
    try:
        propertyText = xml_dom.getElementsByTagName("w:r")[0].getAttribute('w:t')
        if not(propertyText in propertyTextArray) and propertyText:
               propertyTextArray.append(propertyText)
	       drillDownOutput("Property-Text", len(propertyTextArray), propertyText)
       
        #print "Property-Text",propertyText
    except IndexError:
        pass 
    
    # collect names associated with images
    try:
        imageFile = xml_dom.getElementsByTagName("pic:cNvPr")
        drillDown("Image", imageFile, 'name')
    except IndexError:
        pass 

    # get GUIDs from files for customXml info
    try:
        guid = xml_dom.getElementsByTagName("w:guid")
        drillDown("GUID", guid, 'w:val')
    except IndexError:
        pass  

    # get aliases for content control's structured data tag
    try: 
        sdt_alias = xml_dom.getElementsByTagName("w:alias")
        drillDown("Content-Control-Alias", sdt_alias, 'w:val')
    except IndexError:
        pass 
    
    # get tag names for content control's structured data tag
    try: 
        sdt_tags = xml_dom.getElementsByTagName("w:tag")
        drillDown("Content-Control", sdt_tags, 'w:val')
    except IndexError:
        pass
    
    # get id nums for content control's structured data tag
    try: 
        sdt_ids = xml_dom.getElementsByTagName("w:id")
        drillDown("Content-Control-Id", sdt_ids, 'w:val')
    except IndexError:
        pass

    # get data store id nums from customXml part
    try: 
        dataStore_ids = xml_dom.getElementsByTagName("ds:datastoreItem")
        drillDown("Data-Store-Item-Id", dataStore_ids, 'ds:itemID')
    except IndexError:
        pass
 
    # get relationship information (files in archive) from document.xml.rels  
    try: 
        relTarget = xml_dom.getElementsByTagName("Relationship")
        drillDown("Archive-File", relTarget, 'Target')
    except IndexError:
        pass

    # Attempt to retrieve "traditional" metadata
    # Some metadata is tied specifically to Word or PowerPoint
    createdDate = xml_dom.getElementsByTagName("dcterms:created")
    collectMetadata(createdDate, "Created: ")

    modifiedDate = xml_dom.getElementsByTagName("dcterms:modified")
    collectMetadata(modifiedDate, "Last-Modified: ")

    creator = xml_dom.getElementsByTagName("dc:creator")
    collectMetadata(creator, "Creator: ")   

    title = xml_dom.getElementsByTagName("dc:title")
    collectMetadata(title, "Title: ")

    subject = xml_dom.getElementsByTagName("dc:subject")
    collectMetadata(subject, "Subject: ")

    description = xml_dom.getElementsByTagName("dc:description")
    collectMetadata(description, "Description: ")

    keywords = xml_dom.getElementsByTagName("cp:keywords")
    collectMetadata(keywords, "Keywords: ")

    revisionNum = xml_dom.getElementsByTagName("cp:revision")
    collectMetadata(revisionNum, "Revision: ")

    lastMod = xml_dom.getElementsByTagName("cp:lastModifiedBy") 
    collectMetadata(lastMod, "LastSavedBy: ")   

    application = xml_dom.getElementsByTagName("Application")
    collectMetadata(application, "Generator: ")  
        
    company = xml_dom.getElementsByTagName("Company")
    collectMetadata(company, "Company: ")  

    template = xml_dom.getElementsByTagName("Template")
    collectMetadata(template, "Template: ")  

    pages = xml_dom.getElementsByTagName("Pages")
    collectMetadata(pages, "Number-of-Pages: ") 

    lines = xml_dom.getElementsByTagName("Lines")
    collectMetadata(lines, "Number-of-Lines: ") 

    paragraphs = xml_dom.getElementsByTagName("Paragraphs")
    collectMetadata(paragraphs, "Number-of-Paragraphs: ") 

    words = xml_dom.getElementsByTagName("Words")
    collectMetadata(words, "Number-of-Words: ") 

    characters = xml_dom.getElementsByTagName("Characters")
    collectMetadata(characters, "Number-of-Characters: ") 

    slides = xml_dom.getElementsByTagName("Slides")
    collectMetadata(slides, "Number-of-Slides: ") 

    hiddenSlides = xml_dom.getElementsByTagName("HiddenSlides")
    collectMetadata(hiddenSlides, "Number-of-Hidden-Slides: ") 

    notesPages = xml_dom.getElementsByTagName("Notes")
    collectMetadata(notesPages, "Number-of-Notes: ") 

    mediaClips = xml_dom.getElementsByTagName("MMClips")
    collectMetadata(mediaClips, "Number-of-'Multi-Media'-Clips: ") 

    presFormat = xml_dom.getElementsByTagName("PresentationFormat")
    collectMetadata(presFormat, "Presentation-Format: ")  
    

# method drills into xml when there is more than one element
# associated with a tag name within a file
# Secondary check is completed to ignore duplicate entries
# and to insure label is unique
#
# Parameters
#    label     - to be printed with value of attribute
#    tag_array - array of minidom objects 
#    tag_name  - value to be obtained  
def drillDown(label, tag_array, tag_name):
    total_count = range(0, tag_array.length)

    for x in total_count:
          val = tag_array[x].getAttribute(tag_name)
          if val:

            if label.startswith("Archive-File"):
               if not(val in targetArray):
                  targetArray.append(val)
                  drillDownOutput(label, len(targetArray), val)

            elif label.endswith("Content-Control"):
		 if not(val in sdtTagArray):
                    sdtTagArray.append(val)
                    drillDownOutput(label, len(sdtTagArray), val)

            elif label.endswith("Content-Control-Id"):
		 if not(val in sdtIdArray):
                    sdtIdArray.append(val)
		    drillDownOutput(label, len(sdtIdArray), val)

            elif label.endswith("Content-Control-Alias"):
		 if not(val in sdtAliasArray):
                    sdtAliasArray.append(val)
		    drillDownOutput(label, len(sdtAliasArray), val)

            elif label.endswith("GUID"):
		 if not(val in GUID_Array):
                    GUID_Array.append(val)
		    drillDownOutput(label, len(GUID_Array), val)

            elif label.endswith("Data-Store-Item-Id"):
		 if not(val in dataStoreArray):
                    dataStoreArray.append(val)
		    drillDownOutput(label, len(dataStoreArray), val)

            elif label.endswith("Image"):
		 if not(val in imageArray):
                    imageArray.append(val)
		    drillDownOutput(label, len(imageArray), val)
            else:
                 print label + ":",val        
       

# method prints the output in label : value format (DGI)
# Parameters:
#    label    - to be printed with text of object 
#    count    - number of times label has appeared 
#               with unique values
#    value    - value to be printed with label
def drillDownOutput(label, count, value):
    print label+ `count` + ":",value
            
    
# method prints metadata associated with an array
# of minidom objects, and prints label and value
# if one exists
# Parameters:
#    tagArray - array of minidom objects
#    label    - to be printed with text of object 
def collectMetadata(tagArray, label):
    if tagArray and tagArray[0].hasChildNodes():
        text = tagArray[0].firstChild.wholeText.strip().replace("\r"," ").replace("\n"," ")
        print label,text

def process(fn):
    #define and initialize counters
    import zipfile
    global targetCounter 
    targetCounter = 0

    if not zipfile.is_zipfile(fn):
        return

    z = zipfile.ZipFile(fn,mode="r")
    for f in z.namelist():
        if f.endswith(".xml") or f.endswith(".rels"):
            process_xml(z.open(f).read())

        
          

#define and initialize arrays/lists for tags        
targetArray = []
idDefaultArray = []
revisionIdArray = []
sdtTagArray = []
sdtIdArray = []
sdtAliasArray = []
imageArray = []
GUID_Array = []
dataStoreArray = []
propertyTextArray = []
imageArray = []

#start the program here
if (len(sys.argv) < 2):
   print "Usage: docx_extractor filename.***x"
   sys.exit()
else:
   if(__name__=="__main__"):
       process(sys.argv[1])

