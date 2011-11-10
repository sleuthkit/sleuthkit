#!/usr/bin/python
# Authors:     James Migletz and Simson Garfinkel
# Description: Compare two XML-containing ZIP files.
# * Report parts that are unique to each file.
# * For parts that are common to each file, run tkdiff 
#
# Filename:    docx_diff.py
# Date:        24 Feb 2008
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
    #global imageList
    #global imageCount
    if(len(xmlString)==0): return
    # print "xml=",xmlString
    xml_dom = xml.dom.minidom.parseString(xmlString)
    if debug:
        u = xml_dom.toprettyxml(" ")
	print u.encode('ascii','replace')

def prettyprint_diff(partname,part1,part2):
    # print "prettyprint_diff(%s,%s)" %(part1,part2)
    partname = partname.replace("/","")

    from tempfile import NamedTemporaryFile
    f1 = NamedTemporaryFile(suffix="    "+partname)
    f1.write(xml.dom.minidom.parseString(part1).toprettyxml(" ").encode('ascii','replace'))
    f1.flush()

    f2 = NamedTemporaryFile(suffix="    "+partname)
    f2.write(xml.dom.minidom.parseString(part2).toprettyxml(" ").encode('ascii','replace'))
    f2.flush()
    
    Popen(["tkdiff",f1.name,f2.name]).wait()


def get_filenames(zipfile):
    """ Returns an array with a list of the contained filenames """
    unzip_output = Popen(['unzip','-l',zipfile],stdout=PIPE).stdout.read()
    files = unzip_output.split("\n")
    files = files[3:-3]
    files = [x[28:] for x in files] # now we have a list of all the files in the zip archive
    return files

def get_part(zipfile,part):
    """ Returns the part """
    return Popen(['unzip','-p',zipfile,part],stdout=PIPE).stdout.read()

def diff(fn1,fn2):
    """Process a file fn"""
    list1 = get_filenames(fn1)
    list2 = get_filenames(fn2)

    print "diff(%s,%s)" % (fn1,fn2)
    onlyin1 = []
    for i in list1:
        if i not in list2:
            onlyin1.append(i)
    if onlyin1:
        print "Pieces only in %s:" % fn1
        print "\n".join(onlyin1)

    onlyin2 = []
    for i in list2:
        if i not in list1:
            onlyin2.append(i)
    if onlyin2:
        print "Pieces only in %s:" % fn2
        print "\n".join(onlyin2)

    both = []
    for i in list1:
        if i in list2: both.append(i)

    print "Pieces in both:"
    print "\n".join(both)

    print "Pieces different in both:"
    for partname in both:
        print ""
        part1 = get_part(fn1,partname)
        part2 = get_part(fn2,partname)
        if part1 != part2:
            if part1[0]=='<' and part2[0]=='<':
                prettyprint_diff(partname,part1,part2)
            else:
                print "%s: type not recognized" % partname

        
    
imageArray = []
imageCount = 0
if(__name__=="__main__"):
    if(len(sys.argv)!=3):
        print "usage: %s <file1> <file2>" % sys.argv[0]
        sys.exit(1)
    diff(sys.argv[1],sys.argv[2])
