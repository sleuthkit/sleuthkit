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
import zipfile
from subprocess import *
import re
debug = False
gap = 4

def docx_grep(pattern,fname):
    r = re.compile(pattern)
    z = zipfile.ZipFile(fname,"r")
    for name in z.namelist():
        data = z.read(name)
        if len(data)==0: continue
        if data[0]=='<':
            data = xml.dom.minidom.parseString(data).toprettyxml(" ")
        lines = data.split("\n")
        for n in range(0,len(lines)):
            m = r.search(lines[n])
            if m:
                for i in range(n-gap,n+gap+1):
                    if i<0 or i>=len(lines): continue
                    print "%s:%s:%4d   %s" % (fname,name,i,lines[i])
                print ""


if(__name__=="__main__"):
    if(len(sys.argv)!=3):
        print "usage: %s pattern file" % (sys.argv[0])
    for f in sys.argv[2:]:
        try:
            docx_grep(sys.argv[1],f)
            print ""
            print ""
            print "====================="
        except zipfile.BadZipfile:
            print "%s is not a zip file" % f

