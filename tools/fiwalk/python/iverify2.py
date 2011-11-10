#!/usr/bin/python
"""Verify the contents of a disk image"""

import hashlib
import xml.dom
import xml.dom.minidom
from xml.dom.minidom import parse, Node, Document, parseString
import fiwalk_dom


################################################################
if __name__=="__main__":
    import sys
    import os.path
    from optparse import OptionParser
    from subprocess import Popen,PIPE
    global options

    parser = OptionParser()
    parser.add_option("-d","--debug",help="prints debugging info",dest="debug")
    parser.add_option("-g","--ground",help="ground truth XML output file",dest="ground")
    parser.add_option("-s","--save",help="saves verified files in SAVEDIR",dest="savedir")
    parser.usage = '%prog [options] image.iso xmlfile1 [xmlfile2 ...]'
    (options,args) = parser.parse_args()

    if len(args)<2:
        parser.print_help()
        sys.exit(1)

    groundtruth = None
    if options.ground:
        groundtruth = xml.dom.minidom.parseString("<groundtruth></groundtruth>")

    if options.savedir:
        if os.path.exists(options.savedir):
            raise IOError,options.savedir+" must not exist"
        os.mkdir(options.savedir)

    # Read the redaction configuration file
    imagefilename = args[0]
    imagefile = open(imagefilename,"r")

    files_present  = []
    not_present    = []
    runs_processed = set()

    import pickle

    # Read the XML file
    for xmlfile in args[1:]:
        doc = parseString(open(xmlfile,"r").read())

        # process the file objects:
        for xmlfi in doc.getElementsByTagName("fileobject"):
            # Make a file object
            fi = fiwalk_dom.fileobject(xmlfi,imagefile)

            # We need contents to process
            if not fi.has_contents(): continue 

            # Get the runs
            fobj_runs = pickle.dumps(fi.byte_runs())

            # Check to see if we have already processed this run
            if fobj_runs in runs_processed: 
                continue

            # Remember this run
            runs_processed.add(fobj_runs) 

            if fi.file_present():
                files_present.append(fi)
                newdoc=xml.dom.minidom.parseString("<tag/>")
                newtag = newdoc.createElement("present")
                newtag.appendChild(newdoc.createTextNode("1"))
                xmlfi.appendChild(newtag)
                if groundtruth:
                    groundtruth.firstChild.appendChild(xmlfi)
                if options.savedir:
                    (root,ext) = os.path.splitext(fi.filename())
                    start = fi.byte_runs()[0][0]
                    newpath = options.savedir + "/" + ("file%08d" % start) + ext
                    open(newpath,"w").write(fi.contents())
            else:
                not_present.append(fi)

    if groundtruth:
        open(options.ground,"w").write(groundtruth.toxml())

    if len(files_present)==0:
        print "None of the files are present in the image"
        sys.exit(0)

    if len(not_present)==0:
        print "All of the files are present in the image"
        sys.exit(0)

    print "\n\n"
    print "Present in image:"
    print "================="
    print "\n".join([fi.filename() for fi in files_present])

    print "\n"
    print "Not Present or altered in image:"
    print "====================="
    print "\n".join([fi.filename() for fi in not_present])

    


