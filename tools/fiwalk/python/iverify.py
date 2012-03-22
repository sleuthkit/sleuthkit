#!/usr/bin/python
"""Reads an fiwalk XML file and reports how many of the files are still in the image..."""

import hashlib, os.path, fiwalk, sys

present = []
not_present = []

def process_fi(fi):
    print "process file",fi.filename()
    if fi.filesize()==0: return
    try:
        if fi.file_present():
            present.append(fi)
            return
        else:
            not_present.append(fi)
            return
    except ValueError,e:
        sys.stderr.write(str(e)+"\n")


################################################################
if __name__=="__main__":
    import sys
    from optparse import OptionParser
    from subprocess import Popen,PIPE
    global options

    parser = OptionParser()
    parser.add_option("-d","--debug",help="prints debugging info",dest="debug")
    parser.add_option("-g","--ground",help="ground truth XML file",dest="ground")
    parser.usage = '%prog [options] image.iso'
    (options,args) = parser.parse_args()

    if not options.ground:
        parser.print_help()
        sys.exit(1)

    # Read the XML file
    reader = fiwalk.fileobject_reader()
    reader.set_imagefilename(args[0])
    reader.process_xml_stream(open(options.ground,"r"),process_fi)

    if len(present)==0:
        print "None of the files are present in the image"
        sys.exit(0)

    if len(not_present)==0:
        print "All of the files are present in the image"
        sys.exit(0)

    print "\n\n"
    print "Present in image:"
    print "================="
    print "\n".join([fi.filename() for fi in present])

    print "\n"
    print "Not Present or altered in image:"
    print "====================="
    for fi in not_present:
        print fi.filename()

    

