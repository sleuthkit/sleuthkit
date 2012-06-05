#!/usr/bin/python
"""Reads an fiwalk XML file and reports how many of the files are still in the image..."""

import sys,os
sys.path.append(os.getenv("DOMEX_HOME") + "/src/lib/") # add the library
sys.path.append("../lib/")      # add the library
sys.path.append("../fiwalk/")

import fiwalk
import time

def calc_jumps(fis,title):
    print title
    print "Count: %d" % (len(fis))
    from histogram import histogram
    h = histogram()
    pos = 0
    backwards = 0
    prev_frag_count = 0
    for fi in fis:
        for i in range(0,len(fi.byte_runs())):
            run = fi.byte_runs()[i]
            try:
                sector = run.start_sector()
                if sector<pos:
                    backwards+=1
                    h.add((prev_frag_count,i))
                pos = sector
            except AttributeError:
                pass
        pref_frag_count = len(fi.byte_runs())
            
    print "Backwards Jumps: %d" % backwards
    print "Histogram of backwards:"
    h.print_top(10)

if __name__=="__main__":
    import sys
    from optparse import OptionParser
    from subprocess import Popen,PIPE
    global options

    parser = OptionParser()
    parser.add_option("-d","--debug",help="prints debugging info",dest="debug")
    parser.add_option("-x","--xmlfile",help="XML file (optional)")
    parser.add_option("-i","--imagefile",help="image file (required)")
    parser.usage = '%prog [options] xmlfile diskimage'
    (options,args) = parser.parse_args()

    if not options.xmlfile or not options.imagefile:
        parser.print_help()
        sys.exit(1)

    # Read the redaction configuration file
    imagefile = open(options.imagefile,"r")
    if options.xmlfile:
        xmlfile   = open(options.xmlfile,"r")
    else:
        xmlfile   = None

    t0  = time.time()
    fis = fiwalk.fileobjects_using_sax(imagefile=imagefile,xmlfile=xmlfile)
    t1  = time.time()
    print("Time to read file objects: {} seconds".format(t1-t0))

    # Create a new array with just those that we can read
    def resident_file(fi):
        if len(fi.byte_runs())==0: return False
        if len(fi.byte_runs())>2: return False
        if hasattr(fi.byte_runs()[0],"uncompressed_len"): return False
        if not hasattr(fi.byte_runs()[0],"img_offset"): return False
        return True

    fis = filter(resident_file,fis)

    print "Native order: "
    calc_jumps(fis,"Native Order")
    def sort_function(a,b):
        a0 = a.byte_runs()[0].start_sector()
        b0 = b.byte_runs()[0].start_sector()
        if a0 < b0 : return -1
        if a0 == b0 : return 0
        return 1
    fis.sort(sort_function)
    calc_jumps(fis,"Sorted Order")
    


