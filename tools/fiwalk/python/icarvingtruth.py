#!/usr/bin/python
"""ground truth program.

Inputs: Multiple image files.
Outputs: List of all the files and partial files in the last file.

Process:

1. Read current disk image. Map out all allocated files. Add each fileinfo to the ground truth.
2. Read all of the previous disk images (or XML files). 
   - If the a previously allocated file is present in the current image, add it to the ground truth.
3. Read all of the previous disk images.
   - For all of the sectors not used in the final version, note which sectors of the original files survive.
"""

import dfxml,fiwalk
import sys
import xml.dom.minidom
from xml.dom.minidom import parseString

# http://wiki.python.org/moin/MiniDom

def make_residual(fi=None,image=None,runs=None):
    """Take a regular fileobject XML document
    and move the byte_runs into an <original> section and add a
    <residual> section."""
    fidoc = fi.doc
    dom = parseString("<foo/>")
    newdoc = deepcopy(fidoc)
    original = dom.createElement("original")
    newdoc.appendChild(original)
    original.appendChild(newdoc.getElementsByTagName("byte_runs")[0])

    # Create the residual
    residual = dom.createElement("residual")
    newdoc.appendChild(residual)

    # Create a new byte_runs
    new_byte_runs = dom.createElement("byte_runs")
    residual.appendChild(new_byte_runs)

    if image:
        x = dom.createElement("image")
        txt = dom.createTextNode(image)
        x.appendChild(txt)
        original.appendChild(x)

    for run in runs:
        x = dom.createElement("run")
        x.setAttribute("img_offset",run.img_offset)
        x.setAttribute("len",run.bytes)
        new_byte_runs.appendChild(x)
    return newdoc
    
def annotate(xml,tag,value):
    from xml.dom.minidom import parseString
    dom = parseString("<foo/>")
    x = dom.createElement(tag)
    txt = dom.createTextNode(value)
    x.appendChild(txt)
    xml.appendChild(x)

def add_reference(doc,image="",reason=""):
    d2 = parseString("<reference><image>%s</image><reason>%s</reason></reference>"
                     % (image,reason))
    doc.appendChild(d2.getElementsByTagName("reference")[0])

def print_ground_truth_fi(fi,out=sys.stdout):
    import os.path
    reference = fi.doc.getElementsByTagName("reference")[0]
    image = reference.getElementsByTagName("image")[0].firstChild.wholeText
    try:
        out.write("Original Filename: %s  in: %s\nSHA 1: %s\n" %
                  (fi.filename(),os.path.basename(image),fi.sha1()))
    except KeyError:
        print "***",fi
        print "***",fi.filename()
        print "***",os.path.basename(image)
    desc = "Location: "
    sector_size = 512
    for run in fi.byte_runs():
        eblurb = ""
        if run.extra_bytes()>0:
            eblurb = "and %3d bytes " % run.extra_bytes()
        out.write("%10s @ sector %8d ; %5d %4d-byte sectors %14s (%7d bytes total)\n"
                  % (desc,run.start_sector(),run.sector_count(),run.sector_size,eblurb,run.bytes))
        desc = ""
    out.write("\n")

def print_ground_truth_report(doc,out=sys.stdout):
    def sort_by_runs(a,b):
        if len(a.byte_runs())==0: return -1
        if len(b.byte_runs())==0: return 1
        if a.byte_runs()[0].img_offset < b.byte_runs()[0].img_offset: return -1
        if a.byte_runs()[0].img_offset > b.byte_runs()[0].img_offset: return 1
        return 0

    filist = [dfxml.fileobject_dom(x)
              for x in doc.getElementsByTagName("fileobject")]
    for fi in sorted(filist,sort_by_runs):
        print_ground_truth_fi(fi,out=out)


def sector_from_file(imagefile,sector_number,sectorsize = 512):
    imagefile.seek(sector_number * sectorsize)
    return imagefile.read(sectorsize)

if __name__=="__main__":
    from optparse import OptionParser
    from copy import deepcopy

    parser = OptionParser()
    parser.usage = '%prog [options] [mapfile1.iso mapfile2.iso ...] masterfile.iso'
    parser.add_option("-x","--xml",help="specify output file for XML",dest="xmlfilename")
    parser.add_option("-r","--report",help="specify output file for the report",dest="reportfilename")
    parser.add_option("-d","--debug",help="debug")
    (options,args) = parser.parse_args()

    if len(args)<1:
        parser.print_help()
        sys.exit(1)

    masterfn = args[-1]
    refs     = args[:-1]
    master_imagefile = open(masterfn,"r")
    db     = dfxml.extentdb(sectorsize=512)

    (doc,fileobjects) = fiwalk.fileobjects_using_dom(imagefile=master_imagefile,
                                                     flags=fiwalk.ALLOC_ONLY)

    groundtruth = parseString("<groundtruth/>")

    # First, add all relevant metadata elements from the master file's
    # XML to the to the groundtruth file's XML.
    for node in doc.childNodes[0].childNodes:
        if node.nodeType==node.ELEMENT_NODE and \
               node.nodeName not in ["volume","fileobject"]:
            groundtruth.childNodes[0].appendChild(node.cloneNode(node))

    # Next, add the file object elements
    for fi in fileobjects:
        if options.debug: print "adding ",fi
        newdoc = fi.doc.cloneNode(fi)
        add_reference(newdoc,image=masterfn,reason='resident file')
        groundtruth.childNodes[0].appendChild(newdoc)
        db.add_runs(fi.byte_runs())
        
    # For each map file, see if any of the allocated files are
    # in the ground truth file but not previously discovered

    for ref in refs:
        if options.debug: print "check files in ",ref
        (d2,fobj2) = fiwalk.fileobjects_using_dom(imagefile=open(ref,"r"),
                                                  flags=fiwalk.ALLOC_ONLY)
        for fi in fobj2:
            runs = fi.byte_runs()
            if not db.intersects_runs(runs):
                db.add_runs(runs)
                newdoc = fi.doc.cloneNode(fi)
                add_reference(newdoc,image=ref,reason='residual file')
                groundtruth.childNodes[0].appendChild(newdoc)


    # Now, for each file, get a list of the sectors that are in unallocated
    # space and report which of them (if any) are in the final file.

    for ref in refs:
        if options.debug: print "check residual data in ",ref
        ref_imagefile = open(ref,"r")
        (d2,fobj2) = fiwalk.fileobjects_using_dom(imagefile=ref_imagefile,
                                                  flags=fiwalk.ALLOC_ONLY)
        for fi in fobj2:
            for run in fi.byte_runs():
                sectors_to_check =  db.sectors_not_in_db(run)
                # For each sector to check, see if the value in the current image file
                # is the same as in the report imagefile

                def check_sector(n):
                    return sector_from_file(ref_imagefile,n) \
                           == sector_from_file(master_imagefile,n)
                sectors_that_match = filter(check_sector,sectors_to_check)
                if sectors_that_match:
                    if options.debug:
                        print(fi.filename(),
                              "run sectors:", db.sectors_for_bytes(run_len),
                              "total sectors: ",len(sectors_to_check),
                              "matching:",len(sectors_that_match))
                    runs = db.runs_for_sectors(sectors_that_match)
                    if options.debug: print("runs:",runs)
                    db.add_sectors(sectors_that_match)
                    residual_doc = make_residual(fi=fi, image=ref, runs=runs)
                    residual = residual_doc.childNodes[0]
                    groundtruth.childNodes[0].appendChild(residual)

    try:
        xmlfile = open(options.xmlfilename,"w")
    except TypeError:
        xmlfile = sys.stdout
        print("Here is the XML:")

    xmlfile.write(groundtruth.toxml())

    try:
        reportfile = open(options.reportfilename,"w")
    except TypeError:
        reportfile = sys.stdout
        print("\n\nHere is the report:")

    print_ground_truth_report(groundtruth,out=reportfile)
    sys.exit(0)


