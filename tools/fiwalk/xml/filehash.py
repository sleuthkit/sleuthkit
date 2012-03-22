#!/usr/bin/python
'''
This is will hash a set of files, and produce digitial forensics xml output,
and optionally a pseudo-csv file that will import into FTK
Joshua B. Gross
jbgross@nps.edu
23 March 2010
'''

import sys, os
import xml.dom.minidom
import hashlib
from optparse import OptionParser

hashtypes = {"md5": hashlib.md5, "sha1": hashlib.sha1, "sha256": hashlib.sha256}
docroot = None
csvfiles = None

def walk(fognode, dirname, files):
    global docroot, kfile
    if len(files) > 0:
        for f in files:

            # ignore dot files
            if f.startswith("."):
                continue

            f = os.path.join(dirname, f)
            if os.path.isfile(f):

                # create the node for a fileobject
                fonode = docroot.createElement("fileobject")
                fognode.appendChild(fonode)

                # create filename node and value
                namenode = docroot.createElement("filename")
                namenode.appendChild(docroot.createTextNode(f))
                fonode.appendChild(namenode)
                hashfileobject(f, fonode)
                
def main():
    inputdir = ""
    outputfile = ""
    csvfilebase = ""

    parser = OptionParser()
    parser.add_option("-c", "--create-csv",
                      action="store",
                      help="create csv format files for import into FTK", 
                      dest="csvfilebase")
    parser.add_option("-i", "--input-directory",
                      action="store",
                      help="directory or filelist to parse",
                      dest="inputdir")
    parser.add_option("-o", "--output-file",
                      action="store",
                      help="name of output xml file",
                      dest="outputfile")
    (options, args) = parser.parse_args()
    outputfile = options.outputfile
    inputdir = options.inputdir
    csvfilebase = options.csvfilebase

    global docroot
    if outputfile=="" or inputdir=="":
        parser.print_help()
        sys.exit(1)

    if csvfilebase != "":
        open_csvfiles(csvfilebase)

    # create the document and root
    docroot = xml.dom.minidom.Document()
    fognode = docroot.createElementNS("http://afflib.org/fiwalk/fileobject/", "fileobjectgroup")
    docroot.appendChild(fognode)

    os.path.walk(inputdir, walk, fognode)

    # open file, write, and close file
    xmlfile = open(outputfile, "w")
    xmlfile.write(fognode.toprettyxml())
    xmlfile.close()
    
    close_csvfiles()

'''
close csvfiles, if any
'''
def close_csvfiles():
    if csvfiles != None:
        for hashtype in csvfiles.keys():
            file = csvfiles[hashtype]
            file.write("\n")
            file.close()

def hashfileobject(fileobj, fileobjnode):
    global hashtypes, docroot
    f = open(fileobj)
    fdata = f.read()
    f.close()

    for hashtype in hashtypes.keys():
        hashval = hashtypes[hashtype](fileobj).hexdigest()
        hashnode = docroot.createElement("hashdigest")
        hashnode.setAttribute("type", hashtype)
        hashnode.appendChild(docroot.createTextNode(hashval))
        fileobjnode.appendChild(hashnode)
        
    if csvfiles != None:
        for hashtype in csvfiles.keys():
            csvfiles[hashtype].write("%s\n" % hashval)

def open_csvfiles(csvfilebase):
    global csvfiles
    csvfiles = {}
    for hashtype in hashtypes.keys():
        filename = "%s-%s.csv" % (csvfilebase, hashtype)
        csvfiles[hashtype] = open(filename, "w")


if __name__ == '__main__':
    main()
