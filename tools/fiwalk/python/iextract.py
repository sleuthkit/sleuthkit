#!/usr/bin/env python

import dfxml,fiwalk
import zipfile,sys,os,os.path,datetime

if __name__=="__main__":
    from optparse import OptionParser
    parser = OptionParser()
    parser.add_option("-x", "--xml", dest="xmlfilename", help="Already-created DFXML file for imagefile")
    parser.usage = '%prog [options] imagefile zipfile [x1 x2 x3]\nFind files x1, x2, x3 ... in imagefile and write to zipfile'
    (options,args) = parser.parse_args()

    if len(args)<3:
        parser.print_help()
        exit(1)

    imagefilename = args[0]
    xmlfilename = options.xmlfilename
    xmlfh = None
    if xmlfilename != None:
        xmlfh = open(xmlfilename, "r")
    zipfilename = args[1]
    targets = set([fn.lower() for fn in args[2:]])
    zfile = zipfile.ZipFile(zipfilename,"w",allowZip64=True)
    
    def proc(fi):
        basename = os.path.basename(fi.filename()).lower()
        if basename in targets:
            info = zipfile.ZipInfo(fi.filename(),datetime.datetime.fromtimestamp(fi.mtime().timestamp()).utctimetuple())
            info.internal_attr = 1
            info.external_attr = 2175008768 # specifies mode 0644
            zfile.writestr(info,fi.contents())
    fiwalk.fiwalk_using_sax(imagefile=open(imagefilename), xmlfile=xmlfh, callback=proc)
    
