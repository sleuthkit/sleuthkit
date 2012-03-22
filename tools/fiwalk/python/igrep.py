#!/usr/bin/python
"""Usage: igrep imagefile.iso string ...

Reports the files in which files have the string.
"""
import fiwalk,dfxml

if __name__=="__main__":
    import sys

    from optparse import OptionParser
    parser = OptionParser()
    parser.usage = '%prog [options] image.iso  s1'
    parser.add_option("-d","--debug",help="debug",action="store_true")
    (options,args) = parser.parse_args()

    if len(args)!=2:
        parser.print_help()
        sys.exit(1)

    (imagefn,data) = args

    def process(fi):
        offset = fi.contents().find(data)
        if offset>0:
            print "%s (offset=%d)" % (fi.filename(),offset)
            
    fiwalk.fiwalk_using_sax(imagefile=open(imagefn),callback=process)
