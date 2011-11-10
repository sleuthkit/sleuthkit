#!/usr/bin/python
"""Usage: iblkfind imagefile.iso s1 [s2 s3 ...] ...

Reports the files in which sectors s1, s2, s3... are located.
"""
import dfxml,sys


if __name__=="__main__":
    from optparse import OptionParser
    parser = OptionParser()
    parser.usage = '%prog [options] imagefile-or-xmlfile s1 [s2 s3 s3 ...]'
    parser.add_option("--offset",help="values are byte offsets, not sectors",action="store_true")
    parser.add_option("--blocksize",help="specify sector blockszie",default=512)
    (options,args) = parser.parse_args()

    if len(args)<1:
        parser.print_help()
        sys.exit(1)
    fn = args[0]

    print(args)
    print("Processing %s" % fn)
    print("Searching for %s" % ", ".join(args[1:]))

    divisor = 1
    if options.offset:
        divisor = options.blocksize

    sectors = set([int(s)/divisor for s in args[1:]])


    def process(fi):
        for s in sectors:
            if fi.has_sector(s):
                print("%d\t%s" % (s,fi.filename()))
    
    if not fn.endswith(".xml"):
        print("iblkfind requires an XML file")
        exit(1)
    dfxml.read_dfxml(xmlfile=open(args[0]),callback=process)
