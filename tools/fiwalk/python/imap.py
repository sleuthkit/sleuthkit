#!/usr/bin/python
"""Usage: imap imagefile0.iso imagefile1.iso imagefile2.iso ...

Produces a map of imagefile0.iso, using the other image files as "hints" for missing
data. Only reports files that have been allocated; deleted files are reported only if
they can be found allocated in another file.
"""


import fiwalk


################################################################
if __name__=="__main__":
    import sys
    from sys import stdout

    from optparse import OptionParser
    parser = OptionParser()
    parser.usage = '%prog [options] image.iso '
    parser.add_option("-d","--debug",help="debug",action="store_true")
    (options,args) = parser.parse_args()

    if len(args)<1:
        parser.print_help()
        sys.exit(1)

    imagefile = open(args[0],"r")
    annotated_runs = []
    if options.debug: print("Read %d file objects from %s" % (len(fileobjects),imagefile.name))

    def cb(fi):
        if options.debug: print("Read "+str(fi))
        fragment_num = 1
        for run in fi.byte_runs():
            annotated_runs.append((run.img_offset,run,fragment_num,fi))
            fragment_num += 1
    fiwalk.fiwalk_using_sax(imagefile=imagefile,callback=cb)

    next_sector = 0

    for (ip,run,fragment_num,fi) in sorted(annotated_runs):
        extra = ""
        fragment = ""
        start_sector = run.img_offset/512
        sector_count = int(run.bytes/512)
        partial        = run.bytes % 512
    
        if not fi.allocated():
            print("***")

        if not fi.file_present():       # it's not here!
            continue 

        if partial>0:
            sector_count += 1
            extra = "(%3d bytes slack)" % (512-partial)

        if fi.fragments()>2:
            fragment = "fragment %d" % fragment_num

        if next_sector != start_sector:
            print "  <-- %5d unallocated sectors @ sector %5d -->" % (start_sector-next_sector,next_sector)

        print("[ %6d  -> %6d sectors %18s ]   %s  %s " % (start_sector,sector_count,extra,fi.filename(),fragment))

        next_sector = start_sector + sector_count

