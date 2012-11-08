#!/usr/bin/python
#
# dedup 

import os

class dedup:
    def __init__(self,options):
        self.seen = set()
        self.options = options

    def process(fi):
        if fi.md5() in self.seen:
            if self.verbose:
                print("rm {}".format(fi.filename()))
            if self.commit:
                #os.unlink(fi.filename())
                continue


if __name__=="__main__":
    from optparse import OptionParser
    from copy import deepcopy
    global options

    parser.add_option("--commit",action="store_true")
    parser.add_option("--verbose",action="store_true")
    parser = OptionParser()
    (options,args) = parser.parse_args()

    dobj = dedup(options)

    dfxml.read_dfxml(open(args[0],'rb'),callback=dobj.process)

