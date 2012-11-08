#!/usr/bin/env python3.2
#
# sync corpus based on DFXML files

import dfxml, fiwalk
from collections import defaultdict

class CorpusDB:
    def __init__(self):
        self.all    = []
        self.md5db  = defaultdict(list)    # maps from 
        self.pathdb = dict()
    def process_fi(self,fi):
        self.all.append(fi)
        self.md5db[fi.md5()].append(fi)
        self.pathdb[fi.filename()] = fi
    def ingest_dfxml(self,fname):
        fiwalk.fiwalk_using_sax(xmlfile=open(fname,'rb'),flags=fiwalk.ALLOC_ONLY,callback=self.process_fi)
    def __iter__(self):
        return self.all.__iter__()
    def __delitem__(self,fi):
        self.all.remove(fi)
        self.md5db[fi.md5()].remove(fi)
        del self.pathdb[fi.filename()]
        
        
        

if __name__=="__main__":
    from optparse import OptionParser
    from copy import deepcopy

    parser = OptionParser()
    (options,args) = parser.parse_args()
    
    (fn1,fn2) = args[0:2]
    print("# Reading B - the master {}".format(fn1))
    b = CorpusDB()
    b.ingest_dfxml(fn1)

    print("# Reading A - the current system {}".format(fn2))
    a = CorpusDB()
    a.ingest_dfxml(fn2)

    print("# Files in A that should not be in B:")
    rmlist = [afi for afi in a if (afi.md5() not in b.md5db)]
    for afi in rmlist:
        print("rm {}".format(afi.filename()))
        del a[afi]

    fixups = []
    for bfi in b:
        if bfi.filename() in a.pathdb and bfi.md5()==a.pathdb[bfi.filename()].md5():
            continue
        if bfi.md5() not in a.md5db:
            print("get {}".format(bfi.filename()))
            continue
        
        afi = a.md5db[bfi.md5()][0]
        nfn = bfi.filename()+".new"
        print("ln {} {}".format(afi.filename(),nfn))
        fixups.append((nfn,bfi.filename()))

    for (nfn,bfi_filename) in fixups:
        print("mv {} {}".format(nfn,bfi_filename))

