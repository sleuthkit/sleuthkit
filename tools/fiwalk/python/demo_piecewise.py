#!/usr/bin/env python3.2

#
# Demo program that prints piecewise hashes and reports on co-occurance of hashes.
#
# Multimap from http://stackoverflow.com/questions/1731971/is-there-multimap-implementation-in-python

import dfxml,math,sys,collections


class SectorCorrelator:
    def __init__(self):
        self.hashdb = collections.defaultdict(list) #  key is the MD5 code, value is a list of matches
        self.files = 0
        self.sectors = 0
    def process(self,fi):
        """ Process the <fileobject> objects as they are read from the XML file"""
        self.files += 1
        print(fi.filename())
        for br in fi.byte_runs():
            self.sectors += 1
            self.hashdb[br.hashdigest['md5']].append((fi.filename(),br.file_offset))
    def print_report(self):
        print("Files processed: {}".format(self.files))
        print("Sectors processed: {}".format(self.sectors))
        print("")
        print("The following duplicates were found:")
        print("Hash   Filename           Offset in file")
        for (hash,ents) in self.hashdb.items():
            if len(ents)>1:
                print("{}  -- {} copies found".format(hash,len(ents)))
                for e in sorted(ents):
                    print("  {}  {:8,}".format(e[0],e[1]))
                print("")

sc = SectorCorrelator()
dfxml.read_dfxml(xmlfile=open(sys.argv[1],'rb'),callback=sc.process)
sc.print_report()
