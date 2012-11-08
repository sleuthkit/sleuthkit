#!/usr/bin/env python
# coding=UTF-8
"""dfxinfo.py:
Generates a report about what up with a DFXML file.
"""

import platform,os,os.path,sys,time
if platform.python_version_tuple() < ('3','2','0'):
    raise RuntimeError('This script now requires Python 3.2 or above')

try:
    import dfxml, fiwalk
except ImportError:
    raise ImportError('This script requires the dfxml and fiwalk modules for Python.')

__version__='0.0.1'

import fiwalk,dfxml
from histogram import histogram

class DiskSet:
    """DiskSet maintains a database of the file objects within a disk.
    The entire database is maintained in memory."""
    def __init__(self):
        self.ext_histogram          = histogram()
        self.ext_histogram_distinct = histogram()
        self.fi_by_md5              = dict() # a dictionary of lists

    def pass1(self,fi):
        if fi.is_virtual(): return
        if fi.is_file():
            self.fi_by_md5.setdefault(fi.md5(),[]).append(fi)

    def print_dups_report(self):
        print("Duplicates:")
        # First extract the dups, then sort them
        dups  = filter(lambda a:len(a[1])>1,self.fi_by_md5.items(),)
        dup_bytes = 0
        for (md5hash,fis) in sorted(dups,key=lambda a:a[1][0].filesize(),reverse=True):
            for fi in fis:
                print("{:>16,} {:32} {}".format(fi.filesize(),fi.md5(),fi.filename()))
            print()
            dup_bytes += fis[0].filesize() * (len(fis)-1)
        print("Total duplicate bytes: {:,}".format(dup_bytes))


if __name__=="__main__":
    from argparse import ArgumentParser
    from copy import deepcopy

    parser = ArgumentParser(description='Report information about a DFXML file')
    parser.add_argument('xmlfiles',help='XML files to process',nargs='+')
    parser.add_argument("--imagefile",help="specifies imagefile to examine; automatically runs fiwalk",nargs='+')

    args = parser.parse_args()
    ds   = DiskSet()
    for fn in args.xmlfiles:
        print("Processing {}".format(fn))
        dfxml.read_dfxml(xmlfile=open(fn,'rb'),callback=ds.pass1)
    ds.print_dups_report()
