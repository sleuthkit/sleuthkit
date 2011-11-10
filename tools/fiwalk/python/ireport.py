#!/usr/bin/env python
#
# Print the stats from a DFXML file 

import sys,os,shelve

sys.path.append(os.getenv("HOME")+"/slg/src/python")
sys.path.append(os.getenv("DOMEX_HOME")+"/src/lib")

from histogram2d import histogram2d
from histogram import histogram
from statbag import statbag
from ttable import ttable
import re,dfxml,fiwalk

def process_files(fn):
    drive_files = {}                         # index of drives
    all_parts  = []
    all_files = []
    files_by_md5 = {}           # a dictionary of sets of fiobject, indexed by md5
    extension_len_histogram = histogram2d()
    extension_fragments_histogram = histogram2d()
    partition_histogram = histogram2d()

    def cb(fi):
        # add the md5 to the set
        if fi.is_file() and fi.filesize():
            files_by_md5.get(fi.md5,set()).add(fi)
            ext = fi.ext()
            if not ext: print fi.meta_type(),fi
            extension_len_histogram.add(ext,fi.filesize())
            extension_fragments_histogram.add(ext,fi.fragments())
            partition_histogram.add(fi.partition(),fi.filesize())

    if fn.endswith('xml'):
        fiwalk.fiwalk_using_sax(xmlfile=open(fn),callback=cb)
    else:
        fiwalk.fiwalk_using_sax(imagefile=open(fn),callback=cb)
    

    #
    # Typeset the information
    #

    tab = ttable()
    tab.header     = "File extension popularity and average size (suppressing 0-len files)"
    tab.col_headings = [['Ext','Count','Average Size','Max','Std Dev']]
    tab.omit_row = [[0,'']]
    extension_len_histogram.statcol = ['iaverage','maxx','istddev']
    print extension_len_histogram.typeset(tab=tab)

    #
    # Information about fragmentation patterns
    #
    tab = ttable()
    tab.header="Fragmentation pattern by file system and file type:"
    tab.col_headings = [['Ext','Count','Average Size','Max','Std Dev']]
    tab.omit_row = [[0,'']]
    extension_fragments_histogram.statcol = ['iaverage','maxx','istddev']
    print extension_fragments_histogram.typeset(tab=tab)
    exit(0)

    for fstype in fstypes:
        for ftype in ['jpg','pdf','doc','txt']:
            len1stats = statbag()
            len2stats = statbag()
            delta_hist = histogram()
            delta_re = re.compile("(\d+)\-?(\d+)? ?(\d+)\-?(\d+)?")
            for i in filter( (lambda(f): f.ext()==ftype and f.fragments==2),all_files):
                runs = False
                if(hasattr(i,'block_runs')): runs = i.block_runs
                if(hasattr(i,'sector_runs')): runs = i.sector_runs
                if not runs: continue
                m = delta_re.search(runs)
                r = []
                for j in range(1,5):
                    try:
                        r.append(int(m.group(j)))
                    except TypeError:
                        r.append(int(m.group(j-1)))

                len1 = r[1] - r[0] + 1
                len2 = r[3] - r[2] + 1
                delta = r[2]-r[1]
                
                len1stats.addx(len1)
                len2stats.addx(len2)
                delta_hist.add(delta)

            if len1stats.count()>0:
                print "\n\n"
                print "fstype:",fstype,"  ftype:",ftype
                print "len1 average: %f stddev: %f" % (len1stats.average(),len1stats.stddev())
                print "len2 average: %f stddev: %f" % (len2stats.average(),len2stats.stddev())
                print "delta average: %f" % delta_hist.average()
                print "delta histogram:"
                delta_hist.print_top(10)


    exit(0)


    print("Partition histogram:")
    partition_histogram.print_top(n=100)
    print("Counts by extension:")
    extension_len_histogram.print_top(n=100)
    print("Fragments by extension:")
    extension_fragments_histogram.print_top(n=100)

    exit(0)
    for fstype in fstypes:
        if fstype=='(unrecognized)': continue
        print fstype,"Partitions:"

        def isfstype(x): return x.fstype==fstype
        these_parts = filter(isfstype,all_parts)
        these_files = []
        for part in these_parts:
            these_files.extend(part.files)
        print fragmentation_table(these_files)

    
    exit(0)

    sys.exit(0)


    #
    # Typeset information about file extensions
    #
    hist_exts = histogram2d()
    hist_exts.topn = 20
    for i in all_files:
        if i.size>0 and i.fragments>0: hist_exts.add(i.ext(),i.size)
    tab = table()
    tab.header     = "File extension popularity and average size (suppressing 0-len files)"
    tab.col_headings = ['Ext','Count','Average Size','Max','Std Dev']
    tab.omit_row = [[0,'']]
    hist_exts.statcol = ['iaverage','maxx','istddev']
    print hist_exts.typeset(t=tab)

    hist_exts = histogram2d()
    hist_exts.topn = 20
    for i in all_files:
        if i.fragments>0: hist_exts.add(i.ext(),i.fragments)
    tab = table()
    tab.header     = "Fragmentation by file extension (suppressing files with 0 fragments)"
    tab.col_headings = ['Ext','Count','Avg Fragments','Max','Std Dev']
    tab.omit_row = [[0,'']]
    hist_exts.statcol = ['average','maxx','stddev']
    print hist_exts.typeset(t=tab)

    print "==========================="


    #
    # Typeset the File Systems on Drives table
    #

    tab = table()
    tab.header     = "File Systems on Drives"
    tab.col_headings = ["FS Type","Drives","MBytes"]
    tab.col_totals = [1,2]
    fstypeh.statcol = 'sumx'
    print fstypeh.typeset(t=tab)

    #
    # Typeset overall fragmentation stats
    #

    print fragmentation_table(all_files)

if(__name__=="__main__"):
    from optparse import OptionParser
    from copy import deepcopy
    global options

    parser = OptionParser()
    parser.usage="%prog [options] file1 [file2...] (files can be XML or image files)"
    (options,args) = parser.parse_args()

    for fn in args:
        process_files(fn)
