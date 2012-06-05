#!/usr/bin/python                                                                                                     
import fiwalk
import time

if __name__=="__main__":
    import sys
    from optparse import OptionParser
    from sys import stdout
    parser = OptionParser()
    parser.usage = '%prog [options] (xmlfile or imagefile)'
    (options,args) = parser.parse_args()

    if not args:
        parser.print_usage()
        exit(1)

    sizes = []
    dates = {}
    def callback(fi):
        sizes.append(fi.filesize())
        for (tag,val) in (fi.times().iteritems()):
            date = val.datetime()
            dates[date] = dates.get(date,0)+1

    fn = args[0]
    if fn.endswith(".xml"):
        fiwalk.fiwalk_using_sax(xmlfile=open(fn),callback=callback)
    else:
        fiwalk.fiwalk_using_sax(imagefile=open(fn),callback=callback)

    print("Here is the dates array:")
    for d in sorted(dates.keys()):
        print("{}   {}".format(d,dates[d]))

