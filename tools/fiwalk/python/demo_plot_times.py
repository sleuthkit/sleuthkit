#!/usr/bin/python                                                                                                     
import fiwalk
import time

if __name__=="__main__":
    import sys
    from optparse import OptionParser
    from sys import stdout
    parser = OptionParser()
    parser.usage = '%prog [options] xmlfile '
    (options,args) = parser.parse_args()

    sizes = []
    dates = {}
    def callback(fi):
        sizes.append(fi.filesize())
        for (tag,val) in (fi.times().iteritems()):
            date = val.datetime()
            dates[date] = dates.get(date,0)+1

    fiwalk.fiwalk_using_sax(xmlfile=open(args[0],"r"),callback=callback)
    try:
        import pylab
        pylab.grid()
        pylab.hist(times,100)
        pylab.show()
    except ImportError:
        print("pylab not installed.")
        print("Date\tActivity Count:")
        for date in sorted(dates.keys()):
            print("%s\t%d" % (date,dates[date]))

