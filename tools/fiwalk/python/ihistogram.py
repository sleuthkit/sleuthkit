#!/usr/bin/python
"""Draw a quick hisogram of the timestamps on the hard drive"""

import matplotlib
matplotlib.use('agg.pdf')


import fiwalk
import datetime
from matplotlib.dates import MonthLocator, WeekdayLocator, DateFormatter
from matplotlib.dates import MONDAY,SATURDAY
import time
from pylab import *


def get_dates_and_counts(times):
    from datetime import date
    data = {}
    for t in times:
        gm = time.gmtime(t)
        d = date(gm[0],gm[1],gm[2])
        data[d] = data.get(d,0)+1

    # Create a list of key,val items so you can sort by date
    dates_and_counts = [ (date,count) for date,count in data.items()]
    dates_and_counts = sorted(dates_and_counts)
    return dates_and_counts

def version1(times):    
    import pylab
    pylab.grid()
    pylab.hist(times,100)
    pylab.show()


def version2(times):
    # see http://mail.python.org/pipermail/python-list/2003-November/236559.html
    # http://www.gossamer-threads.com/lists/python/python/665014
    from matplotlib.pylab import plot, show, title, xlabel, ylabel, gca, bar, savefig, plot_date
    
    dates_and_counts = get_dates_and_counts(times)
    dates, counts = zip(*dates_and_counts)
    # bar(dates,counts)
    plot_date(dates,counts)
    xlabel("Date")
    ylabel("count")
    show()

def version3(times):
    import datetime
    import numpy as np
    import matplotlib
    import matplotlib.pyplot as pyplot
    import matplotlib.dates as mdates
    import matplotlib.mlab as mlab

    dates_and_counts = get_dates_and_counts(times)
    dates, counts = zip(*dates_and_counts)

    years    = mdates.YearLocator()   # every year
    months   = mdates.MonthLocator()  # every month
    yearsFmt = mdates.DateFormatter('%Y')

    fig = pyplot.figure()
    ax = fig.add_subplot(111)
    ax.bar(dates,counts)

    ax.set_ylabel('file count')
    ax.set_xlabel('file modification time (mtime)')

    #ax.set_yscale('log')

    # Format the ticks

    ax.xaxis.set_major_locator(years)
    ax.xaxis.set_major_formatter(yearsFmt)
    #ax.xaxis.set_minor_locator(months)

    datemin = datetime.date(min(dates).year, 1, 1)
    datemax = datetime.date(max(dates).year, 1, 1)
    ax.set_xlim(datemin, datemax)
    ax.set_ylim(0,max(counts))

    # format the coords message box
    def price(x): return '$%1.2f'%x
    ax.format_xdata = mdates.DateFormatter('%Y-%m-%d')
    ax.format_ydata = price
    ax.grid(True)

    # rotates and right aligns the x labels, and moves the bottom of the
    # axes up to make room for them
    fig.autofmt_xdate()
    plt.savefig("hist.pdf",format='pdf')
                
    print("dates:",dates)
    print("num dates:",len(dates))

    
    
if __name__=="__main__":
    import sys
    from optparse import OptionParser
    from sys import stdout

    parser = OptionParser()
    parser.usage = '%prog [options] xmlfile '
    (options,args) = parser.parse_args()

    import time
    times = []
    for fi in fiwalk.fileobjects_using_sax(xmlfile=open(args[0])):
        try:
            times.append(fi.mtime())
        except KeyError:
            pass

    version3(times)

    
