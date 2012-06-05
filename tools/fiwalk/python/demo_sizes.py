#!/usr/bin/env python3.2

#
# Demo program that shows how to calculate the average size of file objects in a DFXML file
#

import dfxml,math,sys
import collections

sums = collections.Counter()
sum_of_squares= collections.Counter()
count = collections.Counter()

def func(fi):
    ext = fi.ext()
    count[ext]  += 1
    sums[ext] += fi.filesize()
    sum_of_squares[ext] = fi.filesize() ** 2

dfxml.read_dfxml(xmlfile=open(sys.argv[1],'rb'),callback=func)
fmt = "{:8}    {:8} {:8} {:8} {:8}"
print(fmt.format("Ext","Count","Total","Average","StdDev"))
for ext in sums.keys():
    print(fmt.format(ext,
                     count[ext],
                     sums[ext],
                     sums[ext]/count[ext],
                     math.sqrt(sum_of_squares[ext]/count[ext] - (sums[ext]/count[ext])**2)))
