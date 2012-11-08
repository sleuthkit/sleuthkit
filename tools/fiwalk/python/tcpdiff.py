#!/usr/bin/env python
"""tcpdiff.py

Generates a report about what's different between two tcp DFXML files
produced by tcpflow.

Process:

"""

import sys,time
if sys.version_info < (3,1):
    raise RuntimeError("rdifference.py requires Python 3.1 or above")

import fiwalk,dfxml,html
def ptime(t):
    """Print the time in the requested format. T is a dfxml time value"""
    global options
    if t is None:
        return None
    elif options.timestamp:
        return str(t.timestamp())
    else:
        return str(t.iso8601())

def dprint(x):
    "Debug print"
    global options
    if options.debug: print(x)

#
# This program keeps track of the current and previous TCP connections in a single
# object called "FlowState". Another way to do that would have been to have
# the instance built from the XML file and then have another function that compares
# them.
#        

class FlowState:
    def __init__(self,fname):
        self.options = options
        self.connections = set()
        self.process(fname)
        
    def process(self,fname):
        self.fname = fname
        dfxml.read_dfxml(xmlfile=open(fname,'rb'), callback=self.process_fi)

    def process_fi(self,fi):
        self.connections.add(fi)

    def report(self):
        html.header()
        html.h1("DFXML file:"+self.current_fname)
        html.table(['Total Connections',str(len(self.connections))])

if __name__=="__main__":
    from optparse import OptionParser
    from copy import deepcopy
    global options

    parser = OptionParser()
    parser.usage = '%prog [options] file1 file2 (files MUST be tcpflow DFXML files)'
    parser.add_option("-d","--debug",help="debug",action='store_true')

    (options,args) = parser.parse_args()

    if len(args)!=2:
        parser.print_help()
        sys.exit(1)

    a = FlowState(fname=args[0])
    a.report()

    b = FlowState(fname=args[1])
    b.report()

    print("Difference:")
