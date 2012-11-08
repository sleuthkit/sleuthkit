#!/usr/bin/env python
import dfxml, sys

timeline = []

def process(co):
    mtime = co.mtime()
    if mtime != None:
        timeline.append([co.mtime(),co.full_path()," modified"])

def main():
    if len(sys.argv) < 2:
        print("Usage: {} <input.regxml>".format(sys.argv[0]))
        exit(1)
    dfxml.read_regxml(xmlfile=open(sys.argv[1],"rb"), callback=process)
    timeline.sort()
    for record in timeline:
        print("\t".join( map(str, record)) )

if __name__ == "__main__":
    main()
