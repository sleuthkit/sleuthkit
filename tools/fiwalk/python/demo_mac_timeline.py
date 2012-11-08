#!/usr/bin/env python
# produce a MAC-times timeline.
# works under either Python2 or Python3
import dfxml, sys



timeline = []

def process(fi):
    if fi.mtime()!=None: timeline.append([fi.mtime(),fi.filename()," modified"])
    if fi.crtime()!=None: timeline.append([fi.crtime(),fi.filename()," created"])
    if fi.ctime()!=None: timeline.append([fi.ctime(),fi.filename()," changed"])
    if fi.atime()!=None: timeline.append([fi.atime(),fi.filename()," accessed"])

def main():
    if len(sys.argv) < 2:
        print("Usage: {} <filename.xml>".format(sys.argv[0]))
        exit(1)
    dfxml.read_dfxml(xmlfile=open(sys.argv[1],"rb"), callback=process)
    timeline.sort()
    for record in timeline:
        print("\t".join( map(str, record)) )

if __name__ == "__main__":
    main()
