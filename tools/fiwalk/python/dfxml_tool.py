#!/usr/bin/python
#
# generate MD5s for a directory in Digital Forensics XML Output
# Uses dublin core.
# Find out more at http://www.dublincore.org/documents/dc-xml-guidelines/
# http://dublincore.org/documents/dc-citation-guidelines/
# http://jedmodes.sourceforge.net/doc/DC-Metadata/dcmi-terms-for-jedmodes.html
# http://www.ukoln.ac.uk/metadata/dcmi/mixing-matching-faq/

import hashlib
from xml.sax.saxutils import escape

xmloutputversion = '0.3'
dfxml_ns = {'xmlns':'http://afflib.org/fiwalk/',
         'xmlns:xsi':'http://www.w3.org/2001/XMLSchema-instance',
         'xmlns:dc':'http://purl.org/dc/elements/1.1/'}


class xml:
    def __init__(self):
        self.stack = []

    def set_outfilename(self,fn):
        self.outfilename = fn
    
    def open(self,f):
        if type(f)==file:
            self.f = f
        if type(f)==str or type(f)==unicode:
            self.f = open(f,'w')
        self.write("<?xml version='1.0' encoding='UTF-8'?>\n")
        
    def dublin_core(self,dc_record):
        self.push('metadata',dfxml_ns,attrib_delim='\n  ')
        for (n,v) in dc_record.iteritems():
            if v!=None:
                self.xmlout(n,v)
        self.pop('metadata')
        self.write('\n')
        

    def push(self,tag,attribs={},attrib_delim=' '):
        """Enter an XML block, with optional attributes on the tag"""
        self.tagout(tag,attribs=attribs,attrib_delim=attrib_delim,newline=True)
        self.stack.append(tag)

    def pop(self,v=None):
        """Leave an XML block"""
        if v: assert v==self.stack[-1]
        self.tagout("/"+self.stack.pop(),newline=True)

    def tagout(self,tag,attribs={},attrib_delim=' ',newline=None):
        """Outputs a plain XML tag and optional attributes"""
        self.f.write("<%s" % tag)
        if attribs:
            self.f.write(" ")
            count = len(attribs)
            for (n,v) in attribs.iteritems():
                self.f.write("%s='%s'" % (n,escape(v)))
                count -= 1
                if count>0: self.f.write(attrib_delim)
        self.f.write(">")
        if newline: self.f.write("\n")

    def xmlout(self,tag,value,attribs={}):
        """Output an XML tag and its value"""
        self.tagout(tag,attribs,newline=False)
        self.write(escape(str(value)))
        self.write("</%s>\n" % tag)

    def write(self,s):
        self.f.write(s)


def hash_file(fn,x):
    import hashlib
    
    try:
        f = open(fn)
    except IOError,e:
        sys.stderr.write("%s: %s" % (fn,str(e)))
        return

    x.push("fileobject")

    if not args.nofilenames:
        x.xmlout("filename",fn)

    if not args.nometadata:
        x.xmlout("filesize",os.path.getsize(fn))
        x.xmlout("mtime",os.path.getmtime(fn),{'format':'time_t'})
        x.xmlout("ctime",os.path.getctime(fn),{'format':'time_t'})
        x.xmlout("atime",os.path.getatime(fn),{'format':'time_t'})
    
    if args.addfixml:
        x.write(args.addxml)

    if args.md5:    md5_all  = hashlib.md5()
    if args.sha1:   sha1_all = hashlib.sha1()
    if args.sha256: sha256_all = hashlib.sha256()

    chunk_size = 65536          # default chunk size
    if args.piecewise:
        chunk_size = args.piecewise

    if args.piecewise:
        x.push("byte_runs")
    offset = 0
    while True:
        buf = f.read(chunk_size)
        if buf=="": break

        if args.md5:    md5_all.update(buf)
        if args.sha1:   sha1_all.update(buf)
        if args.sha256: sha256_all.update(buf)

        if args.piecewise:
            x.write("<run file_offset='%d' len='%d'>" % (offset,len(buf)))

            if args.md5:
                md5_part = hashlib.md5()
                md5_part.update(buf)
                x.write("<hashdigest type='MD5'>%s</hashdigest>" % md5_part.hexdigest())

            if args.sha1:
                sha1_part = hashlib.sha1()
                sha1_part.update(buf)
                x.write("<hashdigest type='SHA1'>%s</hashdigest>" % sha1_part.hexdigest())

            if args.sha256:
                sha256_part = hashlib.sha256()
                sha256_part.update(buf)
                x.write("<hashdigest type='SHA256'>%s</hashdigest>" % sha256_part.hexdigest())

            x.write("</run>\n")

        offset += len(buf)

    if args.piecewise:
        x.pop("byte_runs")

    if args.md5:
        x.write("<hashdigest type='MD5'>%s</hashdigest>\n" % (md5_all.hexdigest()))
    if args.sha1:
        x.write("<hashdigest type='SHA1'>%s</hashdigest>\n" % (sha1_all.hexdigest()))
    if args.sha256:
        x.write("<hashdigest type='SHA256'>%s</hashdigest>\n" % (sha256_all.hexdigest()))
    x.pop("fileobject")
    x.write("\n")
    

def extract(fn):
    out = sys.stdout
    cdata = None
    def start_element(name,attr):
        global cdata
        if name=='hashdigest':
            try:
                kind = attr['type'].upper()
            except KeyError:
                kind = 'MD5'
                
            if ((kind=='MD5' and args.md5 ) or
                (kind=='SHA1' and args.sha1) or
                (kind=='SHA256' and args.sha256)):
                cdata = ""
        else:
            cdata = None
    def char_data(data):
        global cdata
        if cdata!=None:
            cdata += data
    def end_element(name):
        global cdata
        if cdata!=None:
            out.write(cdata)
            out.write("\n")
            cdata = None

    import xml.parsers.expat
    p = xml.parsers.expat.ParserCreate()
    p.StartElementHandler = start_element
    p.EndElementHandler = end_element
    p.CharacterDataHandler = char_data
    p.ParseFile(open(fn))
    

if(__name__=='__main__'):
    import os.path,sys
    from argparse import ArgumentParser
    global args

    parser = ArgumentParser()
    parser.usage =\
"""
 prog [args] file1 [file2...]   --- hash files and produce DFXML
       [args] dir1 [dir2...]     --- hash dirs and produce DFXML

 You can also extract a set of hashes to stdout with:
             [--md5 | --sha1 | --sha256] --extract=filename.xml 

Note: MD5 output is assumed unless another hash algorithm is specified.
"""
    parser.add_argument('--piecewise',help='Specifies size of piecewise hashes',default=0,type=int)
    parser.add_argument('--addfixml',help='Specifies XML to add to each file object (for labeling)')
    parser.add_argument('--sha1',help='Generate sha1 hashes',action='store_true')
    parser.add_argument('--md5',help='Generate MD5 hashes',action='store_true')
    parser.add_argument('--sha256',help='Generate sha256 hashes',action='store_true')
    parser.add_argument('--output',help='Specify output filename (default stdout)')
    parser.add_argument('--extract',help='Specify a DFXML to extract a hash set from')
    parser.add_argument('--nometadata',help='Do not include file metadata (times & size) in XML',action='store_true')
    parser.add_argument('--nofilenames',help='Do not include filenames in XML',action='store_true')
    parser.add_argument('--title',help='HASHSET Title')
    parser.add_argument('--description',help='HASHSET Description')
    parser.add_argument('--publisher',help='HASHSET Publisher')
    parser.add_argument('--identifier',help='HASHSET Identifier')
    parser.add_argument('--creator',help='HASHSET Author or Creator')
    parser.add_argument('--accessRights',help='HASHSET Access Rights')
    parser.add_argument('--dateSubmitted',help='HASHSET Submission Date')
    parser.add_argument('--abstract',help='HASHSET Abstract')
    parser.add_argument('--classification',help='HASHSET Classification')
    parser.add_argument('--contact',help='HASHSET Contact if found')
    parser.add_argument('targets',help='What to aprse',nargs='+')
    args = parser.parse_args()

    if args.extract:
        extract(args.extract)
        exit(0)

    x = xml()

    if args.output:
        x.open(open(args.output))
    else:
        x.open(sys.stdout)

    # Start the DFXML
    x.push("dfxml",{'xmloutputversion':xmloutputversion})
    x.dublin_core({'dc:type':'Hash Set',
                   'dc:title':args.title,
                   'dc:description':args.description,
                   'dc:publisher':args.publisher,
                   'dc:identifier':args.identifier,
                   'dc:creator':args.creator,
                   'dc:accessRights':args.accessRights,
                   'dc:dateSubmitted':args.dateSubmitted,
                   'dc:abstract':args.abstract,
                   'classification':args.classification,
                   'contactIfFound':args.contact
                   }
                  )

    # Generate the hashes

    for fn in args.targets:
        if os.path.isdir(fn):
            for (dirpath,dirnames,filenames) in os.walk(fn):
                for fn in filenames:
                    hash_file(os.path.join(dirpath,fn),x)
        else:
            hash_file(fn,x)
    x.pop("dfxml")

            
