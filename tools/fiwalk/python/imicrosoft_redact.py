#!/usr/bin/python

"""This is a small program written with the python fiwalk framework to
break the microsoft executables from the m57 corpus. It does this by changing
characters in the first 4096 bytes of the executable that are over hex 80 to
hex FF"""

import os.path,sys
from subprocess import Popen,call,PIPE

sys.path.append(os.getenv("DOMEX_HOME") + "/src/lib/") # add the library
sys.path.append(os.getenv("DOMEX_HOME") + "/src/fiwalk/python/") # add the library


import fiwalk,hashlib
import xml.parsers.expat

redact_extensions = set([".dll",".exe",".com"])
redact_filenames  = set()
redact_max_size   = 4096

def should_redact(fi):
    if fi.filename() in redact_filenames: return True
    fnl = fi.filename().lower()
    (root,ext) = os.path.splitext(fnl)
    if options.debug: print "\r",fnl,
    if ext in redact_extensions and fnl.startswith("windows"):
        try:
            content = fi.contents(icat_fallback=False)
        except ValueError:
            if options.debug: print " *** can't redact --- is compressed *** "
            return False
        if not content:
            if options.debug: print " *** can't redact --- no content ***"
            return False
        if "Microsoft" in content:
            return True
        if "\0M\0i\0c\0r\0o\0s\0o\0f\0t" in content:
            return True
        if options.debug: print " *** won't redact --- no Microsoft ***"
        return False
    return False

def redact(fi):
    from xml.sax.saxutils import escape
    global xml_out,options
    if not should_redact(fi): return

    # Get the first byterun
    br = fi.byte_runs()[0]

    if br.img_offset==0: return # this run isn't on the disk
    if br.bytes==0: return      # too small to redact

    content = fi.contents()      # before redaction

    redact_bytes = min(redact_max_size,br.bytes)
    fi.imagefile.seek(br.img_offset)
    sector = fi.imagefile.read(redact_bytes)

    # Redact the sector
    # Read the data
    def redact_function(ch):
        if ch<'~': return ch
        return '0xff'

    sector = "".join(map(redact_function,sector))

    # Now write it back
    if options.commit:
        fi.imagefile.seek(br.img_offset)
        fi.imagefile.write(sector)

    redacted_content = fi.contents() # after redaction

    xml_out.write("<fileobject>\n<filename>%s</filename>\n" % (escape(fi.filename())))
    xml_out.write("  <filesize>%d</filesize>\n" % (len(content)))
    xml_out.write("  <inode>%s</inode>\n" % (fi.inode()))
    xml_out.write("  <redact_image_offset>%d</redact_image_offset>\n" % (br.img_offset))
    xml_out.write("  <redact_bytes>%d</redact_bytes>\n" % (redact_bytes))
    xml_out.write("  <before_redact>\n")
    xml_out.write("    <hashdigest type='MD5'>%s</hashdigest>\n" % (hashlib.md5(content).hexdigest()))
    xml_out.write("    <hashdigest type='SHA1'>%s</hashdigest>\n" % (hashlib.sha1(content).hexdigest()))
    xml_out.write("  </before_redact>\n")
    xml_out.write("  <after_redact>\n")
    xml_out.write("    <hashdigest type='MD5'>%s</hashdigest>\n" % (hashlib.md5(redacted_content).hexdigest()))
    xml_out.write("    <hashdigest type='SHA1'>%s</hashdigest>\n" % (hashlib.sha1(redacted_content).hexdigest()))
    xml_out.write("  </after_redact>\n")
    xml_out.write("</fileobject>\n")
    

if __name__=="__main__":
    import sys,time
    from optparse import OptionParser
    from subprocess import Popen,PIPE
    global options,xml_out
    from glob import glob

    parser = OptionParser()
    parser.usage = "%prog [options] imagefile"
    parser.add_option("-d","--debug",help="prints debugging info",dest="debug",action="store_true")
    parser.add_option("-c","--commit",help="Really do the redaction",action="store_true")
    parser.add_option("--all",help="Do all",action="store_true")
    (options,args) = parser.parse_args()

    # First read all of the redaction files
    for fn in glob("*redacted.xml*"):
        try:
            fiwalk.fiwalk_using_sax(xmlfile=open(fn),callback=lambda fi:redact_filenames.add(fi.filename()))
        except xml.parsers.expat.ExpatError:
            print "Invalid XML file:",fn
    print "number of filenames in redaction XML:",len(redact_filenames)

    if options.all:
        for fn in glob("*.aff"):
            raw = fn.replace(".aff",".raw")
            if not os.path.exists(raw):
                print "%s --> %s" % (fn,raw)
                if call(['afconvert','-e','raw',fn])!=0:
                    raise RuntimeError,"afconvert of %s failed" % fn
        fns = glob("*.raw")
    else:
        fns = args
    
    for fn in fns:
        if fn.endswith(".aff"):
            raise ValueError,"Cannot redact AFF files"
        print "Redacting %s" % fn
        xml_out = open(fn.replace(".raw","-redacted.xml"),"w")
        xml_out.write("<?xml version='1.0' encoding='ISO-8859-1'?>\n")
        xml_out.write("<redaction_report>\n")
        mode = "rb"
        if options.commit: mode="r+b"
        fiwalk.fiwalk_using_sax(imagefile=open(args[0],mode),callback=redact)
        xml_out.write("</redaction_report>\n")
