#!/usr/bin/env python
#
# fiwalk version 0.6.3
#
# %%% BEGIN NO FILL
"""fiwalk module

This is the part of dfxml that is dependent on fiwalk.py

"""
import dfxml
from sys import stderr
from subprocess import Popen,PIPE
ALLOC_ONLY = 1

def fiwalk_installed_version(fiwalk='fiwalk'):
    """Return the current version of fiwalk that is installed"""
    from subprocess import Popen,PIPE
    import re
    for line in Popen([fiwalk,'-V'],stdout=PIPE).stdout.read().split("\n"):
        g = re.search("^FIWalk Version:\s+(.*)$",line)
        if g:
            return g.group(1)
    return None

class XMLDone(Exception):
    def __init__(self,value):
        self.value = value

def fiwalk_xml_version(filename=None):
    """Returns the fiwalk version that was used to create an XML file.
    Uses the "quick and dirt" approach to getting to getting out the XML version."""

    in_element = set()
    cdata = ""
    version = None
    def start_element(name,attrs):
        global cdata
        in_element.add(name)
        cdata = ""
    def end_element(name):
        global cdata
        if ("fiwalk" in in_element) and ("creator" in in_element) and ("version" in in_element):
            raise XMLDone(cdata)
        if ("fiwalk" in in_element) and ("fiwalk_version" in in_element):
            raise XMLDone(cdata)
        in_element.remove(name)
        cdata = ""
    def char_data(data):
        global cdata
        cdata += data

    import xml.parsers.expat
    p = xml.parsers.expat.ParserCreate()
    p.StartElementHandler  = start_element
    p.EndElementHandler    = end_element
    p.CharacterDataHandler = char_data
    try:
        p.ParseFile(open(filename))
    except XMLDone(e):
        return e.value
    except xml.parsers.expat.ExpatError:
        return None             # XML error
    return None
    

################################################################
def E01_glob(fn):
    import os.path
    "If the filename ends .E01, then glob it. Currently only handles E01 through EZZ"""
    ret = [fn]
    if fn.endswith(".E01") and os.path.exists(fn):
        fmt = fn.replace(".E01",".E%02d")
        for i in range(2,100):
            f2 = fmt % i
            if os.path.exists(f2):
                ret.append(f2)
            else:
                return ret
        # Got through E99, now do EAA through EZZ
        fmt = fn.replace(".E01",".E%c%c")
        for i in range(0,26):
            for j in range(0,26):
                f2 = fmt % (i+ord('A'),j+ord('A'))
                if os.path.exists(f2):
                    ret.append(f2)
                else:
                    return ret
        return ret              # don't do F01 through F99, etc.
    return ret


def fiwalk_xml_stream(imagefile=None,flags=0,fiwalk="fiwalk"):
    """ Returns an fiwalk XML stream given a disk image by running fiwalk."""
    fiwalk_args = "-x"
    if flags & ALLOC_ONLY: fiwalk_args += "O"
    from subprocess import call,Popen,PIPE
    # Make sure we have a valid fiwalk
    try:
        res = Popen([fiwalk,'-V'],stdout=PIPE).communicate()[0]
    except OSError:
        raise RuntimeError("Cannot execute fiwalk executable: "+fiwalk)
    p = Popen([fiwalk,fiwalk_args] + E01_glob(imagefile.name),stdout=PIPE)
    return p.stdout

def fiwalk_using_sax(imagefile=None,xmlfile=None,fiwalk="fiwalk",flags=0,callback=None):
    """Processes an image using expat, calling a callback for every file object encountered.
    If xmlfile is provided, use that as the xmlfile, otherwise runs fiwalk."""
    import dfxml
    if xmlfile==None:
        xmlfile = fiwalk_xml_stream(imagefile=imagefile,flags=flags,fiwalk=fiwalk)
    r = dfxml.fileobject_reader(flags=flags)
    r.imagefile = imagefile
    r.process_xml_stream(xmlfile,callback)

def fileobjects_using_sax(imagefile=None,xmlfile=None,fiwalk="fiwalk",flags=0):
    ret = []
    fiwalk_using_sax(imagefile=imagefile,xmlfile=xmlfile,fiwalk=fiwalk,flags=flags,
                     callback = lambda fi:ret.append(fi))
    return ret

def fileobjects_using_dom(imagefile=None,xmlfile=None,fiwalk="fiwalk",flags=0,callback=None):
    """Processes an image using expat, calling a callback for every file object encountered.
    If xmlfile is provided, use that as the xmlfile, otherwise runs fiwalk."""
    import dfxml
    if xmlfile==None:
        xmlfile = fiwalk_xml_stream(imagefile=imagefile,flags=flags,fiwalk=fiwalk)
    return dfxml.fileobjects_dom(xmlfile=xmlfile,imagefile=imagefile,flags=flags)

