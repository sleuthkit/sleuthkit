#!/usr/bin/env python
#
# dfxml.py
# Digital Forensics XML classes

"""Digital Forensics XML classes.
This module contains a number of classes for dealing with dfxml files,  both using
the XML DOM model and using the EXPAT model.

The following moduel functions are defined:
 isone(x)   - returns true if something is equal to 1 (useful for <ALLOC>1</ALLOC>
 safeInt(x) - converts something to an int but never raises an exception

The following classes are defined in this module:
 byte_run   - the class for representing a run on the disk
 dftime     - represents time. Can be in either Unix timestamp or ISO8601.
              Interconverts as necessary.
 fileobject - represents a DFXML fileobject.


byte_runs() is function that returns an array of byterun objects.
Each object has the attributes:
  file_offset - offset from the beginning of the file
  img_offset  - offset from the beginning of the image
  len         - the number of bytes
  fs_offset   - offset from the beginning of the file system

where encoding, if present, is 0 for raw, 1 for NTFS compressed.

"""
from sys import stderr
from subprocess import Popen,PIPE
import base64

__version__ = "1.0.0"

"Flags"

def isone(x):
    """Return true if something is one (number or string)"""
    try:
        return int(x)==1;
    except TypeError:
        return False

def safeInt(x):
    """Return an integer or False.  False is returned, rather than None, because you can
    divide False by 3 but you can't divide None by 3.

    NOTE: This function could be written as:

    def safeInt(x):
        return int(x) if x else False

    but that doesn't work on older version of Python."""
    if x: return int(x)
    return False

def timestamp2iso8601(ts):
    import time
    return time.strftime("%FT%TZ",time.gmtime(ts))

from datetime import tzinfo,timedelta
class GMTMIN(tzinfo):
    def __init__(self,minoffset):         # DST starts last Sunday in March
        self.minoffset = minoffset
    def utcoffset(self, dt):
        return timedelta(minutes=self.minoffset)
    def dst(self, dt):
        return timedelta(0)
    def tzname(self,dt):
         return "GMT+%02d%02d" % (self.minoffset/60,self.minoffset%60)


import re
tz_offset = re.compile("(\d\d\d\d)-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)(\.\d+)?(Z|[-+]\d+)?$")
def iso8601Tdatetime(s):
    """SLG's conversion of ISO8601 to datetime"""
    m = tz_offset.search(s)
    if not m:
        raise ValueError("Cannot parse: "+s)
    # Get the microseconds
    try:
        microseconds = float(m.group(7)) * 1000000
    except TypeError:
        microseconds = 0
    # Figure tz offset
    offset = None
    if m.group(8)=="Z":
        minoffset = 0
    elif m.group(8)[0:1] in ["-+"]:
        minoffset = int(m.group(8)[0:-2]) * 60 + int(m.group(8)[-2:])
    z = s.find("Z")
    if z>=0:
        offset = 0
    # Build the response
    if minoffset:
        return datetime.datetime(int(m.group(1)),int(m.group(2)),int(m.group(3)),
                                 int(m.group(4)),int(m.group(5)),int(m.group(6)),
                                 microseconds,GMTMIN(minoffset))
    else:
        return datetime.datetime(int(m.group(1)),int(m.group(2)),int(m.group(3)),
                                 int(m.group(4)),int(m.group(5)),int(m.group(6)),
                                 microseconds)
################################################################
###
###  byte_run class
###

class byte_run:
    """The internal representation for a byte run. 

    byte_runs have the following attributes:
    .img_offset  = offset of the byte run from the image start, in bytes
    .len         = the length of the run, in bytes (prevoiusly called 'bytes')
    .sector_size = sector size of the underlying media

    Originally this was an array,
    which is faster than an attributed object. But this approach is more expandable,
    and it's only 70% the speed of an array under Python3.0.
    
    """
    # declaring slots prevents other attributes from appearing,
    # but that prevents the code from working with new XML that has new fields.
    # __slots__ = ["file_offset","img_offset","len","fill","sector_size"]
    def __init__(self,img_offset=None,len=None,file_offset=None):
        self.img_offset = img_offset
        self.file_offset = file_offset
        self.len = len
        self.sector_size = 512          # default
        self.hashdigest  = dict()       # 

    def __cmp__(self,other):
        if self.img_offset != None and other.img_offset != None:
            return cmp(self.img_offset,other.img_offset)
        elif self.file_offset != None and other.file_offset != None:
            return cmp(self.file_offset,other.file_offset)

    def __str__(self):
        try:
            return "byte_run[img_offset=%d; file_offset=%d len=%d] " % \
                (self.img_offset,self.file_offset,self.len)
        except AttributeError:
            pass
        try:
            return "byte_run[file_offset=%d; fill=%d; len=%d]" % \
                (self.file_offset,self.fill,self.len)
        except AttributeError:
            pass
        try:
            return "byte_run[file_offset=%d; uncompressed_len=%d]" % \
                (self.file_offset,self.uncompressed_len)
        except AttributeError:
            return "byte_run"+str(dir(self))
    
    def start_sector(self):
        return self.img_offset // self.sector_size

    def sector_count(self):
        return self.len // self.sector_size

    def has_sector(self,s):
        if self.sector_size==0:
            raise ValueError("%s: sector_size cannot be 0" % (self))
        try:
            return self.img_offset <= s * self.sector_size < self.img_offset+self.len
        except AttributeError:
            # Doesn't have necessary attributes to answer true.
            # Usually this happens with runs of a constant value
            return False       

    def extra_len(self):
        return self.len % self.sector_size

    def decode_xml_attributes(self,attr):
        for (key,value) in attr.items():
            try:
                setattr(self,key,int(value))
            except ValueError:
                setattr(self,key,value)

        
    def decode_sax_attributes(self,attr):
        for (key,value) in attr.items():
            if key=='bytes': key=='len' # tag changed name; provide backwards compatiability 
            try:
                setattr(self,key,int(value))
            except ValueError:
                setattr(self,key,value)
        
class ComparableMixin(object):
    """
    Comparator "Abstract" class.  Classes inheriting this must define a _cmpkey() method.
    
    Credit to Lennart Regebro for the total implementation of this class, found equivalently from:
    http://regebro.wordpress.com/2010/12/13/python-implementing-rich-comparison-the-correct-way/
    http://stackoverflow.com/questions/6907323/comparable-classes-in-python-3/6913420#6913420
    """
    def _compare(self, other, method):
        try:
            return method(self._cmpkey(), other._cmpkey())
        except (AttributeError, TypeError):
            # _cmpkey not implemented, or return different type,
            # so I can't compare with "other".
            return NotImplemented

    def __lt__(self, other):
        return self._compare(other, lambda s, o: s < o)

    def __le__(self, other):
        return self._compare(other, lambda s, o: s <= o)

    def __eq__(self, other):
        return self._compare(other, lambda s, o: s == o)

    def __ge__(self, other):
        return self._compare(other, lambda s, o: s >= o)

    def __gt__(self, other):
        return self._compare(other, lambda s, o: s > o)

    def __ne__(self, other):
        return self._compare(other, lambda s, o: s != o)

class dftime(ComparableMixin):
    """Represents a DFXML time. Automatically converts between representations and caches the
    results as necessary.."""
    UTC = GMTMIN(0)
    def ts2datetime(self,ts):
        import datetime
        return datetime.datetime.utcfromtimestamp(ts).replace(tzinfo=dftime.UTC)

    def __init__(self,val):
        if type(val)==str or type(val)==unicode:
            #Test for ISO format - "YYYY-MM-DD" should have hyphen at val[4]
            if len(val)>5 and val[4]=="-":
                self.iso8601_ = val
            else:
                #Maybe the data is a string-wrapped int?
                #If this fails, data is completely unexpected, so just raise error.
                self.timestamp_ = int(val)
        elif type(val)==int or type(val)==float:
            self.timestamp_ = val
        elif val==None:
            self.timestamp_ = None
            self.iso8601_   = None
        elif isinstance(val, dftime):
            #If we instead use .timestamp_, we risk having a timezone conversion error
            self.iso8601_ = val.iso8601()
        else:
            raise ValueError("Unknown type '%s' for DFXML time value" % (str(type(val))))
    def __str__(self):
        return self.iso8601()
    def __repr__(self):
        return self.iso8601()

    def _cmpkey(self):
        """Provide a key to use for comparisons; for use with ComparableMixin parent class."""
        return self.timestamp()
    
    def __eq__(self,b):
        if b == None:
            #This will always be False - if self were None, we wouldn't be in this __eq__ method.
            return False
        # See if there is a common representation in a form that can be compared
        # before forcing a conversion
        try:
            return self.timestamp_==b.timestamp_
        except AttributeError:
            pass

        try:
            return self.datetime_.utctimetuple() == b.datetime_.utctimetuple()
        except AttributeError:
            pass

        # Okay, convert to datetime and then redo the datetime.
        # The actual datetimes may be the same. If they aren't, the UTC times may be the same.
        if self.datetime()==b.datetime():
            return True
        return self.datetime_.utctimetuple() == b.datetime_.utctimetuple()

    def iso8601(self):
        # Do we have a cached representation?
        import time
        try:
            return self.iso8601_
        except AttributeError:
            pass
        
        # Do we have a datetime representation?
        try:
            self.iso8601_ = self.datetime.isoformat()
            return self.iso8601_
        except AttributeError:
            # We better have a Unix timestamp representation?
            self.iso8601_ = time.strftime("%FT%TZ",time.gmtime(self.timestamp_))
            return self.iso8601_
    
    def timestamp(self):
        import time,dateutil.parser
        # Do we have a cached representation?
        try:
            return self.timestamp_
        except AttributeError:
            pass

        # Do we have a datetime_ object?
        try:
            self.timestamp_ = time.mktime(self.datetime_.timetuple())
            return self.timestamp_
        except AttributeError:
            self.datetime_ = dateutil.parser.parse(self.iso8601_)
            self.timestamp_ = time.mktime(self.datetime_.timetuple())
            return self.timestamp_
        
    def datetime(self):
        import datetime,dateutil.parser
        # return the datetime from parsing either iso8601 or from parsing timestamp
        try:
            self.datetime_ = self.ts2datetime(self.timestamp_)
            # This needs to be in UTC offset. How annoying.
            return self.datetime_
        except AttributeError:
            self.datetime_ = dateutil.parser.parse(self.iso8601_)
            return self.datetime_

class registry_object:
    def __init__(self):
        self.object_index = {}
        self._mtime = None
        
        """Keep handy a handle on the registry object"""
        self.registry_handle = self

    def mtime(self):
        return self._mtime

class registry_cell_object:
    def __init__(self):
        self._byte_runs  = []

        """This is a pointer to a registry_key_object.  The root node has no parent key."""
        self.parent_key = None

        """This is the name of the present key or value."""
        self.name        = None

        """
        This is the full path from the root of the hive, with keys acting like directories and the value name acting like the basename.
        
        Unlike DFXML, registry paths are delimited with a backslash due to the forward slash being a legal and commonly observed character in cell names.
        """
        self.full_path   = None

        """Keys have two types:  "root" (0x2c,0xac) and not-root.  Values have several more types."""
        self.type        = None

        """Keep handy a handle on the registry object"""
        self.registry_handle = None
        
        """Name the cell type, for str() and repr()."""
        self._cell_type = "(undefined cell object type)"

    def _myname(self):
        """This function is called by repr and str, due to (vague memories of) the possibility of an infinite loop if __repr__ calls __self__."""
        if len(self._byte_runs) > 0:
            addr = str(self._byte_runs[0].file_offset)
        else:
            addr = "(unknown)"
        return "".join(["<", self._cell_type, " for hive file offset ", addr, ">"])

    def __repr__(self):
        return self._myname()
    def __str__(self):
        return self._myname()

    def mtime(self):
        raise NotImplementedError("registry_cell_object.mtime() not over-ridden!")

    def byte_runs(self):
        """Returns a sorted array of byte_run objects."""
        #If this idiom is confusing, see:  http://henry.precheur.org/python/copy_list
        ret = list(self._byte_runs)
        return ret

class registry_key_object(registry_cell_object):
    def __init__(self):
        registry_cell_object.__init__(self)
        self._mtime = None
        self.values = {}
        self.used = True  #TODO Add toggling logic for when hivexml (eventually) processes recovered keys
        self._cell_type = "registry_key_object"
    def mtime(self):
        return self._mtime
    def root(self):
        if self.type == None:
            return None
        return self.type == "root"

class registry_value_object(registry_cell_object):
    def __init__(self):
        registry_cell_object.__init__(self)
        self.value_data  = None

        self._cell_type = "registry_value_object"
        
        """List for the string-list type of value."""
        self.strings = None
    def mtime(self):
        """Return nothing.  Alternatively, we might return mtime of parent key in the future."""
        return None
    #    if self.parent_key:
    #        return self.parent_key.mtime()
    #    else:
    #        return None

class fileobject:
    """The base class for file objects created either through XML DOM or EXPAT"""
    TIMETAGLIST=['atime','mtime','ctime','dtime','crtime']

    def __init__(self,imagefile=None):
        self.imagefile  = imagefile
        self.hashdigest = dict()
        
    def __str__(self):
        try:
            fn = self.filename()
        except KeyError:
            fn = "???"
        return "fileobject %s byte_runs: %s" % (fn, " ".join([str(x) for x in self.byte_runs()]))

    def partition(self):
        """Partion number of the file"""
        return self.tag("partition")

    def filename(self):
        """Name of the file"""
        return self.tag("filename")

    def ext(self):
        """Extension, as a lowercase string without the leading '.'"""
        import os, string
        (base,ext) = os.path.splitext(self.filename())
        if ext == '':
            return None
        else:
            return string.lstrip(ext, '\.')

    def filesize(self):
        """Size of the file, in bytes"""
        return safeInt(self.tag("filesize"))

    def uid(self):
        """UID of the file"""
        return safeInt(self.tag("uid"))

    def gid(self):
        """GID of the file"""
        return safeInt(self.tag("gid"))

    def meta_type(self):
        """Meta-type of the file"""
        return safeInt(self.tag("meta_type"))

    def mode(self):
        """Mode of the file"""
        return safeInt(self.tag("mode"))

    def ctime(self):
        """Metadata Change Time (sometimes Creation Time), as number of seconds
        since January 1, 1970 (Unix time)"""
        return dftime(self.tag("ctime"))   
        
    def atime(self):
        """Access time, as number of seconds since January 1, 1970 (Unix time)"""
        return dftime(self.tag("atime"))   
        
    def crtime(self):
        """CR time, as number of seconds since January 1, 1970 (Unix time)"""
        return dftime(self.tag("crtime"))  
        
    def mtime(self):
        """Modify time, as number of seconds since January 1, 1970 (Unix time)"""
        return dftime(self.tag("mtime"))  
        
    def dtime(self):
        """ext2 dtime"""
        return dftime(self.tag("dtime"))

    def times(self):
        """Return a dictionary of all times that the system has"""
        ret = {}
        for tag in self.TIMETAGLIST:
            if self.has_tag(tag):
                try:
                    ret[tag] = dftime(self.tag(tag))
                except TypeError:
                    pass
        return ret

    def sha1(self):
        """Returns the SHA1 in hex"""
        return self.tag("sha1")

    def md5(self):
        """Returns the MD5 in hex"""
        return self.tag("md5")

    def fragments(self):
        """Returns number of file fragments"""
        return len(self.byte_runs())

    def name_type(self):
        """Return the contents of the name_type tag"""
        return self.tag("name_type")

    def is_dir(self):
        """Returns true if file is a directory"""
        return self.name_type()=='d'

    def is_file(self):
        """Returns true if file is a file"""
        return self.name_type()=='r'

    def inode(self):
        """Inode; may be a number or SleuthKit x-y-z formatr"""
        return self.tag("inode")

    def allocated(self):
        """Returns True if the file is allocated, False if it was not
        (that is, if it was deleted or is an orphan).
        Note that we need to be tolerant of mixed case, as it was changed.
        """
        if self.filename()=="$OrphanFiles": return False
        return isone(self.tag("alloc")) or isone(self.tag("ALLOC"))

    def compressed(self):
        if not self.has_tag("compressed") and not self.has_tag("compressed") : return False
        return isone(self.tag("compressed")) or isone(self.tag("COMPRESSED"))

    def encrypted(self):
        if not self.has_tag("encrypted") and not self.has_tag("encrypted") : return False
        return isone(self.tag("encrypted")) or isone(self.tag("ENCRYPTED"))

    def file_present(self,imagefile=None):
        """Returns true if the file is present in the disk image"""
        import hashlib
        if self.filesize()==0:
            return False               # empty files are never present
        if imagefile==None:
            imagefile=self.imagefile # use this one
        for hashname in ['md5','sha1']:
            oldhash = self.tag(hashname)
            if oldhash:
                newhash = hashlib.new(hashname,self.contents(imagefile=imagefile)).hexdigest()
                return oldhash==newhash
        raise ValueError("Cannot process file "+self.filename()+": no hash in "+str(self))

    def has_contents(self):
        """True if the file has one or more bytes"""
        return len(self.byte_runs())>0

    def has_sector(self,s):
        """True if sector s is contained in one of the byte_runs."""
        for run in self.byte_runs():
            if run.has_sector(s): return True
        return False

    def libmagic(self):
        """Returns libmagic string if the string is specified
           in the xml, or None otherwise"""
        return self.tag("libmagic")

    def content_for_run(self,run=None,imagefile=None):
        """ Returns the content for a specific run. This is a convenience feature
        which does not touch the file object if an imagefile is provided."""
        if imagefile==None: imagefile=self.imagefile
        if run.len== -1:
            return chr(0) * run.len
        elif hasattr(run,'fill'):
            return chr(run.fill) * run.len
        else:
            imagefile.seek(run.img_offset)
            return imagefile.read(run.len)

    def contents(self,imagefile=None,icat_fallback=True):
        """ Returns the contents of all the runs concatenated together. For allocated files
        this should be the original file contents. """
        if imagefile is None     : imagefile=self.imagefile
        if imagefile is None     : raise ValueError("imagefile is unknown")
        if self.encrypted()      : raise ValueError("Cannot generate content for encrypted files")
        if self.compressed() or imagefile.name.endswith(".aff") or imagefile.name.endswith(".E01"):
            if icat_fallback:
                # 
                # For now, compressed files rely on icat rather than python interface
                #
                offset     = safeInt(self.volume.offset)
                block_size = safeInt(self.volume.block_size)
                if block_size==0: block_size = 512
                inode = self.inode()
                if inode :
                    block_size = 512
                    cmd = ['icat','-b',str(block_size),'-o',str(offset/block_size),imagefile.name,str(inode)] 
                    (data,err) = Popen(cmd, stdout=PIPE,stderr=PIPE).communicate()
                    # Check for an error
                    if len(err) > 0 :  
                        raise ValueError("icat error: "+" ".join(cmd))
                    return data
                else :
                    raise ValueError("Inode missing from file in compressed format.")
            raise ValueError("Cannot read raw bytes in compressed disk image")
        res = []
        for run in self.byte_runs():
            res.append(self.content_for_run(run=run,imagefile=imagefile))
        return "".join(res)

    def tempfile(self,calcMD5=False,calcSHA1=False):
        """Return the contents of imagefile in a named temporary file. If
        calcMD5 or calcSHA1 are set TRUE, then the object returned has a
        haslib object as self.md5 or self.sha1 with the requested hash."""
        import tempfile,hashlib
        tf = tempfile.NamedTemporaryFile()
        if calcMD5: tf.md5 = hashlib.md5()
        if calcSHA1: tf.sha1 = hashlib.sha1()
        for run in self.byte_runs():
            self.imagefile.seek(run.img_start)
            count = run.len
            while count>0:
                xfer_len = min(count,1024*1024)        # transfer up to a megabyte at a time
                buf = self.imagefile.read(xfer_len)
                tf.write(buf)
                if calcMD5: tf.md5.update(buf)
                if calcSHA1: tf.sha1.update(buf)
                count -= xfer_len
        tf.flush()
        return tf
        
    def frag_start_sector(self,fragment):
        return self.byte_runs()[fragment].img_offset / 512

    def name_type(self):
        return self.tag("name_type")

class fileobject_dom(fileobject):
    """file objects created through the DOM. Each object has the XML document
    stored in the .doc attribute."""    
    def __init__(self,xmldoc,imagefile=None):
        fileobject.__init__(self,imagefile=imagefile)
        self.doc = xmldoc

    def tag(self,name):
        """Returns the wholeText for any given NAME. Raises KeyError
        if the NAME does not exist."""
        try:
            return self.doc.getElementsByTagName(name)[0].firstChild.wholeText
        except IndexError:
            # Check for a hash tag with legacy API
            if name in ['md5','sha1','sha256']:
                for e in self.doc.getElementsByTagName('hashdigest'):
                    if e.getAttribute('type').lower()==name:
                        return e.firstChild.wholeText
            raise KeyError(name+" not in XML")

    def has_tag(self,name) :
        try:
            temp=self.doc.getElementsByTagName(name)[0].firstChild.wholeText
            return True
        except IndexError:
            # Check for a hash tag with legacy API
            if name in ['md5','sha1','sha256']:
                for e in self.doc.getElementsByTagName('hashdigest'):
                    if e.getAttribute('type').lower()==name:
                        return True
            return False

    def byte_runs(self):
        """Returns a sorted array of byte_run objects.
        """
        ret = []
        try:
            for run in self.doc.getElementsByTagName("byte_runs")[0].childNodes:
                b = byte_run()
                if run.nodeType==run.ELEMENT_NODE:
                    b.decode_xml_attributes(run.attributes)
                    ret.append(b)
        except IndexError:
            pass
        ret.sort(key=lambda r:r.file_offset)
        return ret



class saxobject:
    # saxobject is a mix-in that makes it easy to turn XML tags into functions.
    # If the sax tag is registered, then a function with the tag's name is created.
    # Calling the function returns the value for the tag that is stored in the _tags{}
    # dictionary. The _tags{} dictionary is filled by the _end_element() method that is defined.
    # For fileobjects all tags are remembered.
    def __init__(self):
        self._tags     = {}
    def tag(self,name):
        """Returns the XML text for a given NAME."""
        return self._tags.get(name,None)
    def has_tag(self,name) : return name in self._tags

def register_sax_tag(tagclass,name):
    setattr(tagclass,name,lambda self:self.tag(name))

class fileobject_sax(fileobject,saxobject):
    """file objects created through expat. This class is created with a tags array and a set of byte runs."""
    def __init__(self,imagefile=None,xml=None):
        fileobject.__init__(self,imagefile=imagefile)
        saxobject.__init__(self)
        self._byte_runs = []
    def byte_runs(self):
        """Returns an array of byte_run objects."""
        return self._byte_runs


class volumeobject_sax(saxobject):
    """A class that represents the volume."""
    def __init__(self):
        if hasattr(saxobject, "__init__"):
            saxobject.__init__(self)
        self.offset = 0
        self.block_size = 0

    def __str__(self):
        return "volume "+(str(self._tags))

    def partition_offset(self):
        try:
            return self.tag('partition_offset')
        except KeyError:
            return self.tag('Partition_Offset')

register_sax_tag(volumeobject_sax,'ftype')
register_sax_tag(volumeobject_sax,'ftype_str')
register_sax_tag(volumeobject_sax,'block_count')
register_sax_tag(volumeobject_sax,'first_block')
register_sax_tag(volumeobject_sax,'last_block')
    
class imageobject_sax(saxobject):
    """A class that represents the disk image"""
register_sax_tag(imageobject_sax,'imagesize')
register_sax_tag(imageobject_sax,'image_filename')


################################################################

################################################################

class xml_reader:
    def __init__(self):
        self.data = None
        self.tagstack = ['xml']
    
    def _char_data(self, data):
        """Handles XML data"""
        if self.data != None:
            self.data += data


    def process_xml_stream(self,xml_stream,callback):
        "Run the reader on a given XML input stream"
        self.callback = callback
        import xml.parsers.expat
        p = xml.parsers.expat.ParserCreate()
        p.StartElementHandler  = self._start_element
        p.EndElementHandler    = self._end_element
        p.CharacterDataHandler = self._char_data
        p.ParseFile(xml_stream)    

class regxml_reader(xml_reader):
    def __init__(self,flags=None):
        self.flags = flags
        xml_reader.__init__(self)  #TODO wait, shouldn't flags go in here?
        self.objectstack = []
        self.registry_object = None
        self.nonce = 0

    def _start_element(self, name, attrs):
        """
        The objectstack conditionally grows, depending on type of element processed
        * msregistry (hive):  Create a new msregistry object, append to objectstack
        * key (node):  Create a new key object, append to objectstack
        * mtime:  The text is going to become a property of the parent element; do not append to objectstack.
        * value:  Create a new value object, append to objectstack.
        """
        new_object = None
        if name in ["msregistry","hive"]:
            new_object = registry_object()
            self.objectstack.append(new_object)
            self.registry_object = new_object
        elif name in ["key","node"]:
            new_object = registry_key_object()
            
            #Note these two tests for root and parent _are_ supposed to be independent tests.
            if attrs.get("root",None) == "1":
                new_object.type = "root"
            else:
                new_object.type = ""

            if len(self.objectstack) > 1:
                new_object.parent_key = self.objectstack[-1]

            #Sanity check:  root key implies no parent
            if new_object.type == "root":
                assert new_object.parent_key == None
            #Sanity check:  no parent implies root key --OR-- recovered key
            if new_object.parent_key == None:
                assert new_object.used == False or new_object.type == "root"

            enc = attrs.get("name_encoding")
            name_data = str(attrs.get("name"))
            if name_data == None:
                name_data = str(self.nonce)
                self.nonce += 1

            if enc == "base64":
                try:
                    #new_object.name = unicode(name_data.decode("base64")) #AJN TODO Correct non-isprint character printing
                    new_object.name = "(Base-64 encounter #%d)" % self.nonce
                    self.nonce += 1
                except:
                    print "name_data=" + name_data
                    print "type(name_data)=" + str(type(name_data))
                    raise
            else:
                new_object.name = unicode(name_data)

            if new_object.parent_key == None:
                new_object.full_path = u"\\" + new_object.name #TODO need a name scheme for orphan references, when we start processing orphans
            else:
                new_object.full_path = new_object.parent_key.full_path + u"\\" + new_object.name
            self.objectstack.append(new_object)
        elif name in ["value"]:
            new_object = registry_value_object()
            new_object.parent_key = self.objectstack[-1]
            new_object.type = attrs.get("type",None)

            if new_object.type == u"string-list":
                new_object.strings = []
            
            #Store decoded name
            if attrs.get("default",None) == u"1":
                new_object.name = "Default" #TODO Check for concurrently set name and default flag?
            else:
                enc = attrs.get("name_encoding",attrs.get("key_encoding"))
                name_data = attrs.get("name",attrs.get("key",None))
                if enc == "base64":
                    try:
                        new_object.name = base64.b64decode(name_data)
                        new_object.name = "(Base-64 encounter #%d)" % self.nonce
                        self.nonce += 1
                    except:
                        print "name_data=" + name_data
                        print "type(name_data)=" + str(type(name_data))
                        raise
                else:
                    new_object.name = unicode(name_data)
            new_object.full_path = new_object.parent_key.full_path + "\\" + new_object.name

            #Store decoded value
            new_object.value_data = self.decoded_value(attrs)
            self.objectstack.append(new_object)
        elif name in ["mtime"]:
            self.data = ""
        elif name in ["string"]:
            self.data = ""
        elif name in ["byte_runs"]:
            pass
        elif name in ["byte_run"]:
            parent = self.objectstack[-1]
            parent._byte_runs.append(byte_run(file_offset=attrs.get("file_offset"), len=attrs.get("len")))
        else:
            raise ValueError("regxml_reader._start_element: Don't know how to start element %s.\n" % name)
        #Give all cell objects a handle on the registry
        if new_object != None:
            new_object.registry_handle = self.registry_object

    def decoded_value(self, attrs):
        value_data = attrs.get("value",None)
        if value_data:
            value_encoding = attrs.get("encoding", attrs.get("value_encoding")) #TODO adjust hivexml to not use a plain "encoding" attribute
            if value_encoding == "base64":
                return base64.b64decode(value_data)
            else:
                return value_data
        else:
            return None

    def _end_element(self, name):
        """
        The callback is invoked for each stack-popping operation, except the root.
        """
        #TODO sanity-check the objectstack
        if name in ["msregistry","hive"]:
            pass
        elif name in ["key","node"]:
            finished_object = self.objectstack.pop()
            #Add finished object to object index
            if finished_object.full_path in self.registry_object.object_index:
                raise ValueError("regxml_reader._end_element:  Same key path found more than once: " + finished_object.full_path)
            self.registry_object.object_index[finished_object.full_path] = finished_object
            self.callback(finished_object)
        elif name in ["mtime"]:
            self.objectstack[-1]._mtime = dftime(self.data)
            self.data = None
        elif name in ["value"]:
            finished_object = self.objectstack.pop()
            #TODO Simplify once hivexml is patched to have value/@value instead of value/[cdata]
            if finished_object.value_data == None:
                finished_object.value_data = self.data
            self.callback(finished_object)
        elif name in ["string"]:
            value_object = self.objectstack[-1]
            if value_object.strings == None:
                raise ValueError("regxml_reader._end_element:  parsing error, string found but parent's type can't support a string list.")
            value_object.strings.append(self.data)
            self.data = None
        elif name in ["byte_runs","byte_run"]:
            pass
        else:
            raise ValueError("regxml_reader._end_element: Don't know how to end element %s.\n" % name)

class fileobject_reader(xml_reader):
    """Class which uses the SAX expat-based XML reader.
    Reads an FIWALK XML input file and automatically creates
    volumeobject_sax and fileobject_sax objects, but just returns the filoeobject
    objects.."""
    def __init__(self,imagefile=None,flags=None):
        self.volumeobject = None
        self.fileobject   = None
        self.imageobject  = imageobject_sax()
        self.imagefile    = imagefile
        self.flags        = flags
        xml_reader.__init__(self)
        
    def _start_element(self, name, attrs):
        """ Handles the start of an element for the XPAT scanner"""
        self.tagstack.append(name)
        if name=="volume":
            self.volumeobject            = volumeobject_sax()
            self.volumeobject.block_size = 512 # reasonable default
            self.volumeobject.image      = self.imageobject
            self.data                    = ""
            if "offset" in attrs: self.volumeobject.offset = int(attrs["offset"]) 
            return
        if name=="block_size":
            self.data = ""
        if name=="fileobject":
            self.fileobject = fileobject_sax(imagefile=self.imagefile)
            self.fileobject.volume = self.volumeobject
            return
        if name=='hashdigest':
            self.hashdigest_type = attrs['type'] # remember the type
        if not self.fileobject: return
        if name=="run" or name=="byte_run":
            b = byte_run()
            b.decode_sax_attributes(attrs)
            self.fileobject._byte_runs.append(b)
            return
        self.data = ""                 # new element; otherwise data is ignored

    def _end_element(self, name):
        """Handles the end of an eleement for the XPAT scanner"""
        assert(self.tagstack.pop()==name)
        if name=="volume":
            self.volumeobject = None
            return
        if name=="block_size" and len(self.tagstack) > 1 : 
            if self.tagstack[-1] == "volume" : 
                self.volumeobject.block_size = int(self.data)
                self.data=None
            return
        if name=="fileobject":
            self.callback(self.fileobject)
            self.fileobject = None
            return
        if name=='hashdigest' and self.fileobject:
            top = self.tagstack[-1]            # what the hash was for
            alg = self.hashdigest_type.lower() # name of the hash algorithm used
            if top=='byte_run':
                self.fileobject._byte_runs[-1].hashdigest[alg] = self.data
            if top=='fileobject':
                self.fileobject._tags[alg] = self.data # legacy
                self.fileobject.hashdigest[alg] = self.data
            self.data = None
            return
        if self.fileobject:             # in a file object, all tags are remembered
            self.fileobject._tags[name] = self.data
            self.data = None
            return
        # Special case: <source><image_filename>fn</image_filename></source>
        # gets put in <image_filename>fn</image_filename>
        if name in ['image_filename','imagefile'] and self.tagstack[-1]=='source':
            self.imageobject._tags['image_filename'] = self.data

class volumeobject_reader(xml_reader):
    def __init__(self):
        self.volumeobject = False
        xml_reader.__init__(self)
        self.imageobject  = imageobject_sax()

    def _start_element(self, name, attrs):
        """ Handles the start of an element for the XPAT scanner"""
        self.tagstack.append(name)
        if name=="volume":
            self.volumeobject = volumeobject_sax()
            self.volumeobject.image = self.imageobject
            return
        if name=='fileobject':
            self.data = None            # don't record this
            return
        self.data = ""                  # new element; otherwise data is ignored

    def _end_element(self, name):
        """Handles the end of an eleement for the XPAT scanner"""
        assert(self.tagstack.pop()==name)
        if name=="volume":
            self.callback(self.volumeobject)
            self.volumeobject = None
            return
        if self.tagstack[-1]=='volume' and self.volumeobject:             # in the volume
            self.volumeobject._tags[name] = self.data
            self.data = None
            return
        if self.tagstack[-1] in ['fiwalk','dfxml']:
            self.imageobject._tags[name] = self.data
            return

        # Special case: <source><image_filename>fn</image_filename></source> gets put in <image_filename>fn</image_filename>
        if name in ['image_filename','imagefile'] and self.tagstack[-1]=='source':
            self.imageobject._tags['image_filename'] = self.data
        return


def combine_runs(runs):
    """Given an array of bytrun elements, combine the runs and return a new array."""
    if runs==[]: return []
    ret = [runs[0]]
    for run in runs[1:]:
        # if the last one ends where this run begins, just extend
        # otherwise append
        last = ret[-1]
        if last.img_offset+last.len == run.img_offset:
            ret[-1] = byte_run(img_offset = last.img_offset,
                              len = last.len + run.len)
            continue
        else:
            ret.append(run)
    return ret

class extentdb:
    """A class to a database of extents and report if they collide.
    Currently this is not an efficient implementation, but it could become
    more efficient in the future. When it does, every program that uses
    this implementation will get faster too!  Each extent is represented
    as a byte_run object"""
    def __init__(self,sectorsize=512):
        self.db = []                    # the database of runs
        self.sectorsize = 512
        pass
    
    def report(self,f):
        """Print information about the database"""
        f.write("sectorsize: %d\n" % self.sectorsize)
        for run in sorted(self.db):
            f.write("   [@%8d ; %8d]\n" % (run.img_offset,run.len))
        f.write("total entries in database: %d\n\n" % len(r))
    
    def sectors_for_bytes(self,count):
        """Returns the number of sectors necessary to hold COUNT bytes"""
        return (count+self.sectorsize-1)//self.sectorsize
    
    def sectors_for_run(self,run):
        """Returns an array of the sectors for a given run"""
        start_sector = run.img_offset/self.sectorsize
        sector_count = self.sectors_for_bytes(run.len)
        return range(start_sector,start_sector+sector_count)

    def run_for_sector(self,sector_number,count=1):
        """Returns the run for a specified sector, and optionally a count of sectors"""
        return byte_run(len=count*self.sectorsize,img_offset=sector_number * self.sectorsize)

    def intersects(self,extent):
        """Returns the intersecting extent, or None if there is none"""
        if extent.len==0: return True    # 0 length intersects with everything
        if extent.len<0: raise ValueError("Length cannot be negative:"+str(extent))
        start = extent.img_offset
        stop  = extent.img_offset+extent.len
        for d in self.db:
            if d.img_offset <= start < d.img_offset+d.len: return d
            if d.img_offset < stop  < d.img_offset+d.len: return d
            if start<d.img_offset and d.img_offset+d.len <= stop: return d
        return None

    def intersects_runs(self,runs):
        """Returns the intersecting extent for a set of runs, or None
        if there is none."""
        for r in runs:
            v = self.intersects(r)
            if v: return v
        return None

    def intersects_sector(self,sector):
        """Returns the intersecting extent for a specified sector, None otherwise.
        Sector numbers start at 0."""
        return self.intersects(self.run_for_sector(sector))

    def add(self,extent):
        """Adds an EXTENT (start,length) to the database.
        Raises ValueError if there is an intersection."""
        v = self.intersects(extent)
        if v:
            raise ValueError("Cannot add "+str(extent)+": it intersects "+str(v))
        self.db.append(extent)

    def add_runs(self,runs):
        """Adds all of the runs to the extent database"""
        for r in runs:
            self.add(r)

    def runs_for_sectors(self,sectors):
        """Given a list of SECTORS, return a list of RUNS.
        Automatically combines adjacent runs."""

        runs = [byte_run(len=self.sectorsize,img_offset=x*self.sectorsize) for x in sectors]
        return combine_runs(runs)

    def add_sectors(self,sectors):
        """Adds the sectors in the list to the database."""
        self.add_runs(self.runs_for_sectors(sectors))

    def sectors_not_in_db(self,run):
        """For a given run, return a list of sectors not in the extent db"""
        return filter(lambda x:not self.intersects_sector(x),self.sectors_for_run(run))


def read_dfxml(xmlfile=None,imagefile=None,flags=0,callback=None):
    """Processes an image using expat, calling a callback for every file object encountered.
    If xmlfile is provided, use that as the xmlfile, otherwise runs fiwalk."""
    if not callback:
        raise ValueError("callback must be specified")
    r = fileobject_reader(imagefile=imagefile,flags=flags)
    r.process_xml_stream(xmlfile,callback)
    return r

def read_regxml(xmlfile=None,flags=0,callback=None):
    """Processes an image using expat, calling a callback for node encountered."""
    import xml.parsers.expat
    if not callback:
        raise ValueError("callback must be specified")
    if not xmlfile:
        raise ValueError("regxml file must be specified")
    r = regxml_reader(flags=flags)
    try:
        r.process_xml_stream(xmlfile,callback)
    except xml.parsers.expat.ExpatError:
        stderr.write("XML parsing error for file \"" + xmlfile.name + "\".  Object stack:\n")
        for x in r.objectstack:
            stderr.write(str(x) + "\n")
        stderr.write("(Done.)\n")
        raise
    return r

def fileobjects_sax(xmlfile=None,imagefile=None,flags=0):
    """Returns a LIST of fileobjects extracted from the given
    imagefile. If XMLFILE is provided, read the objects are read
    directly from the XML, otherwise this method runs fiwalk with the
    specified FLAGS."""
    ret = []
    read_dfxml(xmlfile=xmlfile,imagefile=imagefile,flags=flags,
                     callback=lambda fi:ret.append(fi))
    return ret

def fileobjects_iter(xmlfile=None,imagefile=None,flags=0):
    """Returns an iterator that returns fileobjects extracted from the given
    imagefile. If XMLFILE is provided, read the objects are read
    directly from the XML, otherwise this method runs fiwalk with the
    specified FLAGS."""
    print("For reasons we do not understand, fileobjects_iter currently does not work.")
    def local_iter(fi):
        yield fi
    read_dfxml(xmlfile=xmlfile,imagefile=imagefile,flags=flags,callback=local_iter)

def fileobjects_dom(xmlfile=None,imagefile=None,flags=0):
    """Returns a tuple consisting of (XML,LIST) where XML is the
    document of the imagefile's fiwalk and LIST is a list of file
    objects extracted from that document."""

    import xml.dom.minidom
    doc =  xml.dom.minidom.parseString(xmlfile.read())
    ret = []
    for xmlfi in doc.getElementsByTagName("fileobject"):
        fi = fileobject_dom(xmlfi,imagefile=imagefile)
        ret.append(fi)
    return (doc,ret)

def volumeobjects_sax(xmlfile=None,imagefile=None,flags=0):
    ret = []
    r = volumeobject_reader()
    r.process_xml_stream(xmlfile,imagefile=None,callback=lambda vo:ret.append(vo))
    return ret
    
        
        
################################################################
if __name__=="__main__":
    from optparse import OptionParser
    parser = OptionParser()
    parser.add_option("-r","--regress",action="store_true")
    (options,args) = parser.parse_args()

    def check_equal(a,b,want=None):
        da = dftime(a)
        db = dftime(b)
        result = da==db
        warn = ""
        if result != want:
            warn = " (!)"
        print("a=%s b=%s want=%s equal=%s%s" % (da,db,want,result,warn))
    
    def check_greater(a,b,want=None):
        da = dftime(a)
        db = dftime(b)
        result = da>db
        warn = ""
        if result != want:
            warn = " (!)"
        print("a=%s b=%s want=%s greater=%s%s" % (da,db,want,result,warn))

    if options.regress:
        print("Testing dftime values")
        check_equal("1900-01-02T02:03:04Z",-2208895016,True)
        check_equal("2000-01-02T02:03:04Z","2000-01-02T03:03:04-0100",False)
        check_equal("2000-01-02T02:03:04-0100","2000-01-02T02:03:04-0100",True)
        check_equal("2000-01-02T02:03:04-0100","2000-01-02T02:03:04-0200",False)
        check_equal("2000-01-02T02:03:04-0100","2000-01-02T01:03:04-0200",True)
        check_greater("2000-01-02T04:04:05-0100","2000-01-02T03:04:05-0100",True)
        check_greater("2000-01-02T03:04:05-0200","2000-01-02T03:04:05-0100",True)
        check_greater("2009-11-17T00:33:30.9375Z","2009-11-17T00:33:30Z",True)
        check_equal("2009-11-17T00:33:30.9375Z","2009-11-17T00:33:30Z",False)
        check_equal("2009-11-17T00:33:30.0000Z","2009-11-17T00:33:30Z",True)
        print("Testing byte_run overlap engine:")
        db = extentdb()
        a = byte_run(img_offset=0,len=5)
        db.add(a)
        b = byte_run(5,5)
        db.add(b)
        assert db.intersects(byte_run(0,5))==byte_run(0,5)
        assert db.intersects(byte_run(0,1))
        assert db.intersects(byte_run(2,3))
        assert db.intersects(byte_run(4,1))
        assert db.intersects(byte_run(5,1))
        assert db.intersects(byte_run(6,1))
        assert db.intersects(byte_run(9,1))
        assert db.intersects(byte_run(-1,5))
        assert db.intersects(byte_run(-1,10))
        assert db.intersects(byte_run(-1,11))
        assert db.intersects(byte_run(-1,1))==None
        assert db.intersects(byte_run(10,1))==None
        print("Overlap engine good!")

