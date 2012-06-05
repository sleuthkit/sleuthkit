#!/usr/bin/env python
"""idifference.

Generates a report about what's different between two disk images.

Process:

1. A map is kept of all filenames->sha1 codes and all sha1->filenames.
2. For each image, read all of the fileobject objects:
    - create new maps
    - Note when things change.
    - Delete each file in the old map as it is processed.
3. Report files left in map; that's the files that were deleted!
4. Replace the old maps with the new maps
"""

import sys,fiwalk,dfxml,time
if sys.version_info < (3,1):
    raise RuntimeError("idifference.py now requires Python 3.1 or above")

def ignore_filename(fn, include_dotdirs=False):
    """
    Ignores particular file name patterns output by TSK.  Detecting new
    and renamed files becomes difficult if there are 3+ names for an
    inode (i.e. "dir", "dir/.", and "dir/child/..").
    """
    return (not include_dotdirs and (fn.endswith("/.") or fn.endswith("/.."))) or fn in set(['$FAT1','$FAT2'])    

def ptime(t):
    """Print the time in the requested format. T is a dfxml time value.  If T is null, return 'null'."""
    global options
    if t is None:
        return "null"
    if options.timestamp:
        return str(t.timestamp())
    else:
        return str(t.iso8601())

def dprint(x):
    global options
    if options.debug: print(x)

def header():
    if options.html:
        print("""<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN http://www.w3.org/TR/html4/loose.dtd">
<html>
<body>
<style>
body  { font-family: Sans-serif;}
.sha1 { font-family: monospace; font-size: small;}
.filesize { padding-left: 15px; padding-right: 15px; text-align: right;}
</style>
""")

def h1(title):
    global options
    if options.html:
        print("<h1>%s</h1>" % title)
        return
    print("\n\n%s\n" % title)

def h2(title):
    global options
    if options.html:
        print("<h2>%s</h2>" % title)
        return
    print("\n\n%s\n%s" % (title,"="*len(title)))


def table(rows,styles=None,break_on_change=False):
    import sys
    global options
    def alldigits(x):
        if type(x)!=str: return False
        for ch in x:
            if ch.isdigit()==False: return False
        return True

    def fmt(x):
        if x==None: return ""
        if type(x)==int or alldigits(x):
            return "{0:>12}".format(x)
        return str(x)
            
    if options.html:
        print("<table>")
        for row in rows:
            print("<tr>")
            if not styles:
                styles = [""]*len(rows)
            for (col,style) in zip(row,styles):
                sys.stdout.write("<td class='%s'>%s</td>" % (style,col))
            print("<tr>")
        print("</table>")
        return
    lastRowCol0 = None
    for row in rows:
        # Insert a blank line if this row[0] is not the same as last row[0]
        if row[0]!=lastRowCol0 and break_on_change:
            sys.stdout.write("\n")
            lastRowCol0 = row[0]
        # Write the row.
        # This won't generate a unicode encoding error because the strings are valid unicode.
        sys.stdout.write("\t".join([fmt(col) for col in row]))
        sys.stdout.write("\n")

#
# This program keeps track of the current and previous diskstate in a single
# object called "DiskState". Another way to do that would have been to have
# the instance built from the XML file and then have another function that compares
# them.
#        

class DiskState:
    global options

    def __init__(self,notimeline=False,summary=False,include_dotdirs=False):
        self.new_fnames = dict() # maps from fname -> fi
        self.new_inodes = dict() # maps from inode_number -> fi
        self.new_fi_tally = 0
        self.notimeline = notimeline
        self.summary = summary
        self.include_dotdirs = include_dotdirs
        self.next()
        
    def next(self):
        """Called when the next image is processed."""
        global options
        self.fnames = self.new_fnames
        self.inodes = self.new_inodes
        self.fi_tally = self.new_fi_tally
        self.new_fnames = dict()
        self.new_inodes = dict()
        self.new_files          = set()     # set of file objects
        self.renamed_files      = set()     # set of (oldfile,newfile) file objects
        self.changed_content    = set()     # set of (oldfile,newfile) file objects
        self.changed_properties = set()     # list of (oldfile,newfile) file objects
        if self.notimeline:
            self.timeline = None
        else:
            self.timeline = set()

    def process_fi(self,fi):
        global options
        dprint("processing %s" % str(fi))
        
        # See if the filename changed its hash code
        changed = False
        if not fi.allocated():
            return # only look at allocated files

        # Filter out specific filenames create by TSK that are not of use
        if ignore_filename(fi.filename(), self.include_dotdirs):
            return 

        # Remember the file for the next generation
        self.new_fnames[fi.filename()] = fi
        self.new_inodes[fi.partition() + "/" + fi.inode()] = fi
        self.new_fi_tally += 1

        # See if this filename changed or was resized
        ofi = self.fnames.get(fi.filename(),None)
        if ofi:
            dprint("   found ofi")
            if ofi.sha1()!=fi.sha1():
                dprint("      >>> sha1 changed")
                self.changed_content.add((ofi,fi))
            elif ofi.atime() != fi.atime() or \
                    ofi.mtime() != fi.mtime() or \
                    ofi.crtime() != fi.crtime() or \
                    ofi.ctime() != fi.ctime():
                dprint("      >>> time changed")
                self.changed_properties.add((ofi,fi))

        # If a new file, note that (and optionally add to the timeline)
        if not ofi:
            self.new_files.add(fi)
            if self.timeline:
                create_time = fi.crtime()
                if not create_time: create_time = fi.ctime()
                if not create_time: create_time = fi.mtime()
                self.timeline.add((create_time,fi.filename(),"created"))

        # Delete files we have seen (so we can find out the files that were deleted)
        if fi.filename() in self.fnames:
            del self.fnames[fi.filename()]

        # Look for files that were renamed
        ofi = self.inodes.get(fi.partition() + "/" + fi.inode(),None)
        if ofi and ofi.filename() != fi.filename() and ofi.sha1()==fi.sha1():
            #Never consider current-directory or parent-directory for rename operations.  Because we match on partition+inode numbers, these trivially match.
            if not (fi.filename().endswith("/.") or fi.filename().endswith("/..") or ofi.filename().endswith("/.") or ofi.filename().endswith("/..")):
                self.renamed_files.add((ofi,fi))

    def process(self,fname):
        self.current_fname = fname
        if fname.endswith(".xml"):
            fiwalk.fiwalk_using_sax(xmlfile=open(infile,'rb'), flags=fiwalk.ALLOC_ONLY, callback=self.process_fi)
        else:
            fiwalk.fiwalk_using_sax(imagefile=open(infile,'rb'), flags=fiwalk.ALLOC_ONLY, callback=self.process_fi)

    def print_fis(self,title,fis):
        h2(title)
        def fidate(fi):
            try:
                return str(ptime(fi.mtime()))
            except TypeError:
                return "n/a"
        res = [(fidate(fi),str(fi.filesize()),fi.filename()) for fi in fis]
        if res:
            table(sorted(res))

    def print_fi2(self,title,fi2s):
        def prtime(t):
            return "%d (%s)" % (t,ptime(t))

        h2(title)
        res = set()
        for(ofi,fi) in fi2s:
            if ofi.filename() != fi.filename():
                res.add((ofi.filename(),"renamed to",fi.filename()))
                # Don't know when it was renamed
            if ofi.filesize() != fi.filesize():
                res.add((ofi.filename(),"resized",ofi.filesize(),"->",fi.filesize()))
                if self.timeline: self.timeline.add((fi.mtime(),fi.filename(),"resized",ofi.filesize(),"->",fi.filesize()))
            if ofi.sha1() != fi.sha1():
                res.add((ofi.filename(),"SHA1 changed",ofi.sha1(),"->",fi.sha1()))
                if self.timeline: self.timeline.add((fi.mtime(),fi.filename(),"SHA1 changed",ofi.sha1(),"->",fi.sha1()))
            if ofi.atime() != fi.atime():
                res.add((ofi.filename(),"atime changed",ptime(ofi.atime()),"->",ptime(fi.atime())))
                if self.timeline: self.timeline.add((fi.atime(),fi.filename(),"atime changed",prtime(ofi.atime()),"->",prtime(fi.atime())))
            if ofi.mtime() != fi.mtime():
                res.add((ofi.filename(),"mtime changed",ptime(ofi.mtime()),"->",ptime(fi.mtime())))
                if self.timeline: self.timeline.add((fi.mtime(),fi.filename(),"mtime changed",prtime(ofi.mtime()),"->",prtime(fi.mtime())))
            if ofi.ctime() != fi.ctime():
                res.add((ofi.filename(),"ctime changed",ptime(ofi.ctime()),"->",ptime(fi.ctime())))
                if self.timeline: self.timeline.add((fi.ctime(),fi.filename(),"ctime changed",prtime(ofi.ctime()),"->",prtime(fi.ctime())))
            if ofi.crtime() != fi.crtime():
                res.add((ofi.filename(),"crtime changed",ptime(ofi.crtime()),"->",ptime(fi.crtime())))
                if self.timeline: self.timeline.add((fi.crtime(),fi.filename(),"crtime changed",prtime(ofi.crtime()),"->",prtime(fi.crtime())))
        if res:
            table(sorted(res),break_on_change=True)

    def print_timeline(self):
        prt = []

        # Make the dates printable
        for line in sorted(self.timeline):
            prt.append([ptime(line[0])]+list(line[1:]))
        h2("Timeline")
        table(prt)

    def report(self):
        header()
        h1("Disk image:"+self.current_fname)
        self.print_fis("New Files:",self.new_files)
        self.print_fis("Deleted Files:",self.fnames.values())
        self.print_fi2("Renamed Files:",self.renamed_files)
        self.print_fi2("Files with modified content:",self.changed_content)
        self.print_fi2("Files with changed file properties:",self.changed_properties)
        if self.summary:
            h2("Summary:")
            table([
              ("Prior image's file (file object) tally", str(self.fi_tally)),
              ("Prior image's file (inode) tally", str(len(self.inodes))),
              ("Current image's file (file object) tally", str(self.new_fi_tally)),
              ("Current image's file (inode) tally", str(len(self.new_inodes))),
              ("New files", str(len(self.new_files))),
              ("Deleted files", str(len(self.fnames))),
              ("Renamed files", str(len(self.renamed_files))),
              ("Files with modified content", str(len(self.changed_content))),
              ("Files with changed file properties", str(len(self.changed_properties)))
            ])

        if self.timeline: self.print_timeline()

    def output_archive(self,imagefile=None,tarname=None,zipname=None):
        """Write the changed and/or new files to a tarfile or a ZIP file. """
        import zipfile, tarfile, StringIO, datetime

        tfile = None
        zfile = None

        to_archive = self.new_files.copy()
        to_archive = to_archive.union(set([val[1] for val in self.changed_content]))
        to_archive = to_archive.union(set([val[1] for val in self.changed_properties]))

        # Make sure we are just writing out inodes that have file contents
        to_archive = filter(
            lambda fi:fi.allocated() and fi.has_tag("inode") and fi.has_contents()
            and (fi.name_type()=='' or fi.name_type()=='r'),
            to_archive)

        if len(to_archive)==0:
            print("No archive created, as no allocated files created or modified")
            return

        if tarname:
            print(">>> Creating tar file: %s" % tarname)
            tfile = tarfile.TarFile(tarname,mode="w")

        if zipname:
            print(">>> Creating zip file: %s" % zipname)
            zfile = zipfile.ZipFile(zipname,mode="w",allowZip64=True)

        files_written=set()
        content_error_log = []
        for fi in to_archive:
            filename = fi.filename()
            fncount = 1
            while filename in files_written:
                filename = "%s.%d" % (fi.filename(),fnperm)
                fncount+= 1
            contents = None
            try:
                contents = fi.contents(imagefile)
            except ValueError as ve:
                if ve.message.startswith("icat error"):
                    #Some files cannot be recovered, even from images that do not seem corrupted; log the icat command that failed.
                    content_error_log.append(ve.message)
                else:
                    #This is a more interesting error, so have process die to report immediately.
                    raise
            if contents:
                if tfile:
                    info = tarfile.TarInfo(name=filename)
                    info.mtime = fi.mtime()
                    info.atime = fi.atime()
                    info.ctime = fi.ctime()
                    info.uid   = fi.uid()
                    info.gid   = fi.gid()
                    info.size  = fi.filesize()
                    # addfile requires a 'file', so let's make one
                    string = StringIO.StringIO()
                    string.write(contents)
                    string.seek(0)
                    tfile.addfile(tarinfo=info,fileobj=string)
                if zfile:
                    mtimestamp = fi.mtime().timestamp()
                    info = zipfile.ZipInfo(filename)
                    if mtimestamp:
                        #mtime might be null
                        info.date_time = datetime.datetime.fromtimestamp(mtimestamp).utctimetuple()
                    info.internal_attr = 1
                    info.external_attr = 2175008768 # specifies mode 0644
                    zfile.writestr(info,contents)
        if tfile: tfile.close()
        if zfile: zfile.close()
        if len(content_error_log) > 0:
            sys.stderr.write("Errors retrieving file contents:\n")
            sys.stderr.write("\n".join(content_error_log))
            sys.stderr.write("\n")

if __name__=="__main__":
    from optparse import OptionParser
    from copy import deepcopy
    global options

    parser = OptionParser()
    parser.usage = '%prog [options] file1 file2 [file3...]  (files can be xml or image files)'
    parser.add_option("-x","--xml",help="specify output file for XML",dest="xmlfilename")
    parser.add_option("--html",help="specify output in HTML",action="store_true")
    parser.add_option("-n","--notimeline",help="do not generate a timeline",action="store_true")
    parser.add_option("-d","--debug",help="debug",action='store_true')
    parser.add_option("-T","--tararchive",help="create tar archive file of new/changed files",dest="tarfile")
    parser.add_option("-Z","--zipfile",help="create ZIP64 archive file of new/changed files",dest="zipfile")
    parser.add_option("--include-dotdirs",help="include files with names ending in '/.' and '/..'",action="store_true", dest="include_dotdirs", default=False)
    parser.add_option("--summary",help="output summary statistics of file system changes",action="store_true", default=False)
    parser.add_option("--timestamp",help="output all times in Unix timestamp format; otherwise use ISO 8601",action="store_true")
    parser.add_option("--imagefile",help="specifies imagefile or file2 is an XML file and you are archiving")

    (options,args) = parser.parse_args()

    if len(args)<1:
        parser.print_help()
        sys.exit(1)

    if (options.tarfile or options.zipfile) and args[1].endswith(".xml") and not options.imagefile:
        print("ERROR: %s is NOT an XML file and no imagefile specified" % args[1])
        parser.print_help()
        exit(1)

    s = DiskState(notimeline=options.notimeline, summary=options.summary, include_dotdirs=options.include_dotdirs)
    for infile in args:
        print(">>> Reading %s" % infile)
        s.process(infile)
        if infile!=args[0]:
            # Not the first file. Report and optionally archive
            if options.tarfile or options.zipfile:
                imagefilename = infile
                if imagefilename.endswith(".xml"):
                    imagefilename = options.imagefile
                s.output_archive(imagefile=open(imagefilename),tarname=options.tarfile,zipname=options.zipfile)
            s.report()
        s.next()
