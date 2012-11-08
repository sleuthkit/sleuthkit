#!/usr/bin/env python
"""rdifference.py

Generates a report about what's different between two Windows Registry hives.

Process:

1. For each regxml file, read all of the fileobject objects:
    - create new maps
    - Note when things change.
    - Delete each file in the old map as it is processed.
2. Report cells left in map; those are the cells that were deleted!
3. Replace the old maps with the new maps
"""

#AJN This script does not call out duplicate paths, but they are reported.

import sys,fiwalk,dfxml,time
if sys.version_info < (3,1):
    raise RuntimeError("rdifference.py requires Python 3.1 or above")

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
# This program keeps track of the current and previous hivestate in a single
# object called "HiveState". Another way to do that would have been to have
# the instance built from the XML file and then have another function that compares
# them.
#        

class HiveState:
    global options

    def __init__(self,notimeline=False):
        self.new_cnames = dict() # maps from cell full path -> cell
        self.notimeline = notimeline
        self.next()
        
    def next(self):
        """Called when the next image is processed."""
        global options
        self.cnames = self.new_cnames
        self.new_cnames = dict()
        self.new_files          = set()     # set of file objects
        self.renamed_files      = set()     # set of (oldfile,newfile) file objects
        self.changed_content    = set()     # set of (oldfile,newfile) file objects
        self.changed_properties = set()     # list of (oldfile,newfile) file objects
        if self.notimeline:
            self.timeline = None
        else:
            self.timeline = set()

    def process_cell(self,cell):
        global options
        dprint("processing %s" % str(cell))
        
        # See if the filename changed its hash code
        changed = False


        # Remember the file for the next generation
        self.new_cnames[cell.full_path()] = cell
        #new_inodes from idifference translates to ... well, there is no 'inode' in the Registry. There's hive identifier and full path. Values are small and thus more likely to appear in multiple places.  Skip translating

        # See if this filename changed or was resized
        ocell = self.cnames.get(cell.full_path(),None)
        if ocell:
            dprint("   found ocell")
            if ocell.sha1()!=cell.sha1():
                dprint("      >>> sha1 changed")
                self.changed_content.add((ocell,cell))
            if ocell.mtime() != cell.mtime():
                dprint("      >>> mtime changed")
                self.changed_properties.add((ocell,cell))

        # If a new file, note that (and optionally add to the timeline)
        if not ocell:
            self.new_files.add(cell)
            if self.timeline:
                modify_time = cell.mtime()
                self.timeline.add((modify_time,cell.full_path(),"modified"))

        # Delete files we have seen (so we can find out the files that were deleted)
        if cell.full_path() in self.cnames:
            del self.cnames[cell.full_path()]

    def process(self,fname):
        self.current_fname = fname
        if fname.endswith(".regxml"):
            reader = dfxml.read_regxml(xmlfile=open(infile,'rb'), callback=self.process_cell)

    def print_cells(self,title,cells):
        h2(title)
        def cdate(cell):
            try:
                return str(ptime(cell.mtime()))
            except TypeError:
                return "n/a"
        res = [(cdate(cell),cell.full_path()) for cell in cells]
        if res:
            table(sorted(res))

    def print_cell2(self,title,cell2s):
        def prtime(t):
            return "%d (%s)" % (t,ptime(t))

        h2(title)
        res = set()
        for(ocell,cell) in cell2s:
            if ocell.sha1() != cell.sha1():
                res.add((ocell.full_path(),"SHA1 changed",ocell.sha1(),"->",cell.sha1()))
                if self.timeline: self.timeline.add((cell.mtime(),cell.full_path(),"SHA1 changed",ocell.sha1(),"->",cell.sha1()))
            if ocell.mtime() != cell.mtime():
                res.add((ocell.full_path(),"mtime changed",ptime(ocell.mtime()),"->",ptime(cell.mtime())))
                if self.timeline: self.timeline.add((cell.mtime(),cell.full_path(),"mtime changed",prtime(ocell.mtime()),"->",prtime(cell.mtime())))
            if ocell.type != cell.type:
                res.add((ocell.full_path(),"cell type changed",ocell.type,"->",cell.type))
                if self.timeline: self.timeline.add((cell.mtime(),cell.full_path(),"cell type changed",prtime(ocell.mtime()),"->",prtime(cell.mtime())))

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
        h1("RegXML file:"+self.current_fname)
        self.print_cells("New Files:",self.new_files)
        self.print_cells("Deleted Files:",self.cnames.values())
        self.print_cell2("Files with modified content:",self.changed_content)
        self.print_cell2("Files with changed file properties:",self.changed_properties)
        if self.timeline: self.print_timeline()

    def output_archive(self,tarname=None,zipname=None):
        """Write the changed and/or new files to a tarfile or a ZIP file. """
        import zipfile, tarfile, StringIO, datetime

        tfile = None
        zfile = None

        to_archive = self.new_files.copy()
        to_archive = to_archive.union(set([val[1] for val in self.changed_content]))
        to_archive = to_archive.union(set([val[1] for val in self.changed_properties]))

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
    parser.add_option("--timestamp",help="output all times in Unix timestamp format; otherwise use ISO 8601",action="store_true")

    (options,args) = parser.parse_args()

    if len(args)<1:
        parser.print_help()
        sys.exit(1)

    s = HiveState(notimeline=options.notimeline)
    for infile in args:
        print(">>> Reading %s" % infile)
        s.process(infile)
        if infile!=args[0]:
            # Not the first file. Report and optionally archive
            if options.tarfile or options.zipfile:
                s.output_archive(tarname=options.tarfile,zipname=options.zipfile)
            s.report()
        s.next()
