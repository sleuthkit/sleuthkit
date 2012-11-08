#
# filesdb
# a module that holds a database of DFXML files
#

import dfxml
from collections import defaultdict
import sys
class filesdb:
    def __init__(self,fname=None):
        self.sha1db   = defaultdict(list) # fi's by hashdb
        self.md5db    = defaultdict(list) # fi's by hashdb
        self.fnamedb  = defaultdict(list) # fi's by fname
        self.dirs     = defaultdict(list) # fi's by directory name
        self.fis      = []  
        self.prefix   = None
        self.delfix   = None
        if fname:
            self.read(fname)
    
    def __iter__(self):
        """The iterator for filesdb iterates through all the files"""
        return self.fis.__iter__()

    def read(self,f):
        if type(f)==str:
            self.fname = f
            f = open(f,'rb')
        dfxml.read_dfxml(xmlfile=f,callback=self.pass1)

    def read_with_prefix(self,fname):
        if ':' in fname:
            (fmt,fname) = fname.split(':')
            if fmt[0]=='+': self.prefix = fmt[1:]
            if fmt[0]=='=': self.delfix = fmt[1:]
            if fmt[0]!='+' and fmt[0]!='=': self.prefix = fmt
        self.read(fname)

    def pass1(self,fi):
        """First pass for reading fi objects"""
        import os
        self.fis.append(fi)
        if fi.sha1(): self.sha1db[fi.sha1()].append(fi)
        if fi.md5(): self.md5db[fi.md5()].append(fi)
        if fi.filename():
            fname = fi.filename()
            if self.delfix:
                if fname.startswith(self.delfix): fname = fname[len(self.delfix):]
            if self.prefix:
                fname = self.prefix + fname
            self.sha1db[fname].append(fi)
            self.dirs[os.path.dirname(fname)].append(fi)
        
    def print_stats(self,f=sys.stdout):
        """Returns a text string of the stats"""
        ret = [
            ['Total directories',len(self.dirs)],
            ['Total files',len(self.fis)],
            ['Total bytes',sum([int(fi.filesize()) for fi in self.fis])],
            ['Total sha1s',len(self.sha1db)],
            ['Total md5s',len(self.md5db)],
            ]
        print("\n".join(["{:20}: {:14,}".format(a[0],a[1]) for a in ret]))

        mtime_min = [fi.mtime() for fi in self.fis]
        #print('mtime=',len(mtime_min))
        #flt = list(filter(lambda a:a!=None,mtime_min))
        #print('flt=',flt,len(flt))

        #print('mtime_min=',mtime_min)
        #print(['ctime range',mtime_min])
        #exit(0)


    def del_dirs(self,targetdb):
        """Given a targetdb, provide the dirs to get there."""
        return set(self.dirs.keys()).difference(set(targetdb.dirs.keys()))
        
    def del_files(self,targetdb):
        """Given an targetdb, provide the files needed to get there."""
        return set(self.filesdb).difference(set(db.filesdb))
        
    def new_dirs(self,db):
        """Given an older db, provide the dirs that are new."""
        return set(db.dirs.keys()).difference(set(self.dirs.keys()))
        
    def search(self,mfi,hash=False,name=False):
        """Return the matching fis"""
        if hash and not name:
            return self.md5db[mfi.md5()]
        if name and not hash:
            return self.fnamedb[mfi.filename()]
        if hash and name:
            return filter(lambda fi:fi.filename()==mfi.filename(),self.md5db[mfi.md5()])
        return []

#
# test program. Reads a database and dumps it.
#
if __name__=="__main__":
    from argparse import ArgumentParser

    parser = ArgumentParser(description='Test the files database with one or more DFXML files')
    parser.add_argument('xmlfiles',help='XML files to process',nargs='+')

    args = parser.parse_args()
    db   = filesdb()
    for fn in args.xmlfiles:
        db.read(fn)
    print(db.stats())
