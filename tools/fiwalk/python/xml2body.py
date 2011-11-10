#!/usr/bin/env python

"""xml2body.py

Generate a Sluethkit 'body' file from fiwalk XML files.


Dave Dittrich <dittrich@u.washington.edu>

"""
import sys,time
import fiwalk,dfxml,idifference

# We are re-using code from idifference.py and over-riding
# the process_fi method in the DiskState class.
from idifference import DiskState

def dprint(x):
    global options
    if options.debug: print(x)

import stat
def is_suid(mode):  return(mode & stat.S_ISUID == stat.S_ISUID)
def is_sgid(mode):  return(mode & stat.S_ISGID == stat.S_ISGID)
def is_svtx(mode):  return(mode & stat.S_ISVTX == stat.S_ISVTX)
def is_read(mode):  return(mode & stat.S_IREAD == stat.S_IREAD)
def is_write(mode): return(mode & stat.S_IWRITE == stat.S_IWRITE)
def is_exec(mode):  return(mode & stat.S_IEXEC == stat.S_IEXEC)
def is_rwxu(mode):  return(mode & stat.S_IRWXU == stat.S_IRWXU)
def is_rusr(mode):  return(mode & stat.S_IRUSR == stat.S_IRUSR)
def is_wusr(mode):  return(mode & stat.S_IWUSR == stat.S_IWUSR)
def is_xusr(mode):  return(mode & stat.S_IXUSR == stat.S_IXUSR)
def is_rwxg(mode):  return(mode & stat.S_IRWXG == stat.S_IRWXG)
def is_rgrp(mode):  return(mode & stat.S_IRGRP == stat.S_IRGRP)
def is_wgrp(mode):  return(mode & stat.S_IWGRP == stat.S_IWGRP)
def is_xgrp(mode):  return(mode & stat.S_IXGRP == stat.S_IXGRP)
def is_rwxo(mode):  return(mode & stat.S_IRWXO == stat.S_IRWXO)
def is_roth(mode):  return(mode & stat.S_IROTH == stat.S_IROTH)
def is_woth(mode):  return(mode & stat.S_IWOTH == stat.S_IWOTH)
def is_xoth(mode):  return(mode & stat.S_IXOTH == stat.S_IXOTH)

# Rather than convert every single permission mode, cache
# each one after generating and re-use it next time.
_modecache = dict()

def make_perms(mode):
    omode = "%o" % mode
    try:
        return _modecache[omode]
    except: pass

    buf = list("---------")
    
    # user perms
    if is_rusr(mode):
        buf[0] = 'r'
    if is_wusr(mode):
        buf[1] = 'w'
    if is_suid(mode):
        if is_xusr(mode):
            buf[2] = 's'
        else:
            buf[2] = 'S'
    elif is_xusr(mode):
        buf[2] = 'x'

    # group perms
    if is_rgrp(mode):
        buf[3] = 'r'
    if is_wgrp(mode):
        buf[4] = 'w'
    # set gid
    if is_sgid(mode):
        if is_xgrp(mode):
            buf[5] = 's'
        else:
            buf[5] = 'S'
    elif is_xgrp(mode):
        buf[5] = 'x'

    # other perms
    if is_roth(mode):
        buf[6] = 'r'
    if is_woth(mode):
        buf[7] = 'w'

    # sticky bit
    if is_svtx(mode):
        if is_xoth(mode):
            buf[8] = 't'
        else:
            buf[8] = 'T'
    elif is_xoth(mode):
        buf[8] = 'x'
    perms= "".join([i for i in buf])
    _modecache[omode] = perms
    return perms



def process_fi(self,fi):
    global options
    dprint("processing %s" % str(fi))
    # Is this a directory, or a file of some type?
    if fi.meta_type() == 2:
      itype = "d"
    else:
      itype = "-"
    # Concatenate inode meta_type and permissions in human-readable form.
    perms = itype + make_perms(fi.mode())
    print "%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s" % (
         fi.md5(),
         fi.filename(),
         fi.inode(),
         perms,
         fi.uid(),
         fi.gid(),
         fi.filesize(),
         fi.atime(),
         fi.mtime(),
         fi.ctime(),
         fi.crtime())

DiskState.process_fi = process_fi

if __name__=="__main__":
    from optparse import OptionParser
    from copy import deepcopy
    global options

    parser = OptionParser()
    parser.usage = '%prog [options] file1 file2 [file3...]  (files can be xml or image files)'
    parser.add_option("-d","--debug",help="debug",action='store_true')

    (options,args) = parser.parse_args()

    if len(args)<1:
        parser.print_help()
        sys.exit(1)

    s = DiskState()
    for infile in args:
        dprint(">>> Reading %s" % infile)
        s.process(infile)
