#!/usr/bin/env python
#
# load the database

import sys,os,re,getopt
sys.path.append(os.getenv("HOME")+"/slg/src/python")

file_trace_dir = '/mnt/data0/walk/'

import MySQLdb,_mysql_exceptions
import time
import sets

from datetime import date,datetime
from time import mktime
from stats import lmean
import glob

mysql = MySQLdb.connect(host='localhost',user='simsong',passwd=os.getenv("MP"),db='files')

def extname(fname):
    if "." not in fname: return None
    ext = fname[fname.rfind('.')+1:].lower()
    if ext=="jpg": ext="jpeg"
    if ext=="htm": ext="html"
    if ext=='temp': ext='tmp'
    if(len(ext)>5): return None
    return ext

def remake_schema():
    c = mysql.cursor()

    c.execute("drop table if exists files")
    c.execute("""create table files (
    fileid int not null auto_increment,
    driveid int not null,
    filename text(65536),
    ext varchar(16),
    inset int(1) default 0,
    ctime int,
    mtime int,
    atime int,
    fragments int,
    md5 varchar(32),
    size bigint,
    Status varchar(32),
    fstype int,
    blocksize int,
    primary key (fileid),
    key (driveid),
    key (ext(16)),
    key (fragments),
    key (fstype));""")

    c.execute("drop table if exists fragments")
    c.execute("""create table fragments (
    fragmentid int not null auto_increment,
    driveid int not null,
    fileid int not null,
    start bigint,
    len bigint,
    primary key (fragmentid),
    key (driveid),
    key (fileid));""")

    c.execute("drop table if exists drives")
    c.execute("""create table drives (
    driveid int not null,
    files int,
    fragmented int,
    fragmentation float,
    fstype int,
    primary key (driveid));""")


def process(c,driveid,parts):
    if 'Partition Offset' in parts: return
    if 'Imagefile' in parts: return
    if 'Partition' in parts: return
    if len(parts)==0: return
    run_multiplier = 1

    runs = None
    tfn = ""
    if 'Filename' in parts:
        tfn = parts['Filename']
        del parts['Filename']
        ext = extname(tfn)
        if ext: parts['ext'] = ext

    cmd = "insert into files (driveid,filename"
    val = ") values (%s,%s"
    values = [driveid,tfn]
    for (k,v) in parts.iteritems():
        if k=='Sector runs' or k=='Block runs':
            runs = v.replace("-",":")
            run_multiplier = parts['blocksize']
            continue
	if k=='Alloc Status': continue
        if k=='Fragmentation': continue
        if k=='Orphan': continue        # orphans don't have file name
        if k=='Byte runs':
            runs = v
            continue
        if k=="Status":
            v = v.replace("UNLINK","")
            v = v.replace("LINK","")
            while "  " in v:
                v = v.replace("  "," ")
        cmd += "," + k
        val += ",%s"
        values.append(v)
    cmd = cmd+val+")"
    try:
        c.execute(cmd,values)
        fileid = c.lastrowid
    except _mysql_exceptions.ProgrammingError:
        print "error: ",cmd,values
        sys.exit(-1)
    except TypeError:
        print "error: ",cmd,values
        sys.exit(-1)
    if runs:
        for run in runs.split(" "):
            if ":" in run:
                (start,rlen) = run.split(':')
            else:
                start = run
                rlen  = 1
            start = int(start) * run_multiplier
            rlen  = int(rlen) * run_multiplier
            c.execute("insert into fragments (driveid,fileid,start,len) values (%s,%s,%s,%s)",(driveid,fileid,start,rlen))


def getvar(line,what):
    a = line.find(what)
    if a==-1:return None
    line = line[a+len(what):]
    return int(line[:line.find(' ')])

def calculate_fragmentation(driveid):
    c = mysql.cursor()
    frag_files_per_drive = {}
    c.execute("select count(*) from files where filename>'' and fragments>1 and driveid=%s",(driveid))
    frag_files = c.fetchone()[0]
    c.execute("select count(*) from files where filename>'' and fragments>0 and driveid=%s",(driveid))
    total_files = c.fetchone()[0]
    per = 0
    if total_files>0:
        per = float(frag_files)/total_files
    c.execute("delete from drives where driveid=%s",driveid)
    if total_files>0:
        c.execute("select fstype from files where driveid=%s limit 1",(driveid))
        fstype = c.fetchone()[0]
        c.execute("insert into drives (driveid,files,fragmented,fragmentation,fstype) values (%s,%s,%s,%s,%s)",
                  (driveid,total_files,frag_files,per,fstype))
    if total_files>=5:
        c.execute("update files set inset=1 where driveid=%s",(driveid))
    else:
        c.execute("update files set inset=0 where driveid=%s",(driveid))
    print "Drive %d has %d files with filenames of which %d are fragmented" % (driveid,total_files,frag_files)


def load_file(fn):
    print fn
    import re
    got_filename = False
    fstype = 0
    blocksize = 0
    r = re.compile("([0-9]+)\.walk")
    m = r.search(fn)
    driveid = int(m.group(1))
    c = mysql.cursor()
    parts = {}
    for line in open(fn,"r"):
        line = line[:-1]               # remove the \n
        if "ftype=" in line: line=line.replace("ftype=","fstype=")
        if "block_size=" in line: line=line.replace("block_size=","blocksize=")
        if line.startswith("# Starting dent_walk"): got_filename=True
        if line[0:1]=='#': continue
        if line.startswith("Invalid argument"): continue
        if line.startswith("Error reading"): continue
        if line.startswith("General file system"): continue
        if line.startswith("Signature Value"): continue
        if line.startswith("This is typically"): continue
        if line.startswith("Filename:"): got_filename=True
        if line.startswith("Cannot determine file system type"): got_filename=True
        if line=='=EOF=\n':
            line = ""                   # more might follow
            
        if "=" in line and "fstype" in line:
            fstype = getvar(line,"fstype=")
            blocksize = getvar(line,"blocksize=")
        if(line==''):
            if fstype: parts['fstype'] = fstype
            if blocksize: parts['blocksize'] = blocksize
            process(c,driveid,parts)
            parts = {}
            continue
        pos = line.find(':')
        if pos>0:
            tag = line[0:pos].strip()
            val = line[pos+1:].strip()
            if(len(val)>0):
                if val[0]=='(':
                    val = val[1:val.find(')')]
                parts[tag] = val
    return got_filename

def has_drive(driveid):
    # See if it has the drive
    c = mysql.cursor()
    c.execute("select driveid from files where driveid=%s limit 1",driveid)
    r = c.fetchone()
    if r: return True
    return False

def has_files(driveid):
    c = mysql.cursor()
    c.execute("select count(*) from files where driveid=%s and length(filename)>0",driveid)
    r = c.fetchone()
    return r[0]>0


def load_drive(driveid):
    print "Loading driveid %d" % driveid
    # First find which files are available
    # See if there is a w4
    c = mysql.cursor()
    c.execute("delete from drives where driveid=%s",driveid)
    c.execute("delete from files where driveid=%s",driveid)
    c.execute("delete from fragments where driveid=%s",driveid)
    w4 = file_trace_dir + "w4/%04d.walk" % driveid
    w3 = file_trace_dir + "w3/%04d.walk" % driveid
    w2 = file_trace_dir + "w2/%04d.walk" % driveid
    for f in [w4,w3,w2]:
        if os.path.exists(f):
            if f==w3 or f==w3: print "**** loading ",f
            got_filename = load_file(f)
            if got_filename: break
            load_file(f)
            if has_files(driveid):
                break
    calculate_fragmentation(driveid)
    return


def load_imagesizes(fn):
    c = mysql.cursor()
    r = re.compile("(\d+)\.aff: (\d+)")
    for line in open(fn,"r"):
        m = r.search(line)
        if m:
            driveid = m.group(1)
            bytes   = m.group(2)
            c.execute("select driveid from drives where driveid=%s",driveid)
            res = c.fetchone()
            if not res:
                c.execute("insert into drives (driveid) values (%s)",driveid)
            #print "bytes=",bytes,"driveid=",driveid
            c.execute("update drives set bytes=%s where driveid=%s",(bytes,driveid))


if(__name__=="__main__"):
    from optparse import OptionParser
    start = 0
    parser = OptionParser()
    parser.add_option("-a","--all",action="store_true",
                      help="Do all (normally just do the ones that have not been added")
    parser.add_option("-r","--remake_schema",action="store_true",help="Remake the schema")
    parser.add_option("-d","--driveid",dest="driveid",type="int",help="Just use this drive")
    parser.add_option("-s","--start",dest="start",type="int",help="Start count here")
    parser.add_option("-f","--frag",action="store_true",help="Just Recaluate fragmentation")
    parser.add_option("-i","--imagesizes",dest="imagesizes",help="Load imagesizes")
    (options,args) = parser.parse_args()
    
    if options.remake_schema:
        remake_schema()
        sys.exit(0)

    if options.driveid:
        load_drive(options.driveid)
        sys.exit(0)

    if options.imagesizes:
        load_imagesizes(options.imagesizes)
        sys.exit(0)

    if options.start: start = options.start

    delay = 10
    if options.frag: print "Will just reload fragmentation table"
    print "Will start loading all drives in %d seconds..." % delay
    for i in range(0,delay):
        print "%d..." % (delay-i)
        time.sleep(1)
        
    for i in range(start,2000):
        if options.frag:
            calculate_fragmentation(i)
            continue
        if not options.all and has_drive(i):
            continue
        load_drive(i)

