#
# Using two XML files make the current system look like the master
#
from filesdb import filesdb
import dfxml
import sys
#
# test program. Reads a database and dumps it.
#
if __name__=="__main__":
    from argparse import ArgumentParser

    parser = ArgumentParser(description='Make the local system look like the master')
    parser.add_argument('--commit',help='Actually do the job',action='store_true')
    parser.add_argument('--local',help='speciies an XML file that describes the local system (required)')
    parser.add_argument('masterfiles',
                        help='XML files to process. Files may be prefixed with an [xml] path',
                        nargs='+')

    args = parser.parse_args()

    if not args.local:
        parser.print_help()
        exit(1)

    masterdb   = filesdb()
    for fn in args.masterfiles:
        masterdb.read_with_prefix(fn)
    print("Master stats:")
    masterdb.print_stats(sys.stdout)
    print("\n")
    print("Local mirror stats:")
    ldb = filesdb()
    ldb.read_with_prefix(args.local)

    # Create new directories if needed
    for newdir in ldb.new_dirs(masterdb):
        print("mkdir {}".format(newdir))
    
    keep_files = []
    mv_files   = []
    rm_files   = []
    def process_fi(fi):
        # If hash is same and name is the same, ignore:
        for nfi in masterdb.search(fi,hash=True,name=True):
            keep_files.append(fi.filename())
            return              # in the database
        
        # If hash is same and name is different, move it
        for nfi in masterdb.search(fi,hash=True):
            mv_files.append((fi.filename(),nfi.filename()))
            return
        
        # If name is same and hash is different, erase it
        for nfi in masterdb.search(fi,name=True):
            rm_files.append(fi.filename())
            return

        # Otherwise, erase the hash
        rm_files.append(fi.filename())
        return

    # Rename files that need to be renamed
    for fi in ldb:
        process_fi(fi)

    print("Files to keep: {:12,}".format(len(keep_files)))
    print("Files to rm:   {:12,}".format(len(rm_files)))
    print("Files to mv:   {:12,}".format(len(mv_files)))
    
