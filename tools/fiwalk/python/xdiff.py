#
# Report the difference between two dfxml files
#
from filesdb import filesdb
import dfxml
import sys
#
# test program. Reads a database and dumps it.
#
if __name__=="__main__":
    from argparse import ArgumentParser

    parser = ArgumentParser(description='Test the files database with one or more DFXML files')
    parser.add_argument('xmlfiles',help='XML files to process',nargs='+')

    args = parser.parse_args()
    db0   = None
    for fn in args.xmlfiles:
        db1 = filesdb()
        db1.fname = fn
        db1.read(fn)
        print("{} stats:".format(fn))
        db1.print_stats(sys.stdout)
        if db0:
            print("")
            print("Difference from {}".format(db0.fname))
        db0 = db1


