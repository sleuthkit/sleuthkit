#!/usr/bin/env python
"""
Test script. Evaluates idifference.py on a sequence of disk images.
"""

import sys, os, subprocess

if __name__ == "__main__":
    from optparse import OptionParser

    parser = OptionParser()
    parser.usage = '%prog [options] dfxml_sequence_list.txt output_zip'
    #parser.add_option("-z", "--zap", help="Zap output directory (erases if present)" dest="zap")
    parser.add_option("-p", "--prefix", help="prepend prefix to every test image path", dest="prefix")
    parser.add_option("-v", "--verbose", help="verbose output: print call to difference program", dest="verbose", action="store_true")
    parser.add_option("-d", "--diff-program", help="use this path to the diff program", dest="diff_program")

    (options,args) = parser.parse_args()
    if len(args) < 2:
        parser.print_help()
        sys.exit(1)

    prefix = ""
    if options.prefix:
        prefix = options.prefix
    #Convert file contents to list
    files = [prefix + x.strip() for x in open(args[0],"r")]

    #Verify we'll run at least one difference
    if len(files) < 2:
        sys.stderr.write("Differencing requires 2 or more files.\n")

    #Check that the list lines actually point to files
    for f in files:
        assert os.path.isfile(f)

    #Run differences
    if options.diff_program:
        diff_program = options.diff_program
    else:
        diff_program = os.path.dirname(sys.argv[0]) + "/idifference.py"
    
    diff_command = ["python", diff_program, "--zipfile=" + args[1], "--imagefile"] + files
    if options.verbose:
        print(" ".join(diff_command))
    subprocess.call(diff_command)