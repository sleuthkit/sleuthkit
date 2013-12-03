from __future__ import with_statement

import os
from optparse import OptionParser
                 
"""
Creates a Doxygen page that displays the contents of a file.
"""
if __name__ == "__main__":
    parser = OptionParser(usage = 'usage: %prog <src_file_path> <output_dir> <page_name> <page_title>')
    (options, args) = parser.parse_args()
    if len(args) != 4:
        parser.error("incorrect number of arguments")

    with open(args[0], 'r') as srcFile:
        srcFileContents = srcFile.read()
        
    (fileName, fileExt) = os.path.splitext(args[0])
        
    with open(os.path.join(args[1], args[2] + '.dox'), 'w') as doxFile:
        doxFile.write('/*! \\page ' + args[2] + '_page ' + args[3] + '\n\n')
        if fileExt is None:
            doxFile.write('\\code\n\n')
        else:
            doxFile.write('\\code{' + fileExt + '}\n\n')
        doxFile.write(srcFileContents)
        doxFile.write('\n\n\\endcode\n\n*/')

