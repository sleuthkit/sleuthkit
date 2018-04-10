# Copyright (c) 2017 Basis Technology.
#
# This software is distributed under the Common Public License 1.0
#This script makes the repositories needed to compile The Sleuth Kit and its dependencies."

import os
import subprocess
import sys


def setupLibrary(path):
    ''' sets up the library path variable '''
    git_repository_url = "https://github.com/sleuthkit/"
    git_zlib_repository_url="https://github.com/madler/"
    gitClone(git_zlib_repository_url,"zlib",path)
    libraries = ["libvhdi_64bit", "libvmdk_64bit", "libewf_64bit"]
    for library in libraries:
        library_path = os.path.normpath(path + library)
        if not os.path.exists(library_path):
            gitClone(git_repository_url, library, path)

def gitClone(URL, repo, path):

    cmd = ["git", "clone", URL + repo + ".git" ]
    ret = subprocess.call(cmd, stdout=sys.stdout, cwd=path)
    if ret != 0:
        sys.exit(1)


def usage():
    ''' Print out how to use the script '''

    print('Usage: python3 setupLibs.py [library directory]')
    sys.stdout.flush()
    sys.exit(1)

def main():

    libhome = os.getenv("LIBEWF_HOME"); #setting the base directory as current directory if no argument is passed
    if(libhome == None):
        base_Library_path = os.path.dirname(libHome);

    if len(sys.argv) == 2:
        base_Library_path = sys.argv[1]
    elif len(sys.argv) > 2:
        print('Wrong arguments.')
        usage()
    if not os.path.exists(base_Library_path):
        print("Please give a valid path")
        sys.stdout.flush()
        sys.exit(1)

    setupLibrary(base_Library_path);

if __name__ == '__main__':
    main()
