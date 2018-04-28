# Copyright (c) 2017 Basis Technology.
#
# This software is distributed under the Common Public License 1.0
#
# This script makes the repositories needed to compile The Sleuth Kit and its dependencies.
# To use it, first define the needed environment variables (such as LIBEWF_HOME).  This script
# will then clone the git repositories into those locations.

import os
import subprocess
import sys


def setupLibrary(path):
    ''' sets up the library path variable '''
    git_repository_url = "https://github.com/sleuthkit/"
    git_zlib_repository_url="https://github.com/madler/"
    zlib_path = os.path.normpath(os.path.join(path["libewf_64bit"],"zlib"))
    if not os.path.exists(zlib_path):
        gitClone(git_zlib_repository_url,"zlib",path["libewf_64bit"])
    for library,base_library_path in path.items():
        library_path = os.path.normpath(os.path.join(base_library_path , library))
        if not os.path.exists(library_path):
            gitClone(git_repository_url, library, base_library_path)

def gitClone(URL, repo, path):
    # This method will clone the library if it does not exist
    cmd = ["git", "clone", URL + repo + ".git" ]
    ret = subprocess.call(cmd, stdout=sys.stdout, cwd=path)
    if ret != 0:
        sys.exit(1)


def main():
    #setting the base directory with the help of library env variables.
    libewf_home = os.getenv("LIBEWF_HOME")
    libvhdi_home = os.getenv("LIBVHDI_HOME")
    libvmdk_home = os.getenv("LIBVMDK_HOME")
    base_Library_path = {}
    if(libewf_home != None):
        base_Library_path["libewf_64bit"] = os.path.dirname(libewf_home)
    else:
        print('Please set the env variable LIBEWF_HOME')
        sys.exit(1)

    if(libvhdi_home != None):
        base_Library_path["libvhdi_64bit"] = os.path.dirname(libvhdi_home)
    else:
        print('Please set the env variable LIBVHDI_HOME')
        sys.exit(1)
    if(libvmdk_home != None):
        base_Library_path["libvmdk_64bit"] = os.path.dirname(os.path.dirname(libvmdk_home))
    else:
        print('Please set the env variable LIBVMDK_HOME')
        sys.exit(1)

    setupLibrary(base_Library_path);

if __name__ == '__main__':
    main()
