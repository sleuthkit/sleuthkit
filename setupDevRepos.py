# Copyright (c) 2017 Basis Technology.
#
# This software is distributed under the Common Public License 1.0
#
# This script makes the repositories needed to compile The Sleuth Kit and its dependencies.
# To use it, first define the needed environment variables (such as LIBEWF_HOME).  This script
# will then clone the git repositories into those locations.

import os
import subprocess
import ntpath
import sys


def makeRepos(path):
    ''' creates the needed repositories '''
    
    # Clone zlib
    git_zlib_repository_url="https://github.com/madler/"
    zlib_path = os.path.normpath(os.path.join(path["libewf_64bit"],"zlib"))
    if not os.path.exists(zlib_path):
        gitClone(git_zlib_repository_url,"zlib",path["libewf_64bit"])
        
    # Clone the others
    git_repository_url = "https://github.com/sleuthkit/"
    for library,base_library_path in path.items():
        library_path = os.path.normpath(os.path.join(base_library_path , library))
        if not os.path.exists(library_path):
            gitClone(git_repository_url, library, base_library_path)

            
def gitClone(URL, repo, path):
    # This method will clone the library if it does not exist
    cmd = ["git", "clone", URL + repo + ".git" ]
    print("Cloning " + repo + " into " + path)
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
        base_Library_path["libewf_64bit"] = ntpath.dirname(libewf_home)
    else:
        print('Please set the env variable LIBEWF_HOME')
        sys.exit(1)

    if(libvhdi_home != None):
        base_Library_path["libvhdi_64bit"] = ntpath.dirname(libvhdi_home)
    else:
        print('Please set the env variable LIBVHDI_HOME')
        sys.exit(1)
        
    if(libvmdk_home != None):
        base_Library_path["libvmdk_64bit"] = ntpath.dirname(ntpath.dirname(libvmdk_home))
    else:
        print('Please set the env variable LIBVMDK_HOME')
        sys.exit(1)

    makeRepos(base_Library_path);

if __name__ == '__main__':
    main()
