# Copyright (c) 2017 Basis Technology.
#
# This software is distributed under the Common Public License 1.0
#
# Gets TSK dependencies from Nuget and compiles the current branch

import codecs
import datetime
import logging
import os
import os.path
import re
import shutil
import subprocess
import sys
import getopt
from sys import platform as _platform

import time
import traceback

MSBUILD_LOCATIONS = [r'C:/Program Files (x86)/Microsoft Visual Studio/2019/Community/MSBuild/Current/Bin',
                     r'C:/Program Files (x86)/Microsoft Visual Studio/2022/Enterprise/MSBuild/Current/Bin',
                     r'/cygdrive/c/Program Files (x86)/MSBuild/14.0/Bin/']

MSBUILD = 'MSBuild.exe'

CURRENT_PATH = os.getcwd()
# save the build log in the output directory
LOG_PATH = os.path.join(CURRENT_PATH, 'output', time.strftime("%Y.%m.%d-%H.%M.%S"))
MINIMAL = False

def find_msbuild():
    # First try using shutil to search the patn
    msbuild_path = shutil.which(MSBUILD)
    if msbuild_path:
        return msbuild_path

    # Use our hard-coded locations
    for loc in MSBUILD_LOCATIONS:
        print("Checking",loc,"for",MSBUILD)
        if os.path.exists(loc):
            msbuild_exe = os.path.join(loc, MSBUILD)
            assert os.path.exists(msbuild_exe)
            print("found",msbuild_exe)
            return msbuild_exe
    raise FileNotFoundError(f"Could not find {MSBUILD}")


def getDependencies(depBranch):
    '''
        Compile libewf, libvhdi, libvmdk.
        Args:
            depBranch: String, which branch to compile (currently only support master)
    '''
    # Passed is a global variable that gets set to false
    # When an error occurs
    global passed
    passed = True

    # get all nuget packages needed by the solution
    if(passed):
        TSK_HOME = os.getenv("TSK_HOME", False)
        if not TSK_HOME:
            print("Please set the TSK_HOME environment variable")
            sys.exit(1)
        else:
            # nuget restore
            os.chdir(os.path.join(os.getenv("TSK_HOME"),"win32"))

            print ("Restoring nuget packages.")
            ret = subprocess.call(["nuget", "restore", "tsk-win.sln"] , stdout=sys.stdout)
            if ret != 0:
                sys.exit("Failed to restore nuget packages")


def buildTSKAll():

    TSK_HOME = os.getenv("TSK_HOME", False)
    if not TSK_HOME:
        print("Please set the TSK_HOME environment variable")
        sys.exit(1)

    if not MINIMAL:
        if(passed):
            buildTSK(32, "Release")
        if(passed):
            buildTSK(64, "Release_NoLibs")


    # MINIMAL is 64-bit for Autopsy and 32-bit with no deps for logical imager et al.
    if(passed):
        buildTSK(32, "Release_NoLibs")
    if(passed):
        BuildXPNoLibsFilePath = os.path.join(TSK_HOME, "build_xpnolibs")
        if os.path.exists(BuildXPNoLibsFilePath):
            buildTSK(32, "Release_XPNoLibs")
    if(passed):
        buildTSK(64, "Release")


def buildTSK(wPlatform, target):
    '''
        Build C++ sleuthkit library
    '''
    global passed

    print ("Building TSK " + str(wPlatform) + "-bit " + target + " build.")
    sys.stdout.flush()
    TSK_HOME = os.getenv("TSK_HOME",False)

    if not TSK_HOME:
        print("Please set the TSK_HOME environment variable")
        sys.exit(1)
    else:
        os.chdir(os.path.join(os.getenv("TSK_HOME"),"win32"))

    vs = []
    vs.append(find_msbuild())
    vs.append(os.path.join("tsk-win.sln"))
    vs.append("/p:configuration=" + target)
    if wPlatform == 64:
        vs.append("/p:platform=x64")
    elif wPlatform == 32:
        vs.append("/p:platform=Win32")
    else:
        print("Invalid platform")
        sys.stdout.flush()
        passed = False
        return
    vs.append("/clp:ErrorsOnly")
    vs.append("/t:clean")
    vs.append("/t:build")
    vs.append("/m")

    outputFile = os.path.join(LOG_PATH, "TSKOutput.txt")
    VSout = open(outputFile, 'w')
    try:
        ret = subprocess.call(vs, stdout=sys.stdout)
    except FileNotFoundError as e:
        logging.error("failing command line: %s",vs)
        raise
    VSout.close()
    if ret != 0:
        print("ret = " + str(ret))
        print(vs)
        print("LIBTSK " + str(wPlatform) + "-bit C++ failed to build.\n")
        sys.stdout.flush()
        passed = False
        return


def usage():
    '''
    Print out how to use this script.
    '''
    print('Usage: python3 updateAndBuildLibs.py [[-h | --help, -b <branch> | --branch=<branch>, -m | --minimal]')
    print('branch: Branch for dependencies (master is default)')
    print('-m,--minimal: Build 64-bit Release only')
    sys.stdout.flush()
    sys.exit(1)

def main():
    depBranch = 'master'
    global MINIMAL
    try:
        opts, args = getopt.getopt(sys.argv[1:],"mhb:",['help','minimal','branch='])
    except getopt.GetoptError as err:
        print(err)
        usage()
        sys.exit(2)

    for o,a in opts:
        if o in ("-m","--minimal"):
            MINIMAL = True
        elif o in ("-b","--branch"):
            depBranch = a
        elif o in ("-h","--help"):
            usage()
            system.exit(2)

    if not os.path.exists(LOG_PATH):
        os.makedirs(LOG_PATH)

    getDependencies(depBranch)
    buildTSKAll()

class OS:
    LINUX, MAC, WIN, CYGWIN = range(4)

if __name__ == "__main__":
    global SYS
    if _platform == "linux" or _platform == "linux2":
        SYS = OS.LINUX
    elif _platform == "darwin":
        SYS = OS.MAC
    elif _platform == "win32":
        SYS = OS.WIN
    elif _platform == "cygwin":
        SYS = OS.CYGWIN

    global passed
    if SYS is OS.WIN or SYS is OS.CYGWIN:
        passed = True
        main()
    else:
        passed = False
        print("We only support Windows and Cygwin at this time.")
        sys.stdout.flush()

    if (passed):
        sys.exit(0)
    else:
        sys.exit(1)

#/cygdrive/c/Program\ Files\ \(x86\)/MSBuild/14.0/Bin/MSBuild.exe libewf.sln /p:Configuration=Release /p:platform=x64 /t:clean /t:libewf_dll /m /clp:ErrorsOnly /nologo
