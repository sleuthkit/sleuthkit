# Copyright (c) 2017 Basis Technology.
#
# This software is distributed under the Common Public License 1.0

import codecs
import datetime
import logging
import os
import re
import shutil
import subprocess
import sys
import getopt
from sys import platform as _platform

import time
import traceback

MSBUILD_PATH = os.path.normpath("c:/Program Files (x86)/MSBuild/14.0/Bin/MSBuild.exe")
CURRENT_PATH = os.getcwd()
# save the build log in the output directory
LOG_PATH = os.path.join(CURRENT_PATH, 'output', time.strftime("%Y.%m.%d-%H.%M.%S"))
POSTGRES = False
Build_64 = True
Build_32 = True
Both = True
APPVEYOR = os.getenv("APPVEYOR_BUILD_FOLDER",False);
def pullAndBuildAllDependencies(branch):
    '''
        Compile libewf, libvhdi, libvmdk.
        Args:
            branch: String, which branch to compile (currently only support master)
    '''
    # Passed is a global variable that gets set to false
    # When an error occurs
    global passed
    passed = True

    # get the LIBEWF_HOME, LIBVHDI_HOME, LIBVMDH_HOME
    ewfHome = os.getenv("LIBEWF_HOME", "C:\\libewf_64bit")
    vhdiHome = os.getenv("LIBVHDI_HOME", "C:\\libvhdi_64bit")
    vmdkHome = os.getenv("LIBVMDK_HOME", "C:\\libvmdk_64bit\\libvmdk")
    # check if ewfHome, vhdiHome or vmdhHome exits
    checkPathExist(ewfHome)
    checkPathExist(vhdiHome)
    checkPathExist(vmdkHome)
    # git update libewf, libvhdi and libvmdk
    if(passed):
        gitPull(ewfHome, "libewf_64bit", branch)
    if(passed):
        gitPull(vhdiHome, "libvhdi_64bit", branch)
    if(passed):
        gitPull(vmdkHome, "libvmdk_64bit", branch)

    if Build_32 or Both:
        # build 32-bit of libewf, libvhdi, libvmdk and TSK
        if(passed):
            buildDependentLibs(ewfHome, 32, "libewf")
        if(passed):
            buildDependentLibs(vhdiHome, 32, "libvhdi")
        if(passed):
            buildDependentLibs(vmdkHome, 32, "libvmdk")


    # build 64-bit of libewf, libvhdi, libvmdk and TSK
    if Build_64 or Both:
        if(passed):
            buildDependentLibs(ewfHome, 64, "libewf")
        if(passed):
            buildDependentLibs(vhdiHome, 64, "libvhdi")
        if(passed):
            buildDependentLibs(vmdkHome, 64, "libvmdk")


def buildTSKAll():
    if(POSTGRES):
        if(passed):
            buildTSK(64, "Release_PostgreSQL")
            return

    if Build_32 or Both:
        if(passed):
            buildTSK(32, "Release")
        if(passed):
            buildTSK(32, "Release_NoLibs")
        if(passed):
            buildTSK(32, "Release_PostgreSQL")
    if Build_64 or Both:
        if(passed):
            buildTSK(64, "Release")
        if(passed):
            buildTSK(64, "Release_NoLibs")
        if(passed):
            buildTSK(64, "Release_PostgreSQL")

def checkPathExist(path):
    global passed

    if not os.path.exists(path):
        print (path + " not exist.")
        sys.stdout.flush()
        passed = False

def gitPull(libHome, repo, branch):
    '''
        Pull the latest code.
        Args:
            libHome: according the environment variable to get the location
            repo String of repository ("libewf_64bit", "libvmdk_64bit" or "libvhdi_64bit" which one to pull
            branch: String, which branch to pull
    '''

    global SYS
    global passed

    gppth = os.path.join(LOG_PATH, "GitPullOutput" + repo + ".txt")
    gpout = open(gppth, 'a')


    print("Resetting " + repo)
    sys.stdout.flush()
    call = ["git", "reset", "--hard"]
    ret = subprocess.call(call, stdout=sys.stdout, cwd=libHome)

    if ret != 0:
        passed = False
        return

    print("Checking out " + branch)
    sys.stdout.flush()
    call = ["git", "checkout", branch]
    ret = subprocess.call(call, stdout=sys.stdout, cwd=libHome)

    if ret != 0:
        passed = False
        return

    call = ["git", "pull"]
    print("Pulling " + repo + "/" + branch)
    sys.stdout.flush()
    ret = subprocess.call(call, stdout=sys.stdout, cwd=libHome)

    if ret != 0:
        passed = False

    gpout.close()
    if passed:
        print("Update " + repo + " successfully.")
    else:
        print("Update " + repo + " failed.")

def buildDependentLibs(libHome, wPlatform, targetDll):
    '''
        build libewf.dll, libvhdi.dll and libvmdk.dll
    '''
    global passed
    passed = True

    print("Building " + str(wPlatform) + "-bit " + targetDll)
    sys.stdout.flush()

    target = "Release"

    if wPlatform == 64:
        dllFile = os.path.join(libHome, "msvscpp", "x64", target, targetDll +".dll")
    elif wPlatform == 32:
        dllFile = os.path.join(libHome, "msvscpp", target, targetDll + ".dll")
    else:
        print("Invalid platform")
        sys.stdout.flush()
        passed = False
        return

    if (os.path.isfile(dllFile)):
        os.remove(dllFile)
    os.chdir(os.path.join(libHome,"msvscpp"))

    vs = []
    vs.append(MSBUILD_PATH)
    vs.append(os.path.join(targetDll + ".sln"))
    vs.append("/p:configuration=" + target)
    if wPlatform == 64:
        vs.append("/p:platform=x64")
    elif wPlatform == 32:
        vs.append("/p:platform=Win32")
    vs.append("/v:minimal")
    vs.append("/t:clean")
    vs.append("/t:build")

    outputFile = os.path.join(LOG_PATH, targetDll + "Output.txt")
    VSout = open(outputFile, 'w')
    ret = subprocess.call(vs, stdout=sys.stdout)
    errorCode = ret
    VSout.close()
    if ret > 0:
        failed_proj = os.system("grep 'Done Building Project' " + outputFile + " | grep vcxproj |grep FAILED |wc -l |cut -f1 -d' '")
        failed_pyewf = os.system("grep 'Done Building Project' " + outputFile + " | grep pyewf |grep FAILED |grep pywc -l |cut -f1 -d' '")
        if failed_proj == failed_pyewf:
            errorCode = 0
    if errorCode != 0 or not os.path.exists(dllFile) or os.path.getctime(dllFile) < (time.time() - 2 * 60): # the new dll should not be 2 mins old
        print(targetDll + " " + str(wPlatform) + "-bit C++ failed to build.\n")
        print("return code: " + str(ret) + "\tdll file: " + dllFile + "\tcreated time: " + str(os.path.getctime(dllFile)))
        sys.stdout.flush()
        passed = False
        os.chdir(CURRENT_PATH)
        return
    else:
        print("Build " + str(wPlatform) + "-bit " + targetDll + " successfully")

    os.chdir(CURRENT_PATH)

def buildTSK(wPlatform, target):
    '''
        Build C++ sleuthkit library
    '''
    global passed

    print ("Building TSK " + str(wPlatform) + "-bit " + target + " build.")
    sys.stdout.flush()
    if(APPVEYOR):
        TSK_HOME = os.getenv("APPVEYOR_BUILD_FOLDER")
        os.chdir(os.path.join(TSK_HOME,"win32"))

    vs = []
    vs.append(MSBUILD_PATH)
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
    vs.append("/v:minimal")
    vs.append("/t:clean")
    vs.append("/t:build")

    outputFile = os.path.join(LOG_PATH, "TSKOutput.txt")
    VSout = open(outputFile, 'w')
    ret = subprocess.call(vs, stdout=sys.stdout)
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
    print('Usage: python3 updataBuildlibs.py [-h | --help, -b <branch> | --branch=<branch>, -d | --postgres, --platform=<[64|32]> |  -p <64|32>')
    print('-h,--help show help')
    print('-b,--branch enter the branch name')
    print('-d,--postgres use this option for postgres build')
    print('-p,--platform enter the platform to be build for 64 or 32 or both')
    print('branch is which branch to build and is optional. Currently only works for master')
    print('Note: all the arguments above are optional')
    sys.stdout.flush()
    sys.exit(1)

def main():

    #by default we use master branch to update the source
    branch = 'master'
    global Build_32
    global Build_64
    global Both
    global POSTGRES
    try:
        opts, args = getopt.getopt(sys.argv[1:],"p:b:dh",['help','platform=','branch=','postgres'])
    except getopt.GetoptError as err:
        print(err)
        usage()
        sys.exit(2)

    for o,a in opts:
        if o in ("-p","--platform"):
            if a == '64':
                Build_32 = False
                Both =False
            elif a == '32':
                Build_64 = False
                Both = False
            elif a == '':
                Both = True
        elif o in ("-b","--branch"):
             branch == a
        elif o in ("-d","--postgres"):
             POSTGRES = True
             Build_64 = True
             Build_32 = False
             Both = False
        elif o in ("-h","--help"):
            usage()
            sys.exit()
    print(Build_64)
    print(Build_32)
    print(Both)
    print(POSTGRES)
    '''
    if len(sys.argv) == 2:    #keep this parameter here for the future we may let user use different branch to update source
        branch = sys.argv[1]
    elif len(sys.argv) > 2:
        print('Wrong arguments.')
        usage()
    '''
    print('Updating source by %s branch.' % branch)
    if not os.path.exists(LOG_PATH):
        os.makedirs(LOG_PATH)
    if not os.path.exists(MSBUILD_PATH):
        print("MS_BUILD Does not exist")
        sys.stdout.flush()
    pullAndBuildAllDependencies(branch)
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
