# Copyright (c) 2020 Basis Technology.
#
# This software is distributed under the Common Public License 1.0
#
# Downloads the nuget packages for libewf, etc, and places them in the correct location.

import glob
import os
import shutil
import wget
import zipfile

# Download a package and copy to the package folder.
#
# URL - url of the zipped nuget package.
# zipFileName - name of the zipped package.
# baseName - base name for the package. This is expected to be the beginning of the extracted folder name.
def installPackage(url, zipFileName, baseName):
    print("Installing nuget package for " + baseName)
    pathToScript = os.path.abspath(__file__)
    targetDir = os.path.join(os.path.dirname(pathToScript), "packages")

    # Remove the existing zip file, if present
    if os.path.exists(zipFileName):
        os.remove(zipFileName)

    # Remove the existing package dir for this module, if present
    existingPackageDirs = glob.glob(targetDir + "/" + baseName + "*")
    for dir in existingPackageDirs:
        print("Deleting existing package " + dir)
        shutil.rmtree(dir)
    
    # Download the zipped nuget package
    print("Downloading nuget package from : " + url)
    wget.download(url, zipFileName)
   
    # Extract to the packages folder
    print("\nExtracting " + zipFileName + " to " + os.path.abspath(targetDir) + "\n")
    with zipfile.ZipFile(zipFileName, 'r') as zip_ref:
        zip_ref.extractall(targetDir)

    # Delete the downloaded file
    os.remove(zipFileName)

# Install all nuget packages
def installAllPackages():
    installPackage("https://github.com/sleuthkit/libewf_64bit/releases/download/20130416/libewf.nuget.zip", "./libewf.nuget.zip", "libewf")    


def main():
    installAllPackages()
    
if __name__ == "__main__":
    main()