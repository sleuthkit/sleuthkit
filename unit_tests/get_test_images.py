#!/usr/bin/env python3

"""
This python script gets disk images used in the unit tests.
"""

import os
import os.path
from os.path import join,abspath,dirname,basename

HOME = os.getenv("HOME")
IMAGE_DIR=join(HOME, "from_brian") # legacy directory

# Format of IMAGES:
# [ (source, destination_name) ]
DFTT='https://digitalcorpora.s3.amazonaws.com/corpora/drives/dftt-2004/'
HFSJTEST1 = "https://corp.digitalcorpora.org/corpora/drives/nps-2009-hfsjtest1/"

IMAGES =  [ (DFTT + "3-kwsrch-ntfs.zip", "ntfs-img-kw-1.dd"),
            (DFTT + "3-kwsrch-ntfs.xml", "ntfs-img-kw-1.xml")
            (DFTT + "imageformat_mmls_1.E01", "imageformat_mmls_1.E01"),
            (DFTT + "imageformat_mmls_1.E01.xml", "imageformat_mmls_1.E01.xml"),
            (DFTT + "https://corp.digitalcorpora.org/corpora/drives/nps-2009-hfsjtest1/image.gen1.dmg", "image.gen1.dmg")
            (DFTT + image.gen1.dmg", "image.gen1.dmg")

def get_test_images():
    os.makedirs(IMAGE_DIR, exist_ok=True)


if __name__=="__main__":

mkdir -p $IMAGE_DIR

for fn in 3-kwsrch-ntfs.zip imageformat_mmls_1.E01 imageformat_mmls_1.vhd imageformat_mmls_1.vmdk; do
    if ! test -f $IMAGE_DIR/$fn
    then
        curl https://digitalcorpora.s3.amazonaws.com/corpora/drives/dftt-2004/$fn -o $IMAGE_DIR/$fn
        if [[ $fn == *.zip ]]; then
            (cd $IMAGE_DIR; unzip $fn)
        fi
    fi
done

if ! test -f $IMAGE_DIR/ntfs-img-kw-1.dd ; then
    cp $IMAGE_DIR/3-kwsrch-ntfs/ntfs-img-kw-1.dd $IMAGE_DIR/.
fi

# Get additional digital corpora files
for url in https://corp.digitalcorpora.org/corpora/drives/nps-2009-hfsjtest1/image.gen1.dmg; do
    fn=$(basename url)
    if ! test -f $IMAGE_DIR/$fn
    then
        curl $url -o $IMAGE_DIR/$fn
    fi
done
