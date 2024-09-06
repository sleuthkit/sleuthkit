#!/usr/bin/bash

IMAGE_DIR=${HOME}/from_brian

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

cp $IMAGE_DIR/3-kwsrch-ntfs/ntfs-img-kw-1.dd $IMAGE_DIR/.


