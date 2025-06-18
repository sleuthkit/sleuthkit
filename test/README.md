Unit testing
============
This is the new unit testing system.

Goals of unit testing
---------------------

1 - Exercise as much of SleuthKit as possible, as evidenced through code-coverage reported to codecov.io
2 - Validate outputs in addition to no-crash.
3 - Automated; run on as many operating systems as possible.
4 - Run entirely within GitHub Actions.
5 - Test with disk images that are publicly available.

Disk Images
-----------
Disk images for testing reside on Amazon S3 here:

    https://digitalcorpora.s3.amazonaws.com/corpora/drives/tsk-2024/sleuthkit_test_data.zip

Once you download, unpack and should set the environment variable SLEUTHKIT_TEST_DATA_DIR to the location from which you dwonloaded.

Images larger than 10MB should be stored as a compressed data type (e.g. .E01), so you need libewf support installed.


Currently, it's necessary to type `make unpack` in the sleuthkit_test_data directory to unpack the
zipfiles. However, in the future, the contents of zipfile itself will
be not be compressed.

The master copy of the disk images reside in the [Github repository](https://github.com/sleuthkit/sleuthkit_test_data) using [git's extensions for large objects](https://git-lfs.com/). However, we hit GitHub bandwidth download limitations, so instead of downloading from GitHub, you should download from the S3 bucket.

Test Program
------------
The unit test program is linked with fiwalk (without the
fiwalk_main.cpp) so that we can just run fiwalk on disk images and do
a full filesystem walk as part of our unit tests.

XML should be prepared using fiwalk and then processing with xmlstarlet to remove the `<creator>` section, e.g.:

fiwalk -x filename.dd | xmlstartlet ed -d "//creator" - > filename.xml
