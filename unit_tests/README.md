Unit testing
============


The unit test program is linked with fiwalk (without the fiwalk_main.cpp) so that we can just run fiwalk on disk images and do a full filesystem walk as part of our unit tests.

XML should be prepared using fiwalk and then processing with xmlstarlet to remove the `<creator>` section, e.g.:

fiwalk -x filename.dd | xmlstartlet ed -d "//creator" - > filename.xml
