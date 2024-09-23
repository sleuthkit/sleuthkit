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

The unit test program is linked with fiwalk (without the fiwalk_main.cpp) so that we can just run fiwalk on disk images and do a full filesystem walk as part of our unit tests.

Disk Images

XML should be prepared using fiwalk and then processing with xmlstarlet to remove the `<creator>` section, e.g.:

fiwalk -x filename.dd | xmlstartlet ed -d "//creator" - > filename.xml
