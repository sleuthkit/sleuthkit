Legacy tests
============

Note: This directory contains legacy unit tests. For the new unit test framework, please see [../unit_tests/README.md](../unit_tests/README.md)


Disk Images
-----------
Unit testing is done with the following disk images:


All different images:
```
data/imageformat_mmls_1.E01 - 405k file
data/imageformat_mmls_1.vhd - 18M VHD file
data/imageformat_mmls_1.vmdk - 5.6M VMDK file
data/image/image.dd  - 100k file
data/image/image.E01 -
data/image/image.iso - 358k file
data/image/image.qcow - 36k
data/image/image.vhd -  2M file
data/image/image.vmdk - 128k

data/image/image_dd.xml - DFXML output of running fiwalk on data/image/image.dd

```
Setup:

`get_dfft.bash` - Bash script that gets disk images from digitalcorpora and stores them in `$HOME/from_brian` (which is the legacy location where disk images are stored.
