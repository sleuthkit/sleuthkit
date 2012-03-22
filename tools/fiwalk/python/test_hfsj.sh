#!/bin/sh

hdiutil create -size 10m -fs HFS+J -nospotlight -attach -volname image -ov -layout NONE \
    -imagekey diskimage-class=CRawDiskImage image.dmg
echo "This is file 1 - snarf" > /Volumes/image/file1.txt
echo "This is file 2 - snarf" > /Volumes/image/file2.txt
sync
hdiutil detach /Volumes/image
cp image.dmg image.gen0.dmg
echo "look for file1 and file2:"
strings -o image.dmg | grep snarf
echo "mount the disk and overwrite the contents of file2"
hdiutil attach image.dmg
echo "New file 1 contents - snarf" | dd of=/Volumes/image/file1.txt
echo ""
echo "===file1.txt==="
cat /Volumes/image/file1.txt
echo ""
echo "===file2.txt==="
cat /Volumes/image/file2.txt
echo ""
hdiutil detach /Volumes/image
cp image.dmg image.gen1.dmg
strings -o image.dmg | grep snarf
