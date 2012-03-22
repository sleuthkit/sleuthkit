#!/bin/sh
/bin/rm -f testdisk.dmg redact.cfg
hdiutil create -size 1m -fs MS-DOS -nospotlight -attach -volname testdisk testdisk.dmg
echo "This is the zero file. FILE0001." > /Volumes/TESTDISK/file0.txt
echo "This is the first file. FILE0001." > /Volumes/TESTDISK/file1.txt
echo "This is the second file. FILE0002." > /Volumes/TESTDISK/file2.txt
echo "This is the third file. FILE0003." > /Volumes/TESTDISK/file3.txt
echo "This is the fourth file. FILE0004." > /Volumes/TESTDISK/file4.txt
echo "This is the fifth file. FILE0005." > /Volumes/TESTDISK/file5.txt
echo "This is the dixth file. FILE0006." > /Volumes/TESTDISK/file6.txt
hdiutil detach /Volumes/TESTDISK
cat > redact.cfg <<EOF
FILENAME file1.txt FILL 0x44
FILEPAT file2.* FILL 0x45
MD5 493b48719704853f7f468ac748e3854f FILL 0x46                 # file3
SHA1 2b4357a2f3352d9df67d5184e1bda187e6a92545 FILL 0x47        # file4
EOF
python iredact.py -r redact.cfg testdisk.dmg
hdiutil attach testdisk.dmg
for i in /Volumes/TESTDISK/* ; do echo ===== $i ==== ; cat $i ; echo "" ; echo "" ; done
hdiutil detach /Volumes/TESTDISK
