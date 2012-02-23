#!/usr/bin/env bash
#       ficlam.sh : a simple plug-in that runs on top of fiwalk framework.
#     description : fiwalk's plug-in system will instantiate clamav's daemon for a scan on each file.
#    requirements : clamconfig.txt which is in $domex/src/fiwalk/plugins
#    quick how to : to use this, the basic syntax is as follows:
#                   fiwalk -c clamconfig.txt -X<path/to/output.xml> <path/to/input/image.aff|raw|whatever>


## change walked file to readable
chmod +r $1

## old way to call front end each time.  not efficient at all.

#clamscan --bytecode=yes --scan-pe --scan-elf --scan-ole2 --scan-pdf --scan-html $1 | head -n 1 | cut -d " " -f2 > /tmp/clamscan.result.out
#if [[ $(cat /tmp/clamscan.result.out) == "OK" ]]
#then
#  echo "Virus: Not Infected"
#else
#  echo "Virus: Infected"
#fi
#cat /tmp/clamscan.result.out
#rm /tmp/clamscan.result.out

## output raw clamdscan output to <clamav> tags.  this is useful for diagnosing and troubleshooting

#result=$(clamdscan $1 2>&1 | grep "$1")
#echo "clamav: $result"

## output to stderr/stdout and grep for "OK".  If OK, not infected (0), else infected (1) and show signature.

result=$(clamdscan $1 2>&1 | grep "$1" | cut -d " " -f2)
if [[ $result == "OK" ]]
then
    echo "clamav_infected: 0"
else
    echo "clamav_infected: 1"
    echo "clamav_file: $1"
    echo "clamav_sig: $result"
fi

