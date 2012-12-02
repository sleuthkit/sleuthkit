#!/bin/sh
#
# test program for fiwalk

IMG=/corp/drives/nps/nps-2009-canon2/nps-2009-canon2-gen5.raw

if [ ! -r $IMG ] ; then
  echo ERROR: $IMG not on this system
  echo Cannot perform this test.
  exit 0
fi

/bin/rm -f gen5.xml
ficonfig=../plugins/ficonfig.txt
if [ ! -r $ficonfig ] ; then
  ficonfig=$srcdir/../plugins/ficonfig.txt
fi
if ! ./fiwalk -c $ficonfig  -X gen5.xml $IMG ; then exit 1 ; fi
if ! xmllint gen5.xml > /dev/null ; then 
   echo *** BAD XML  in gen5.xml ***
   exit 1 ; 
fi
if ! grep 6c9e27f9911f37488ef0d6e878c68f2a61100b2c gen5.xml >/dev/null ; then echo sha1 extract not working; exit 1 ; fi
if ! grep 'One-chip color area sensor' gen5.xml >/dev/null ; then echo EXPAT plugin not working ; exit 1; fi
/bin/rm -f gen5.xml

