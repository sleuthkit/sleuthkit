#!/bin/sh
#
# For making for Win32 with mingw, you will need to install MinGW.
# You will also need 
# 
echo making for mingw on `uname -a`

if test -r /opt/local/bin/i386-mingw32-gcc ; then
  echo Compiling for mingw on a Mac installed with MacPorts
  export MBIN=/opt/local/bin/
  export PREFIX=/opt/local/i386-mingw32
  export CC=$MBIN/i386-mingw32-gcc
  export CXX=$MBIN/i386-mingw32-g++
  export RANLIB=$MBIN/i386-mingw32-ranlib
  export AR=$MBIN/i386-mingw32-ar
  export MINGWFLAGS="-mwin32 -mconsole -march=pentium4 -Wall"
  export CFLAGS="$MINGWFLAGS"
  export CXXFLAGS="$MINGWFLAGS"
fi
if test -r /usr/i586-mingw32msvc ; then
  echo Compiling for mingw on a Linux system
  export MBIN=/usr/i586-mingw32msvc
  export PREFIX=/usr/i586-mingw32msvc
  export MINGW32PATH=/usr/i586-mingw32msvc
  export CC=/usr/bin/i586-mingw32msvc-gcc
  export CXX=/usr/bin/i586-mingw32msvc-g++
  export AR=${MINGW32PATH}/bin/ar
  export RANLIB=${MINGW32PATH}/bin/ranlib
  export STRIP=${MINGW32PATH}/bin/strip
  export MINGWFLAGS="-mwin32 -mconsole -march=i586 -Wall"
  export CFLAGS="$MINGWFLAGS"
  export CXXFLAGS="$MINGWFLAGS"
fi

# Figure out which GCC was configured
rebuild='yes'
if test -f Makefile ; then
  CHOSEN_CC=`grep '^CC = ' Makefile | awk '{print $3;}'`
  if test $CHOSEN_CC == $CC ; 
     then rebuild='no' ; 
  fi
fi

echo rebuild: $rebuild

if test $rebuild == 'yes'; then
  make distclean
  echo reconfiguring for mingw
  autoreconf -f
  ./configure CC=$CC CXX=$CXX RANLIB=$RANLIB --target=i586-mingw32msvc --host=i586 --prefix=/opt/local/i386-ming32 
fi
echo ================
echo BUILD COMMAND:
echo make CC=$CC CXX=$CXX RANLIB=$RANLIB CFLAGS=\"$CFLAGS\" CXXFLAGS=\"$CXXFLAGS\" 
echo ================
make CC=$CC CXX=$CXX RANLIB=$RANLIB CFLAGS="$CFLAGS" CXXFLAGS="$CXXFLAGS"  || exit 1
if test x"$1" == "xdist" ; then
  VERSION=`grep PACKAGE_VERSION config.h | awk '{print $3}' | sed s/\"//g`
  EXE=$HOME/fiwalk-$VERSION.exe
  cp -f src/fiwalk.exe $EXE
  ls -l $EXE
  scp $EXE afflib.org:afflib.org/downloads/
  VFILE=fiwalk.exe_version.txt
  /bin/rm -f $VFILE
  echo $EXE > $VFILE
  scp $VFILE afflib.org:afflib.org/downloads/
fi

