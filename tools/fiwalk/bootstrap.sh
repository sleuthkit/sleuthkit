#!/bin/sh
#
echo Bootstrap script to create configure script using autoconf
echo
touch NEWS README AUTHORS ChangeLog stamp-h
aclocal
autoheader -f
autoconf -f
automake --add-missing -c
echo "Ready to run configure!"
if [ $1"x" != "x" ]; then
  ./configure "$@"
fi

