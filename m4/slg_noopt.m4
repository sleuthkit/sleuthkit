################################################################
############## drop optimization flags and add -g if requested ################
# Should we disable optimization?
AC_ARG_ENABLE([opt],
        [AS_HELP_STRING([--disable-opt],[Drop all -O C flags])],
        [with_opt=no],
        [with_opt=yes])

# Or maybe just tone it down a bit?
AC_ARG_ENABLE([o3],
        [AS_HELP_STRING([--disable-o3],[Do not force O3 optimization; use default level])],
        [with_o3=no],
        [with_o3=yes])

if test "${with_opt}" = "no" ; then
  CFLAGS=`echo   -g "$CFLAGS"   | sed s/-O[[0-9]]//`             # note the double quoting!
  CXXFLAGS=`echo -g "$CXXFLAGS" | sed s/-O[[0-9]]//`
else
  # If we are not stripping the optimizer,
  # increase optimizer from -O2 to -O3 if not explicitly forbidden
  if test "${with_o3}" != "no" ; then
      AC_MSG_NOTICE([adding -O3 to CFLAGS and CXXFLAGS])
      CFLAGS=`echo   -g "$CFLAGS"   | sed 's/-O[123]//'`             # note the double quoting!
      CFLAGS="$CFLAGS -O3"

      CXXFLAGS=`echo -g "$CXXFLAGS" | sed 's/-O[123]//'`
      CXXFLAGS="$CXXFLAGS -O3"
  fi
fi
