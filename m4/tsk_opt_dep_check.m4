#
# Check if pkg-config is installed and set up variables used for producing
# the tsk.pc.
#
# This MUST be run before any of the other macros in this file.
#
AC_DEFUN([TSK_CHECK_PROG_PKGCONFIG], [
  AC_CHECK_PROG([PKGCONFIG], [pkg-config], [yes], [no])
  AS_IF([test "x$ac_cv_prog_PKGCONFIG" = "xyes"], [
    m4_ifdef([PKG_PROG_PKG_CONFIG], [PKG_PROG_PKG_CONFIG], [])
    dnl Ask for static libs during static linking
    AS_IF([test "x$enable_shared" != "xyes"], [PKG_CONFIG="$PKG_CONFIG --static"])
  ])

  PACKAGE_LIBS_PRIVATE=
  AC_SUBST([PACKAGE_LIBS_PRIVATE])
])

#
# Call AX_PKG_CHECK_MODULES only if PKG_CHECK_MODULES is defined, i.e.,
# only if we have the pkg-config macros; otherwise make it a no-op
#
AC_DEFUN([TSK_PKG_CHECK_MODULES], [
  m4_ifdef([PKG_CHECK_MODULES],
           [AX_PKG_CHECK_MODULES([$1], [$2], [$3], [$4], [$5], [$6], [$7])])
])

#
# Check for optional dependencies.
#
# TSK_OPT_DEP_CHECK(DISPLAY_NAME, PKG_VAR, PKG_MODULE, HEADER_LIST, CHECK_LIB_NAME, CHECK_LIB_FUNC)
#
# DISPLAY_NAME is the name of the library shown by 'configure --help'
#
# PKG_VAR is the prefix used for variables associated with the particular
# dependency. Each dependency may have its own CPPFLAGS, CFLAGS, CXXFLAGS,
# and LIBS variables. E.g., "FOO" would have FOO_CPPFLAGS, FOO_CFLAGS, etc.
#
# PKG_MODULE is the name of the library to be checked by pkg-config.
#
# HEADER_LIST is a list of header files to be checked by AC_CHECK_HEADERS.
#
# CHECK_LIB_NAME is the name of the library to be checked by AC_CHECK_LIB.
#
# CHECK_LIB FUNC is the name of the function to be checked by AC_CHECK_LIB.
#
# If the library is found, ax_DISPLAY_NAME will be set to 'yes'; otherwise
# to 'no'.
#
AC_DEFUN([TSK_OPT_DEP_CHECK], [
  dnl Check if we should link lib
  AC_ARG_WITH(
    [$1],
    [AS_HELP_STRING([--without-$1],[Do not use $1 even if it is installed])]
    [AS_HELP_STRING([--with-$1=dir],[Specify that $1 is installed in directory 'dir'])],
    dnl If --with-lib or --without-lib is given
    [],
    dnl if nothing was specified, default to a test
    [with_$1=maybe]
  )

  dnl check for lib if they did not specify no
  ax_$1=no
  AS_IF(
    [test "x[$]with_$1" != "xno"],
    [
      AS_IF([test "x[$]with_$1" = "xyes" -o "x[$]with_$1" = "xmaybe"],
        [
          dnl Check for lib using pkg-config, if we have it
          m4_ifnblank([$3], [AS_IF([test "x$ac_cv_prog_PKGCONFIG" = "xyes"],
            [
              SAVED_AX_PACKAGE_REQUIRES="$AX_PACKAGE_REQUIRES"
              SAVED_AX_PACKAGE_REQUIRES_PRIVATE="$AX_PACKAGE_REQUIRES_PRIVATE"
              TSK_PKG_CHECK_MODULES([$2], [], [$3],
              [
                $2[]_CXXFLAGS="[$]$2[]_CFLAGS"
                ax_$1=yes
              ],
              [
                AX_PACKAGE_REQUIRES="$SAVED_AX_PACKAGE_REQUIRES"
                AX_PACKAGE_REQUIRES_PRIVATE="$SAVED_AX_PACKAGE_REQUIRES_PRIVATE"
                ax_$1=no
              ]
            )]
          )])
        ],
        [
          dnl A directory was given; check that it exists
          AS_IF([test -d "[$]with_$1/include"],
            [
              $2[]_CPPFLAGS="-I[$]with_$1/include"
              $2[]_LIBS="-L[$]with_$1/lib -l$5"
            ],
            [AC_MSG_FAILURE([$1 directory not found at [$]with_$1])]
          )
        ]
      )

      dnl Save the user variables
      SAVED_CPPFLAGS="$CPPFLAGS"
      SAVED_CFLAGS="$CFLAGS"
      SAVED_CXXFLAGS="$CXXFLAGS"
      SAVED_LDFLAGS="$LDFLAGS"
      SAVED_LIBS="$LIBS"

      dnl Use the discovered values for AC_CHECK_HEADERS, AC_CHECK_LIB
      CPPFLAGS="$CPPFLAGS [$]$2[]_CPPFLAGS"
      CFLAGS="$CFLAGS [$]$2[]_CFLAGS"
      CXXFLAGS="$CXXFLAGS [$]$2[]_CXXFLAGS"
      LDFLAGS="$LDFLAGS [$]$2[]_LDFLAGS"
      LIBS="$LIBS [$]$2[]_LIBS"

      dnl Check if the library is usable
      AC_CHECK_HEADERS([$4], [AC_CHECK_LIB([$5], [$6])])
      AS_IF([test "x[$]ac_cv_lib_$5[]_$6" = "xyes"],
        [
          dnl Library found and usable
          AS_IF([test "x[$]ax_$1" = "xyes"],
            [
              dnl Library found with pkg-config, nothing to do
            ],
            [
              dnl Library found without pkg-config; ensure that it is added
              dnl to Libs.private in tsk.pc
              PACKAGE_LIBS_PRIVATE="$PACKAGE_LIBS_PRIVATE -l$5"

              dnl Set $2_LIBS if not already set
              AS_IF([test -z "[$]$2[]_LIBS"], [$2[]_LIBS="-l$5"])
              ax_$1=yes
            ]
          )
        ],
        [
          dnl Library not found or unusable
          ax_$1=no
        ]
      )

      dnl Reset user variables
      CPPFLAGS="$SAVED_CPPFLAGS"
      CFLAGS="$SAVED_CFLAGS"
      CXXFLAGS="$SAVED_CXXFLAGS"
      LDFLAGS="$SAVED_LDFLAGS"
      LIBS="$SAVED_LIBS"

      dnl Export library flags
      AC_SUBST([$2_CPPFLAGS])
      AC_SUBST([$2_CFLAGS])
      AC_SUBST([$2_CXXFLAGS])
      AC_SUBST([$2_LDFLAGS])
      AC_SUBST([$2_LIBS])
    ]
  )

  dnl Report an error if the library was requested but is not usable
  AS_IF([test "x[$]ax_$1" = "xno" -a "x[$]with_$1" != "xno" -a "x[$]with_$1" != "xmaybe"],
    [AC_MSG_FAILURE([$1 requested but not available])]
  )
])
