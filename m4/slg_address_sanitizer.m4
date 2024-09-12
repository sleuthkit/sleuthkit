################################################################
## AddressSanitizer support
# https://github.com/libMesh/libmesh/issues/1396
AC_ARG_ENABLE([address-sanitizer],
              [AS_HELP_STRING([--enable-address-sanitizer],
                              [enabled AddressSanitizer support for detecting a wide variety of
                               memory allocation and deallocation errors])],
              [AC_DEFINE(HAVE_ADDRESS_SANITIZER, 1, [enable AddressSanitizer])
              address_sanitizer="yes"
              CXXFLAGS="$CXXFLAGS -fsanitize=address -fsanitize-address-use-after-scope"
              ],
              [])

AC_ARG_ENABLE([thread-sanitizer],
              [AS_HELP_STRING([--enable-thread-sanitizer],
                              [enabled ThreadSanitizer support for detecting a wide variety of
                               thread interlocking errors])],
              [AC_DEFINE(HAVE_THREAD_SANITIZER, 1, [enable ThreadSanitizer])
              thread_sanitizer="yes"
              CXXFLAGS="$CXXFLAGS -fsanitize=thread "
              ],
              [])

AC_ARG_ENABLE([undefined-sanitizer],
              [AS_HELP_STRING([--enable-undefined-sanitizer],
                              [enabled UndefinedSanitizer support for detecting a wide variety of undefined])],
              [AC_DEFINE(HAVE_UNDEFINED_SANITIZER, 1, [enable UndefinedSanitizer])
              undefined_sanitizer="yes"
              CXXFLAGS="$CXXFLAGS -fsanitize=undefined "
              ],
              [])
