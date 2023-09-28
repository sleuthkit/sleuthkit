dnl Function to detect if OSS-Fuzz build environment is available
AC_DEFUN([AX_TESTS_CHECK_OSSFUZZ],
  [AM_CONDITIONAL(
    HAVE_LIB_FUZZING_ENGINE,
    [test "x${LIB_FUZZING_ENGINE}" != x])
  AC_SUBST(
    [LIB_FUZZING_ENGINE],
    ["${LIB_FUZZING_ENGINE}"])
])

