#!/bin/bash -ex
#
# Wine wrapper for MinGW cross-compile test execution.
#
# The autotools test harness supports a LOG_COMPILER variable that is
# prepended to every test invocation.  When cross-compiling for Windows
# with MinGW, "make check" passes LOG_COMPILER=scripts/wine_wrapper.sh
# so that .exe test binaries are run under Wine while plain shell scripts
# (e.g. runtests.sh, test_libraries.sh) are passed through unchanged.
#

case $1 in
*.exe)
  wine $1 -d yes
  ;;
*)
  $1
  ;;
esac
