# ===========================================================================
#    https://www.gnu.org/software/autoconf-archive/ax_prog_java_works.html
# ===========================================================================
#
# SYNOPSIS
#
#   AX_PROG_JAVA_WORKS
#
# DESCRIPTION
#
#   Internal use ONLY.
#
#   Note: This is part of the set of autoconf M4 macros for Java programs.
#   It is VERY IMPORTANT that you download the whole set, some macros depend
#   on other. Unfortunately, the autoconf archive does not support the
#   concept of set of macros, so I had to break it for submission. The
#   general documentation, as well as the sample configure.in, is included
#   in the AX_PROG_JAVA macro.
#
# LICENSE
#
#   Copyright (c) 2008 Stephane Bortzmeyer <bortzmeyer@pasteur.fr>
#
#   This program is free software; you can redistribute it and/or modify it
#   under the terms of the GNU General Public License as published by the
#   Free Software Foundation; either version 2 of the License, or (at your
#   option) any later version.
#
#   This program is distributed in the hope that it will be useful, but
#   WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
#   Public License for more details.
#
#   You should have received a copy of the GNU General Public License along
#   with this program. If not, see <https://www.gnu.org/licenses/>.
#
#   As a special exception, the respective Autoconf Macro's copyright owner
#   gives unlimited permission to copy, distribute and modify the configure
#   scripts that are the output of Autoconf when processing the Macro. You
#   need not follow the terms of the GNU General Public License when using
#   or distributing such scripts, even though portions of the text of the
#   Macro appear in them. The GNU General Public License (GPL) does govern
#   all other use of the material that constitutes the Autoconf Macro.
#
#   This special exception to the GPL applies to versions of the Autoconf
#   Macro released by the Autoconf Archive. When you make and distribute a
#   modified version of the Autoconf Macro, you may extend this special
#   exception to the GPL to apply to your modified version as well.

#serial 11

AU_ALIAS([AC_PROG_JAVA_WORKS], [AX_PROG_JAVA_WORKS])
AC_DEFUN([AX_PROG_JAVA_WORKS], [
        if test x$ac_cv_prog_javac_works = xno; then
                AC_MSG_ERROR([Cannot compile java source. $JAVAC does not work properly])
        fi
        if test x$ac_cv_prog_javac_works = x; then
                AX_PROG_JAVAC
        fi
AC_CACHE_CHECK(if $JAVA works, ac_cv_prog_java_works, [
JAVA_TEST=Test.java
CLASS_TEST=Test.class
TEST=Test
changequote(, )dnl
cat << \EOF > $JAVA_TEST
/* [#]line __oline__ "configure" */
public class Test {
public static void main (String args[]) {
        System.exit (0);
} }
EOF
changequote([, ])dnl
        if AC_TRY_COMMAND($JAVAC $JAVACFLAGS $JAVA_TEST) && test -s $CLASS_TEST; then
                :
        else
          echo "configure: failed program was:" >&AS_MESSAGE_LOG_FD
          cat $JAVA_TEST >&AS_MESSAGE_LOG_FD
          AC_MSG_ERROR(The Java compiler $JAVAC failed (see config.log, check the CLASSPATH?))
        fi
if AC_TRY_COMMAND($JAVA -classpath . $JAVAFLAGS $TEST) >/dev/null 2>&1; then
  ac_cv_prog_java_works=yes
else
  echo "configure: failed program was:" >&AS_MESSAGE_LOG_FD
  cat $JAVA_TEST >&AS_MESSAGE_LOG_FD
  AC_MSG_ERROR(The Java VM $JAVA failed (see config.log, check the CLASSPATH?))
fi
rm -f $JAVA_TEST $CLASS_TEST
])
AC_PROVIDE([$0])dnl
]
)
