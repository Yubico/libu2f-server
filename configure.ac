# Copyright (c) 2014 Yubico AB
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
# # Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#
# # Redistributions in binary form must reproduce the above
# copyright notice, this list of conditions and the following
# disclaimer in the documentation and/or other materials provided
# with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

AC_PREQ([2.69])

AC_INIT([libu2f-server], [1.0.2],
  [https://github.com/Yubico/libu2f-server/issues],
  [libu2f-server],
  [https://developers.yubico.com/libu2f-server])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])

# http://www.gnu.org/s/libtool/manual/html_node/Updating-version-info.html
AC_SUBST(LT_CURRENT, 0)
AC_SUBST(LT_REVISION, 5)
AC_SUBST(LT_AGE, 0)

AM_INIT_AUTOMAKE([gnits dist-xz no-dist-gzip std-options -Wall])
AM_SILENT_RULES([yes])
AC_PROG_CC

m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

LT_INIT([win32-dll])

GTK_DOC_CHECK(1.1)
AM_MISSING_PROG(HELP2ADOC, help2adoc, $missing_dir)
AM_MISSING_PROG(HELP2MAN, help2man, $missing_dir)
if ! which help2man >/dev/null ; then
   AC_MSG_ERROR([help2man missing])
fi
if ! which gengetopt >/dev/null ; then
   AC_MSG_ERROR([gengetopt missing])
fi

gl_LD_VERSION_SCRIPT

PKG_CHECK_MODULES([LIBJSON], [json-c], [], [
  PKG_CHECK_MODULES([LIBJSON], [json])])

# Check for json_object_object_get_ext
am_save_CFLAGS="$CFLAGS"
am_save_LIBS="$LIBS"
CFLAGS="$CFLAGS $LIBJSON_CFLAGS"
LIBS="$LIBS $LIBJSON_LIBS"
AC_CHECK_FUNCS([json_object_object_get_ex])
CFLAGS=$am_save_CFLAGS
LIBS=$am_save_LIBS

PKG_CHECK_MODULES([LIBSSL], [libssl], [], [])

PKG_CHECK_MODULES([LIBCRYPTO], [libcrypto], [], [])

AC_ARG_ENABLE([tests],
              [AS_HELP_STRING([--enable-tests],
                              [use check to run the unit tests])],
                              [enable_tests=$enableval],
                              [enable_tests=no])
AM_CONDITIONAL([ENABLE_TESTS],[test '!' "$enable_tests" = no])
if test '!' "$enable_tests" = no; then
  PKG_CHECK_MODULES([CHECK], [check], [], [AC_MSG_ERROR(`check` not found)])
fi


AC_ARG_ENABLE([coverage],
              [AS_HELP_STRING([--enable-coverage],
                              [use Gcov to test the test suite])],
                              [],
                              [enable_cov=no])
AM_CONDITIONAL([ENABLE_COV],[test '!' "$enable_cov" = no])

AC_ARG_ENABLE([h2a],
              [AS_HELP_STRING([--enable-h2a],
                              [generate asciidoc manpages])],
                              [enable_h2a=$enableval],
                              [enable_h2a=no])
AM_CONDITIONAL([ENABLE_H2A],[test '!' "$enable_h2a" = no])

AC_ARG_ENABLE([gcc-warnings],
  [AS_HELP_STRING([--enable-gcc-warnings],
		  [turn on lots of GCC warnings (for developers)])],
  [case $enableval in
     yes|no) ;;
     *)      AC_MSG_ERROR([bad value $enableval for gcc-warnings option]) ;;
   esac
   gl_gcc_warnings=$enableval],
  [gl_gcc_warnings=no]
)

if test "$gl_gcc_warnings" = yes; then
  nw="$nw -Wsystem-headers"         # Don't let system headers trigger warnings
  nw="$nw -Wpadded"                 # Struct's arenot padded
  nw="$nw -Wc++-compat"             # We don't care strongly about C++ compilers
  nw="$nw -Wtraditional"            # Warns on #elif which we use often
  nw="$nw -Wtraditional-conversion" # Too many warnings for now
  nw="$nw -Wconversion"             # Too many warnings for now
  nw="$nw -Wsuggest-attribute=pure" # Is it worth using attributes?
  nw="$nw -Wsuggest-attribute=const" # Is it worth using attributes?

  gl_MANYWARN_ALL_GCC([ws])
  gl_MANYWARN_COMPLEMENT(ws, [$ws], [$nw])
  for w in $ws; do
    gl_WARN_ADD([$w])
  done

  gl_WARN_ADD([-fdiagnostics-show-option])
fi

AC_SUBST([U2FS_VERSION_MAJOR],
	 `echo $PACKAGE_VERSION | sed 's/\(.*\)\..*\..*/\1/g'`)
AC_SUBST([U2FS_VERSION_MINOR],
	 `echo $PACKAGE_VERSION | sed 's/.*\.\(.*\)\..*/\1/g'`)
AC_SUBST([U2FS_VERSION_PATCH],
	 `echo $PACKAGE_VERSION | sed 's/.*\..*\.\(.*\)/\1/g'`)
AC_SUBST([U2FS_VERSION_NUMBER],
	 `printf "0x%02x%02x%02x" $U2FS_VERSION_MAJOR \
		 $U2FS_VERSION_MINOR $U2FS_VERSION_PATCH`)

AC_CONFIG_FILES([
  Makefile
  gtk-doc/Makefile
  src/Makefile
  u2f-server/Makefile
  u2f-server/u2f-server-version.h
  u2f-server/u2f-server.pc
])
if test '!' "$enable_tests" = no; then
  AC_CONFIG_FILES([
    tests/Makefile
  ])
fi
AC_OUTPUT

AC_MSG_NOTICE([summary of build options:

  Version:          ${VERSION} shared $LT_CURRENT:$LT_REVISION:$LT_AGE major $U2FS_VERSION_MAJOR minor $U2FS_VERSION_MINOR patch $U2FS_VERSION_PATCH number $U2FS_VERSION_NUMBER
  Host type:        ${host}
  Install prefix:   ${prefix}
  Compiler:         ${CC}
  Shared library:   ${enable_shared}
  Static library:   ${enable_static}
  CFLAGS:           ${CFLAGS}
  CPPFLAGS:         ${CPPFLAGS}
  JSON CFLAGS:      $LIBJSON_CFLAGS
  JSON LIBS:        $LIBJSON_LIBS
  OPENSSL CFLAGS:   $LIBSSL_CFLAGS
  OPENSSL LIBS:     $LIBSSL_LIBS
  LIBCRYPTO CFLAGS: $LIBCRYPTO_CFLAGS
  LIBCRYPTO LIBS:   $LIBCRYPTO_LIBS
  CHECK CFLAGS:     $CHECK_CFLAGS
  CHECK LIBS:       $CHECK_LIBS
])
