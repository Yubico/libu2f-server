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

AM_CFLAGS = $(WARN_CFLAGS)
AM_CPPFLAGS = -I$(srcdir)/.. -I$(builddir)/..
AM_CPPFLAGS += $(LIBJSON_CFLAGS) $(LIBSSL_CFLAGS) $(LIBCRYPTO_CFLAGS)

lib_LTLIBRARIES = libu2f-server.la
u2f_server_includedir = $(includedir)/u2f-server
u2f_server_include_HEADERS = u2f-server.h u2f-server-version.h

libu2f_server_la_SOURCES = u2f-server.h u2f-server-version.h
libu2f_server_la_SOURCES += internal.h
libu2f_server_la_SOURCES += u2f-server.pc.in u2f-server.map
libu2f_server_la_SOURCES += global.c version.c error.c
libu2f_server_la_SOURCES += core.c
libu2f_server_la_SOURCES += sha256.h sha256.c
libu2f_server_la_SOURCES += cencode.c cdecode.c b64/cencode.h b64/cdecode.h
libu2f_server_la_SOURCES += crypto.h
libu2f_server_la_SOURCES += openssl.c

libu2f_server_la_LIBADD = $(HIDAPI_LIBS) $(LIBJSON_LIBS) $(LIBSSL_LIBS) $(LIBCRYPTO_LIBS)

libu2f_server_la_LDFLAGS = -no-undefined \
	-version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

if HAVE_LD_VERSION_SCRIPT
libu2f_server_la_LDFLAGS += -Wl,--version-script=$(srcdir)/u2f-server.map
else
libu2f_server_la_LDFLAGS += -export-symbols-regex '^u2fs_.*'
endif

if ENABLE_COV
AM_CFLAGS += --coverage
AM_LDFLAGS = --coverage
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = u2f-server.pc
