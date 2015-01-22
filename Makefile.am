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

SUBDIRS = u2f-server src tests gtk-doc

ACLOCAL_AMFLAGS = -I m4

DISTCHECK_CONFIGURE_FLAGS = --enable-gtk-doc

if ENABLE_COV
cov-reset:
	rm -fr coverage
	find . -name "*.gcda" -exec rm {} \;
	lcov --directory . --zerocounters

cov-report:
	mkdir -p coverage
	lcov --compat-libtool --directory . --capture --output-file coverage/app.info
	lcov --extract coverage/app.info '*.c' --output-file coverage/app2.info
	lcov --remove coverage/app2.info cmdline.c --output-file coverage/app3.info
	genhtml -o coverage/ coverage/app3.info

cov:
	make cov-report

clean-local:
	make cov-reset

check:
	make cov
endif

# Release

indent:
	indent -kr -nut -i2 */*.c */*.h */*.h.in
	indent -kr -nut -i2 */*.c */*.h */*.h.in

ChangeLog:
	cd $(srcdir) && git2cl > ChangeLog

release:
	@if test ! -d "$(YUBICO_WWW_REPO)"; then \
		echo "www repo not found!"; \
		echo "Make sure that YUBICO_WWW_REPO is set"; \
		exit 1; \
	fi
	@if test -z "$(KEYID)"; then \
		echo "Try this instead:"; \
		echo "  make release KEYID=[PGPKEYID]"; \
		echo "For example:"; \
		echo "  make release KEYID=2117364A"; \
		exit 1; \
	fi
	@head -3 $(srcdir)/NEWS | \
		grep -q "Version $(VERSION) .released `date -I`" || \
		(echo 'error: You need to update date/version in $(srcdir)/NEWS'; exit 1)
	rm -f $(srcdir)/ChangeLog
	make ChangeLog distcheck
	gpg --detach-sign --default-key $(KEYID) $(PACKAGE)-$(VERSION).tar.xz
	gpg --verify $(PACKAGE)-$(VERSION).tar.xz.sig
	cd $(srcdir) && git push
	cd $(srcdir) && git tag -u $(KEYID) -m $(VERSION) $(PACKAGE)-$(VERSION)
	cd $(srcdir) && git push --tags
	$(YUBICO_WWW_REPO)/publish $(PACKAGE) $(VERSION) $(PACKAGE)-$(VERSION).tar.xz*
