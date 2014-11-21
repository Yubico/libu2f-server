#!/bin/sh

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

EXIT_SUCCESS=0
EXIT_FAILURE=99

MKTEMP="/bin/mktemp"
RM="/bin/rm"

ORIGIN="http://yubico.com"
APPID="http://yubico.com"
AUTH_PARAM="authenticate"
REGISTER_PARAM="register"

CHALLENGE1="TVgGf_GfMfVf4L2KiNmLdyIoR59ez4qtmLwwdG4-lkI"
REQUEST1="{ \"challenge\": \"TVgGf_GfMfVf4L2KiNmLdyIoR59ez4qtmLwwdG4-lkI\", \"version\": \"U2F_V2\", \"appId\": \"http:\/\/yubico.com\" }"
RESPONSE1=
"{ \"registrationData\": \"BQRjk4BrghuG1RR0nIzda230YhTj4iMpyFvZpRyZf37\
eKNAWPmcmPbsouRxw2NUj2Z0kPlbUIaFlAD88Ez_bGyzRQNaWpOywZ1-DkgpDiCnej_COz\
gsEwXO2Cgwyd2IZ_5wK7b4L85-T9DZHBtgNYnsxdYekFvDikKdd5TND-WVUn9cwggIbMII\
BBaADAgECAgR1o_Z1MAsGCSqGSIb3DQEBCzAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb\
3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDA\
wMFowKjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTk3MzY3OTczMzBZMBMGB\
yqGSM49AgEGCCqGSM49AwEHA0IABBmjfkNqa2mXzVh2ZxuES5coCvvENxDMDLmfd-0ACG0\
Fu7wR4ZTjKd9KAuidySpfona5csGmlM0Te_Zu35h_wwujEjAQMA4GCisGAQQBgsQKAQIEA\
DALBgkqhkiG9w0BAQsDggEBAb0tuI0-CzSxBg4cAlyD6UyT4cKyJZGVhWdtPgj_mWepT3T\
u9jXtdgA5F3jfZtTc2eGxuS-PPvqRAkZd40AXgM8A0YaXPwlT4s0RUTY9Y8aAQzQZeAHuZ\
k3lKKd_LUCg5077dzdt90lC5eVTEduj6cOnHEqnOr2Cv75FuiQXX7QkGQxtoD-otgvhZ2F\
jk29o7Iy9ik7ewHGXOfoVw_ruGWi0YfXBTuqEJ6H666vvMN4BZWHtzhC0k5ceQslB9Xdnt\
ky-GQgDqNkkBf32GKwAFT9JJrkO2BfsB-wfBrTiHr0AABYNTNKTceA5dtR3UVpI492VUWQ\
bY3YmWUUfKTI7fM4wRQIhAJnjtf2irhjgUbsdFUft-38T4d70e7DhsynVR_cy7Y2ZAiByN\
798SHtk61WmSsGcQ9e7hUW3OKxYGjgvKAwEMDHuKQ==\", \"clientData\": \"eyAiY\
2hhbGxlbmdlIjogIlRWZ0dmX0dmTWZWZjRMMktpTm1MZHlJb1I1OWV6NHF0bUx3d2RHNC1\
sa0kiLCAib3JpZ2luIjogImh0dHA6XC9cL3l1Ymljby5jb20iLCAidHlwIjogIm5hdmlnY\
XRvci5pZC5maW5pc2hFbnJvbGxtZW50IiB9\" }"

run_simple() {
    $USFSBIN $1
}

KEYFILE=$($MKTEMP)
USERFILE=$($MKTEMP)
$U2FSBIN -a$AUTH_PARAM -c$CHALLENGE1 -u$USERFILE -k$KEYFILE
expect ""
send "$RESPONSE1"
if [ $? -eq 0 ]; then
    echo "YAY"
else
    echo "NAY"
fi
$($RM $KEYFILE)
$($RM $USERFILE)

echo $EXIT_FAILURE $EXIT_SUCCESS

exit $EXIT_SUCCESS
