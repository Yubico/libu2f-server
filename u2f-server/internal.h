/*
* Copyright (c) 2014 Yubico AB
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are
* met:
*
* * Redistributions of source code must retain the above copyright
* notice, this list of conditions and the following disclaimer.
*
* * Redistributions in binary form must reproduce the above
* copyright notice, this list of conditions and the following
* disclaimer in the documentation and/or other materials provided
* with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
* OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef INTERNAL_H
#define INTERNAL_H

#include <u2f-server/u2f-server.h>
#include <stdio.h>
#include <stdlib.h>

typedef void *u2fs_ECDSA_t;
typedef void *u2fs_X509_t;
typedef void *u2fs_EC_KEY_t;

extern int debug;

#define _SHA256_LEN 32
#define _B64_BUFSIZE 2048

#define U2F_VERSION "U2F_V2"
#define U2FS_HASH_LEN _SHA256_LEN

struct u2fs_reg_res {
  char *keyHandle;
  char *publicKey;
  char *attestation_certificate_PEM;
  u2fs_EC_KEY_t *user_public_key;
  u2fs_X509_t *attestation_certificate;
};

struct u2fs_auth_res {
  int verified;
  uint32_t counter;
  uint8_t user_presence;
};

struct u2fs_ctx {
  char challenge[U2FS_CHALLENGE_B64U_LEN + 1];
  char *keyHandle;
  u2fs_EC_KEY_t *key;
  char *origin;
  char *appid;
};

#endif
