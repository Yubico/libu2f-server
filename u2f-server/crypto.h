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

#ifndef U2FS_CRYPTO_H
#define U2FS_CRYPTO_H

#include "internal.h"

void dumpCert(const u2fs_X509_t * certificate);

void crypto_init(void);
void crypto_release(void);

void free_key(u2fs_EC_KEY_t * key);
void free_cert(u2fs_X509_t * cert);
void free_sig(u2fs_ECDSA_t * sig);


u2fs_rc set_random_bytes(char *data, size_t len);

u2fs_rc decode_X509(const char *data, size_t len, u2fs_X509_t ** cert);
u2fs_rc decode_ECDSA(const char *data, size_t len, u2fs_ECDSA_t ** sig);
u2fs_rc decode_user_key(const char *data, u2fs_EC_KEY_t ** key);

u2fs_rc verify_ECDSA(const unsigned char *dgst, int dgst_len,
                     const u2fs_ECDSA_t * sig, u2fs_EC_KEY_t * eckey);

u2fs_rc extract_EC_KEY_from_X509(const u2fs_X509_t * cert,
                                 u2fs_EC_KEY_t ** key);
u2fs_EC_KEY_t *dup_key(const u2fs_EC_KEY_t * key);
u2fs_X509_t *dup_cert(const u2fs_X509_t * cert);

u2fs_rc dump_user_key(const u2fs_EC_KEY_t * key, char **output);

#endif
