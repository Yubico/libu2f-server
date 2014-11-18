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

#ifndef U2F_SERVER_H
#define U2F_SERVER_H

#include <stdint.h>
#include <string.h>

#include <u2f-server/u2f-server-version.h>

#ifdef __cplusplus
extern "C" {
#endif

#define U2FS_CHALLENGE_RAW_LEN 32
#define U2FS_CHALLENGE_B64U_LEN 43
#define U2FS_PUBLIC_KEY_LEN 65
#define U2FS_COUNTER_LEN 4

/**
 * u2fs_rc:
 * @U2FS_OK: Success.
 * @U2FS_MEMORY_ERROR: Memory error.
 * @U2FS_JSON_ERROR: Json error.
 * @U2FS_BASE64_ERROR: Base64 error.
 * @U2FS_CRYPTO_ERROR: Cryptographic error.
 * @U2FS_ORIGIN_ERROR: Origin mismatch.
 * @U2FS_CHALLENGE_ERROR: Challenge error.
 * @U2FS_SIGNATURE_ERROR: Signature mismatch.
 * @U2FS_FORMAT_ERROR: Message format error.
 *
 * Error codes.
 */
  typedef enum {
    U2FS_OK = 0,
    U2FS_MEMORY_ERROR = -1,
    U2FS_JSON_ERROR = -2,
    U2FS_BASE64_ERROR = -3,
    U2FS_CRYPTO_ERROR = -4,
    U2FS_ORIGIN_ERROR = -5,
    U2FS_CHALLENGE_ERROR = -6,
    U2FS_SIGNATURE_ERROR = -7,
    U2FS_FORMAT_ERROR = -8
  } u2fs_rc;

/**
 * u2fs_initflags:
 * @U2FS_DEBUG: Print debug messages.
 *
 * Flags passed to u2fs_global_init().
 */
  typedef enum {
    U2FS_DEBUG = 1
  } u2fs_initflags;

  typedef struct u2fs_ctx u2fs_ctx_t;
  typedef struct u2fs_reg_res u2fs_reg_res_t;
  typedef struct u2fs_auth_res u2fs_auth_res_t;

/* Must be called successfully before using any other functions. */
  u2fs_rc u2fs_global_init(u2fs_initflags flags);
  void u2fs_global_done(void);

/* Error handling */
  const char *u2fs_strerror(int err);
  const char *u2fs_strerror_name(int err);

/* Create context before registration/authentication calls. */

  u2fs_rc u2fs_init(u2fs_ctx_t ** ctx);
  void u2fs_done(u2fs_ctx_t * ctx);
  u2fs_rc u2fs_set_origin(u2fs_ctx_t * ctx, const char *origin);
  u2fs_rc u2fs_set_appid(u2fs_ctx_t * ctx, const char *appid);
  u2fs_rc u2fs_set_challenge(u2fs_ctx_t * ctx, const char *challenge);
  u2fs_rc u2fs_set_keyHandle(u2fs_ctx_t * ctx, const char *keyHandle);
  u2fs_rc u2fs_set_publicKey(u2fs_ctx_t * ctx,
                             const unsigned char *publicKey);

/* U2F Registration functions */

  u2fs_rc u2fs_registration_challenge(u2fs_ctx_t * ctx, char **output);
  u2fs_rc u2fs_registration_verify(u2fs_ctx_t * ctx, const char *response,
                                   u2fs_reg_res_t ** output);

  const char *u2fs_get_registration_keyHandle(u2fs_reg_res_t * result);
  const char *u2fs_get_registration_publicKey(u2fs_reg_res_t * result);

  void u2fs_free_reg_res(u2fs_reg_res_t * result);

/* U2F Authentication functions */

  u2fs_rc u2fs_authentication_challenge(u2fs_ctx_t * ctx, char **output);
  u2fs_rc u2fs_authentication_verify(u2fs_ctx_t * ctx,
                                     const char *response,
                                     u2fs_auth_res_t ** output);

  u2fs_rc u2fs_get_authentication_result(u2fs_auth_res_t * result,
                                         u2fs_rc * verified,
                                         uint32_t * counter,
                                         uint8_t * user_presence);

  void u2fs_free_auth_res(u2fs_auth_res_t * result);

#ifdef __cplusplus
}
#endif
#endif
