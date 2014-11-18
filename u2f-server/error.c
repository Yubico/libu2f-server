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

#include <u2f-server/u2f-server.h>

#define ERR(name, desc) { name, #name, desc }

typedef struct {
  int rc;
  const char *name;
  const char *description;
} err_t;

static const err_t errors[] = {
  ERR(U2FS_OK, "Successful return"),
  ERR(U2FS_MEMORY_ERROR, "Memory error (e.g., out of memory)"),
  ERR(U2FS_JSON_ERROR, "Error in JSON handling"),
  ERR(U2FS_BASE64_ERROR, "Base64 error"),
  ERR(U2FS_CRYPTO_ERROR, "Crypto error"),
  ERR(U2FS_ORIGIN_ERROR, "Origin mismatch"),
  ERR(U2FS_CHALLENGE_ERROR, "Challenge error"),
  ERR(U2FS_SIGNATURE_ERROR, "Unable to verify signature"),
  ERR(U2FS_FORMAT_ERROR, "Format mismatch")
};

/**
 * u2fs_strerror:
 * @err: error code
 *
 * Convert return code to human readable string explanation of the
 * reason for the particular error code.
 *
 * This string can be used to output a diagnostic message to the user.
 *
 * This function is one of few in the library that can be used without
 * a successful call to u2fs_global_init().
 *
 * Return value: Returns a pointer to a statically allocated string
 *   containing an explanation of the error code @err.
 **/
const char *u2fs_strerror(int err)
{
  static const char *unknown = "Unknown libu2f-server error";
  const char *p;

  if (-err < 0 || -err >= (int) (sizeof(errors) / sizeof(errors[0])))
    return unknown;

  p = errors[-err].description;
  if (!p)
    p = unknown;

  return p;
}

/**
 * u2fs_strerror_name:
 * @err: error code
 *
 * Convert return code to human readable string representing the error
 * code symbol itself.  For example, u2fs_strerror_name(%U2FS_OK)
 * returns the string "U2FS_OK".
 *
 * This string can be used to output a diagnostic message to the user.
 *
 * This function is one of few in the library that can be used without
 * a successful call to u2fs_global_init().
 *
 * Return value: Returns a pointer to a statically allocated string
 *   containing a string version of the error code @err, or NULL if
 *   the error code is not known.
 **/
const char *u2fs_strerror_name(int err)
{
  if (-err < 0 || -err >= (int) (sizeof(errors) / sizeof(errors[0])))
    return NULL;

  return errors[-err].name;
}
