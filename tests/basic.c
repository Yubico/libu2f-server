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

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
  int rc;
  u2fs_ctx_t *ctx;

  if (strcmp(U2FS_VERSION_STRING, u2fs_check_version(NULL)) != 0) {
    printf("version mismatch %s != %s\n", U2FS_VERSION_STRING,
           u2fs_check_version(NULL));
    return EXIT_FAILURE;
  }

  if (u2fs_check_version(U2FS_VERSION_STRING) == NULL) {
    printf("version NULL?\n");
    return EXIT_FAILURE;
  }

  if (u2fs_check_version("99.99.99") != NULL) {
    printf("version not NULL?\n");
    return EXIT_FAILURE;
  }

  printf("u2fs version: header %s library %s\n", U2FS_VERSION_STRING,
         u2fs_check_version(NULL));

  rc = u2fs_global_init(0);
  if (rc != U2FS_OK) {
    printf("u2fs_global_init rc %d\n", rc);
    return EXIT_FAILURE;
  }

  if (u2fs_strerror(U2FS_OK) == NULL) {
    printf("u2fs_strerror NULL\n");
    return EXIT_FAILURE;
  }

  {
    const char *s;
    s = u2fs_strerror_name(U2FS_OK);
    if (s == NULL || strcmp(s, "U2FS_OK") != 0) {
      printf("u2fs_strerror_name %s\n", s);
      return EXIT_FAILURE;
    }
  }

  rc = u2fs_init(&ctx);

  /* XXX */

  u2fs_done(ctx);

  u2fs_global_done();

  return EXIT_SUCCESS;
}
