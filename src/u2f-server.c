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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>

#include "cmdline.h"

int main(int argc, char *argv[])
{
  int exit_code = EXIT_FAILURE;
  struct gengetopt_args_info args_info;
  char buf[BUFSIZ];
  char *p;
  u2fs_ctx_t *ctx;
  u2fs_reg_res_t *reg_result;
  u2fs_auth_res_t *auth_result;
  u2fs_rc rc;
  if (cmdline_parser(argc, argv, &args_info) != 0)
    exit(EXIT_FAILURE);
  if (args_info.help_given) {
    cmdline_parser_print_help();
    printf
        ("\nReport bugs at <https://github.com/Yubico/libu2f-server>.\n");
    exit(EXIT_SUCCESS);
  }

  if (!args_info.origin_given) {
    printf("error: An origin must be specified with -o\n");
    exit(EXIT_FAILURE);
  } else if (strncmp("http://", args_info.origin_arg, 7) != 0
             && strncmp("https://", args_info.origin_arg, 8) != 0) {
    fprintf(stderr, "error: origin must be http or https\n");
    exit(EXIT_FAILURE);
  }

  if (!args_info.appid_given) {
    printf("error: An appId must be specified with -i\n");
    exit(EXIT_FAILURE);
  }

  if (args_info.challenge_arg
      && strlen(args_info.challenge_arg) != U2FS_CHALLENGE_B64U_LEN) {
    fprintf(stderr, "warning: challenge should be %d characters long\n",
            U2FS_CHALLENGE_B64U_LEN);
    exit(EXIT_FAILURE);
  }
  rc = u2fs_global_init(args_info.debug_flag ? U2FS_DEBUG : 0);
  if (rc != U2FS_OK) {
    printf("error: u2fs_global_init (%d): %s\n", rc, u2fs_strerror(rc));
    exit(EXIT_FAILURE);
  }
  rc = u2fs_init(&ctx);
  if (rc != U2FS_OK) {
    printf("error: u2fs_init (%d): %s\n", rc, u2fs_strerror(rc));
    exit(EXIT_FAILURE);
  }
  if (args_info.action_arg == action_arg_authenticate) {
    if (!args_info.key_handle_given) {
      printf("error: Authentication action requires a key-handle\n");
      exit(EXIT_FAILURE);
    } else {
      FILE *fp;
      if ((fp = fopen(args_info.key_handle_arg, "rb")) == NULL) {
        perror("open");
        exit(EXIT_FAILURE);
      }

      if (fread(buf, sizeof(char), BUFSIZ, fp) == 0) {
        perror("read");
        exit(EXIT_FAILURE);
      }
      fclose(fp);
    }
    rc = u2fs_set_keyHandle(ctx, buf);
    if (rc != U2FS_OK) {
      printf("error: u2fs_set_keyHandle (%d): %s\n", rc,
             u2fs_strerror(rc));
      exit(EXIT_FAILURE);
    }
  }

  if (args_info.action_arg == action_arg_authenticate) {
    if (!args_info.user_key_given) {
      printf("error: Authentication action requires a user-key\n");
      exit(EXIT_FAILURE);
    } else {
      FILE *fp;
      if ((fp = fopen(args_info.user_key_arg, "rb")) == NULL) {
        perror("open");
        exit(EXIT_FAILURE);
      }

      if (fread(buf, sizeof(char), BUFSIZ, fp) == 0) {
        perror("read");
        exit(EXIT_FAILURE);
      }
      fclose(fp);
    }

    rc = u2fs_set_publicKey(ctx, (unsigned char *) buf);
    if (rc != U2FS_OK) {
      printf("error: u2fs_set_publicKey (%d): %s\n", rc,
             u2fs_strerror(rc));
      exit(EXIT_FAILURE);
    }
  }

  rc = u2fs_set_origin(ctx, args_info.origin_arg);
  if (rc != U2FS_OK) {
    printf("error: u2fs_set_origin (%d): %s\n", rc, u2fs_strerror(rc));
    exit(EXIT_FAILURE);
  }

  rc = u2fs_set_appid(ctx, args_info.appid_arg);
  if (rc != U2FS_OK) {
    printf("error: u2fs_set_appid (%d): %s\n", rc, u2fs_strerror(rc));
    exit(EXIT_FAILURE);
  }

  if (args_info.challenge_arg) {
    rc = u2fs_set_challenge(ctx, args_info.challenge_arg);
    if (rc != U2FS_OK) {
      printf("error: u2fs_set_challenge (%d): %s\n", rc,
             u2fs_strerror(rc));
      exit(EXIT_FAILURE);
    }
  }
  switch (args_info.action_arg) {
  case action_arg_register:
    rc = u2fs_registration_challenge(ctx, &p);
    break;
  case action_arg_authenticate:
    rc = u2fs_authentication_challenge(ctx, &p);
    break;
  case action__NULL:
  default:
    printf("error: unknown action.\n");
    goto done;
  }
  if (rc != U2FS_OK) {
    printf("error (%d): %s\n", rc, u2fs_strerror(rc));
    goto done;
  }
  printf("%s\n", p);
  if (fread(buf, 1, sizeof(buf), stdin) == 0 || !feof(stdin)
      || ferror(stdin)) {
    perror("read");
    exit(EXIT_FAILURE);
  }
  switch (args_info.action_arg) {
  case action_arg_register:
    rc = u2fs_registration_verify(ctx, buf, &reg_result);

    if (rc == U2FS_OK)
      printf("Registration successful\n");
    else {
      printf("error: (%d) %s\n", rc, u2fs_strerror(rc));
      exit(EXIT_FAILURE);
    }
      

    if (args_info.key_handle_given) {
      FILE *fp;
      if ((fp = fopen(args_info.key_handle_arg, "wb")) == NULL) {
        perror("open");
        exit(EXIT_FAILURE);
      }
      if (fwrite
          (u2fs_get_registration_keyHandle(reg_result), sizeof(char),
           strlen(u2fs_get_registration_keyHandle(reg_result)),
           fp) != strlen(u2fs_get_registration_keyHandle(reg_result))) {
        perror("write");
        exit(EXIT_FAILURE);
      }
      fclose(fp);
    } else {
      printf("KeyHandle not saved!. Rerun with -k\n");
    }

    if (rc == U2FS_OK && args_info.user_key_given) {
      FILE *fp;
      const char *k = u2fs_get_registration_publicKey(reg_result);

      if ((fp = fopen(args_info.user_key_arg, "wb")) == NULL) {
        perror("open");
        exit(EXIT_FAILURE);
      }

      if (fwrite(k, sizeof(unsigned char), U2FS_PUBLIC_KEY_LEN, fp) !=
          U2FS_PUBLIC_KEY_LEN) {
        perror("write");
        exit(EXIT_FAILURE);
      }

      fclose(fp);
    } else {
      printf("User key not saved!. Rerun with -p\n");
    }
    break;
  case action_arg_authenticate:
    rc = u2fs_authentication_verify(ctx, buf, &auth_result);
    if (rc == U2FS_OK) {
      u2fs_rc verified;
      uint32_t counter;
      uint8_t user_presence;
      rc = u2fs_get_authentication_result(auth_result, &verified, &counter,
                                          &user_presence);
      if (verified == U2FS_OK) {
        printf
            ("Successful authentication, counter: %d, user presence %d\n",
             counter, user_presence);
      } else
        printf("Authentication failed: %s\n", u2fs_strerror(rc));
    } else if (rc != U2FS_OK) {
      printf("error: u2fs_authentication_verify (%d): %s\n", rc,
             u2fs_strerror(rc));
      exit(EXIT_FAILURE);
    }
    break;
  case action__NULL:
  default:
    printf("error: unknown action.\n");
    goto done;
  }
  if (rc != U2FS_OK) {
    printf("error (%d): %s\n", rc, u2fs_strerror(rc));
    goto done;
  }
  exit_code = EXIT_SUCCESS;
done:u2fs_done(ctx);
  u2fs_global_done();
  exit(exit_code);
}
