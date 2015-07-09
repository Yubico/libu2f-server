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

#include <check.h>

#define INVALID_ERROR_CODE 1
#define OOB_ERROR_CODE -100

START_TEST(test_version)
{
  ck_assert_msg(strcmp(U2FS_VERSION_STRING, u2fs_check_version(NULL)) == 0,
                "Was expecting version %s, but found version %s\n",
                U2FS_VERSION_STRING, u2fs_check_version(NULL));

  ck_assert_msg(u2fs_check_version(U2FS_VERSION_STRING) != NULL,
                "Version NULL?\n");

  ck_assert_msg(u2fs_check_version("99.99.99") == NULL,
                "Version not NULL?\n");

}

END_TEST START_TEST(test_utils)
{
  ck_assert_msg(u2fs_global_init(U2FS_DEBUG) == U2FS_OK,
                "u2fs_global_init rc %d\n, rc");

  ck_assert_msg(u2fs_strerror(U2FS_OK) != NULL, "u2fs_strerror NULL\n");

  ck_assert_msg(u2fs_strerror(INVALID_ERROR_CODE) != NULL,
                "u2fs_strerror NULL\n");

  ck_assert_msg(u2fs_strerror(OOB_ERROR_CODE) != NULL,
                "u2fs_strerror NULL\n");

  {
    const char *s;
    s = u2fs_strerror_name(U2FS_OK);
    ck_assert_msg(s != NULL
                  && strcmp(s, "U2FS_OK") == 0, "u2fs_strerror_name %s\n",
                  s);

  }
}

END_TEST START_TEST(test_init)
{

  u2fs_ctx_t *ctx;

  ck_assert_int_eq(u2fs_init(&ctx), U2FS_OK);

  u2fs_done(ctx);
  u2fs_global_done();

}

END_TEST Suite *basic_suite(void)
{
  Suite *s;
  TCase *tc_basic;

  s = suite_create("u2fs_basic");

  /* Basic test case */
  tc_basic = tcase_create("Basic");

  tcase_add_test(tc_basic, test_version);
  tcase_add_test(tc_basic, test_utils);
  tcase_add_test(tc_basic, test_init);

  suite_add_tcase(s, tc_basic);

  return s;
}


int main(void)
{
  int number_failed;
  Suite *s;
  SRunner *sr;

  s = basic_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_NORMAL);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
