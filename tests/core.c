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
#include <u2f-server/internal.h>
#include <check.h>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

START_TEST(test_create)
{

  u2fs_ctx_t *ctx;

  ck_assert_int_eq(u2fs_global_init(U2FS_DEBUG), U2FS_OK);
  ck_assert_int_eq(u2fs_init(&ctx), U2FS_OK);

  u2fs_done(ctx);
  u2fs_global_done();

}

END_TEST START_TEST(set_challenge)
{

  u2fs_ctx_t *ctx;

  ck_assert_int_eq(u2fs_global_init(U2FS_DEBUG), U2FS_OK);
  ck_assert_int_eq(u2fs_init(&ctx), U2FS_OK);

  ck_assert_int_eq(u2fs_set_challenge(ctx, ""), U2FS_CHALLENGE_ERROR);
  ck_assert_int_eq(u2fs_set_challenge(ctx, NULL), U2FS_MEMORY_ERROR);
  ck_assert_int_eq(u2fs_set_challenge
                   (ctx, "dDwRsjdFoPHZ5Qg2fHQsFba0NKl-F1hxjJ3uLLk5gbA"),
                   U2FS_OK);
  ck_assert_str_eq(ctx->challenge,
                   "dDwRsjdFoPHZ5Qg2fHQsFba0NKl-F1hxjJ3uLLk5gbA");

  ck_assert_int_eq(strlen(ctx->challenge), U2FS_CHALLENGE_B64U_LEN);
  char *s = strdup(ctx->challenge);
  u2fs_done(ctx);
  ck_assert_int_eq(u2fs_init(&ctx), U2FS_OK);
  ck_assert_int_eq(strlen(ctx->challenge), U2FS_CHALLENGE_B64U_LEN);
  ck_assert_str_ne(ctx->challenge, s);

  free(s);
  s = NULL;

  u2fs_done(ctx);
  u2fs_global_done();

}

END_TEST START_TEST(set_keyhandle)
{

  u2fs_ctx_t *ctx;

  ck_assert_int_eq(u2fs_global_init(U2FS_DEBUG), U2FS_OK);
  ck_assert_int_eq(u2fs_init(&ctx), U2FS_OK);

  ck_assert_int_eq(u2fs_set_keyHandle(ctx, NULL), U2FS_MEMORY_ERROR);
  ck_assert_int_eq(u2fs_set_keyHandle
                   (ctx,
                    "kAbb2p57pxHg2mY8y_Kgcdc7jnnAoncJm8vOgqfigyWTvPGFlvxA04ULD9IJ-KpSyn733LRbJ-CG573N9jCY1g"),
                   U2FS_OK);
  ck_assert_str_eq(ctx->keyHandle,
                   "kAbb2p57pxHg2mY8y_Kgcdc7jnnAoncJm8vOgqfigyWTvPGFlvxA04ULD9IJ-KpSyn733LRbJ-CG573N9jCY1g");

  u2fs_done(ctx);
  u2fs_global_done();

}

END_TEST START_TEST(set_origin)
{

  u2fs_ctx_t *ctx;

  ck_assert_int_eq(u2fs_global_init(U2FS_DEBUG), U2FS_OK);
  ck_assert_int_eq(u2fs_init(&ctx), U2FS_OK);

  ck_assert_int_eq(u2fs_set_origin(ctx, NULL), U2FS_MEMORY_ERROR);
  ck_assert_int_eq(u2fs_set_origin(ctx, "http://example.com"), U2FS_OK);
  ck_assert_str_eq(ctx->origin, "http://example.com");
  ck_assert_int_eq(u2fs_set_origin(ctx, "https://test.org"), U2FS_OK);
  ck_assert_str_eq(ctx->origin, "https://test.org");

  u2fs_done(ctx);
  u2fs_global_done();

}

END_TEST START_TEST(set_appid)
{

  u2fs_ctx_t *ctx;

  ck_assert_int_eq(u2fs_global_init(U2FS_DEBUG), U2FS_OK);
  ck_assert_int_eq(u2fs_init(&ctx), U2FS_OK);

  ck_assert_int_eq(u2fs_set_appid(ctx, NULL), U2FS_MEMORY_ERROR);
  ck_assert_int_eq(u2fs_set_appid(ctx, "http://example.com"), U2FS_OK);
  ck_assert_str_eq(ctx->appid, "http://example.com");
  ck_assert_int_eq(u2fs_set_appid(ctx, "https://test.org"), U2FS_OK);
  ck_assert_str_eq(ctx->appid, "https://test.org");

  u2fs_done(ctx);
  u2fs_global_done();

}

END_TEST START_TEST(set_publicKey)
{

  u2fs_ctx_t *ctx;
  unsigned char userkey_dat[] = {
    0x04, 0x14, 0xc3, 0x2e, 0x41, 0x0b, 0x30, 0x9d, 0x6e, 0x93, 0x7f, 0x8b,
    0x5d, 0x81, 0xf9, 0xe5, 0x64, 0xfd, 0x11, 0x2c, 0xe5, 0xfe, 0xf0, 0x10,
    0x5e, 0xfb, 0xec, 0xd5, 0x55, 0x54, 0x52, 0x25, 0x25, 0xe4, 0x54, 0x29,
    0x0f, 0xf4, 0x2e, 0xa1, 0xd8, 0x77, 0x19, 0x36, 0x12, 0xe3, 0x6e, 0x39,
    0x17, 0x91, 0x24, 0xb5, 0x93, 0x8e, 0xe0, 0xfe, 0xf3, 0x69, 0xac, 0xb9,
    0x4c, 0x37, 0x97, 0x83, 0xcb, 0x15, 0x40
  };

  ck_assert_int_eq(u2fs_global_init(U2FS_DEBUG), U2FS_OK);
  ck_assert_int_eq(u2fs_init(&ctx), U2FS_OK);
  ck_assert_int_eq(u2fs_set_publicKey(ctx, userkey_dat), U2FS_OK);
  /* TODO: how to check it was imported ok? This test is now a bit silly. */

  u2fs_done(ctx);
  u2fs_global_done();

}

END_TEST START_TEST(registration_verify_ok)
{

  u2fs_ctx_t *ctx;

  char *reg_response =
      "{ \"registrationData\": \"BQRcbdE4PHGRaJUTK9hY4GrX_jZa5eWgjJK6\
    IfwezrndHvQi7QQtYA2qAg4NrebNkSCoOwJ0V1PzLlP1Wr_Oku_0QKfeNR0Ei4_\
    I40GCo5xjm4Q7hnZwzXQ5f5vjtnx7xIqCZ-z7GOGExeouBXxaMgleYpX7xMR6Y9\
    wa_qzLLTAr6IcwggIbMIIBBaADAgECAgR1o_Z1MAsGCSqGSIb3DQEBCzAuMSwwK\
    gYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0x\
    NDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowKjEoMCYGA1UEAwwfWXViaWN\
    vIFUyRiBFRSBTZXJpYWwgMTk3MzY3OTczMzBZMBMGByqGSM49AgEGCCqGSM49Aw\
    EHA0IABBmjfkNqa2mXzVh2ZxuES5coCvvENxDMDLmfd-0ACG0Fu7wR4ZTjKd9KA\
    uidySpfona5csGmlM0Te_Zu35h_wwujEjAQMA4GCisGAQQBgsQKAQIEADALBgkq\
    hkiG9w0BAQsDggEBAb0tuI0-CzSxBg4cAlyD6UyT4cKyJZGVhWdtPgj_mWepT3T\
    u9jXtdgA5F3jfZtTc2eGxuS-PPvqRAkZd40AXgM8A0YaXPwlT4s0RUTY9Y8aAQz\
    QZeAHuZk3lKKd_LUCg5077dzdt90lC5eVTEduj6cOnHEqnOr2Cv75FuiQXX7QkG\
    QxtoD-otgvhZ2Fjk29o7Iy9ik7ewHGXOfoVw_ruGWi0YfXBTuqEJ6H666vvMN4B\
    ZWHtzhC0k5ceQslB9Xdntky-GQgDqNkkBf32GKwAFT9JJrkO2BfsB-wfBrTiHr0\
    AABYNTNKTceA5dtR3UVpI492VUWQbY3YmWUUfKTI7fM4wRQIhAN3c-VHubCCkUt\
    ZXfWL1aiEXU1qWRiM_ayKmWLUafyFbAiARTwlVocoamd9S-cYBosRKso_XGAPzA\
    edzpuE2tEjp1g==\", \"clientData\": \"eyAiY2hhbGxlbmdlIjogIllTMT\
    ludV9ZWWpnczI5WndrU3dRb2JyNzhPaURXRnoxeXFZZW85WUpmQnciLCAib3JpZ\
    2luIjogImh0dHA6XC9cL2RlbW8ueXViaWNvLmNvbSIsICJ0eXAiOiAibmF2aWdh\
    dG9yLmlkLmZpbmlzaEVucm9sbG1lbnQiIH0=\" }";

  u2fs_reg_res_t *res = NULL;;
  const char *p;

  unsigned char userkey_dat[] = {
    0x04, 0x5c, 0x6d, 0xd1, 0x38, 0x3c, 0x71, 0x91, 0x68, 0x95, 0x13, 0x2b,
    0xd8, 0x58, 0xe0, 0x6a, 0xd7, 0xfe, 0x36, 0x5a, 0xe5, 0xe5, 0xa0,
    0x8c, 0x92, 0xba, 0x21, 0xfc, 0x1e, 0xce, 0xb9, 0xdd, 0x1e, 0xf4,
    0x22, 0xed, 0x04, 0x2d, 0x60, 0x0d, 0xaa, 0x02, 0x0e, 0x0d, 0xad,
    0xe6, 0xcd, 0x91, 0x20, 0xa8, 0x3b, 0x02, 0x74, 0x57, 0x53, 0xf3,
    0x2e, 0x53, 0xf5, 0x5a, 0xbf, 0xce, 0x92, 0xef, 0xf4
  };

  ck_assert_int_eq(u2fs_global_init(U2FS_DEBUG), U2FS_OK);
  ck_assert_int_eq(u2fs_init(&ctx), U2FS_OK);
  ck_assert_int_eq(u2fs_set_appid(ctx, "http://demo.yubico.com"), U2FS_OK);
  ck_assert_int_eq(u2fs_set_origin(ctx, "http://demo.yubico.com"),
                   U2FS_OK);
  ck_assert_int_eq(u2fs_set_challenge
                   (ctx, "YS19nu_YYjgs29ZwkSwQobr78OiDWFz1yqYeo9YJfBw"),
                   U2FS_OK);
  ck_assert_int_eq(u2fs_registration_verify(ctx, reg_response, &res),
                   U2FS_OK);

  ck_assert_str_eq(u2fs_get_registration_keyHandle(res),
                   "p941HQSLj8jjQYKjnGObhDuGdnDNdDl_m-O2fHvEioJn7PsY4YT"
                   "F6i4FfFoyCV5ilfvExHpj3Br-rMstMCvohw");

  p = u2fs_get_registration_publicKey(res);
  ck_assert_int_eq(memcmp(p, userkey_dat, U2FS_PUBLIC_KEY_LEN), 0);

  u2fs_free_reg_res(res);
  u2fs_done(ctx);
  u2fs_global_done();

}

END_TEST START_TEST(registration_challenge_error)
{

  u2fs_ctx_t *ctx;

  char *reg_response =
      "{ \"registrationData\": \"BQRcbdE4PHGRaJUTK9hY4GrX_jZa5eWgjJK6\
    IfwezrndHvQi7QQtYA2qAg4NrebNkSCoOwJ0V1PzLlP1Wr_Oku_0QKfeNR0Ei4_\
    I40GCo5xjm4Q7hnZwzXQ5f5vjtnx7xIqCZ-z7GOGExeouBXxaMgleYpX7xMR6Y9\
    wa_qzLLTAr6IcwggIbMIIBBaADAgECAgR1o_Z1MAsGCSqGSIb3DQEBCzAuMSwwK\
    gYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0x\
    NDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowKjEoMCYGA1UEAwwfWXViaWN\
    vIFUyRiBFRSBTZXJpYWwgMTk3MzY3OTczMzBZMBMGByqGSM49AgEGCCqGSM49Aw\
    EHA0IABBmjfkNqa2mXzVh2ZxuES5coCvvENxDMDLmfd-0ACG0Fu7wR4ZTjKd9KA\
    uidySpfona5csGmlM0Te_Zu35h_wwujEjAQMA4GCisGAQQBgsQKAQIEADALBgkq\
    hkiG9w0BAQsDggEBAb0tuI0-CzSxBg4cAlyD6UyT4cKyJZGVhWdtPgj_mWepT3T\
    u9jXtdgA5F3jfZtTc2eGxuS-PPvqRAkZd40AXgM8A0YaXPwlT4s0RUTY9Y8aAQz\
    QZeAHuZk3lKKd_LUCg5077dzdt90lC5eVTEduj6cOnHEqnOr2Cv75FuiQXX7QkG\
    QxtoD-otgvhZ2Fjk29o7Iy9ik7ewHGXOfoVw_ruGWi0YfXBTuqEJ6H666vvMN4B\
    ZWHtzhC0k5ceQslB9Xdntky-GQgDqNkkBf32GKwAFT9JJrkO2BfsB-wfBrTiHr0\
    AABYNTNKTceA5dtR3UVpI492VUWQbY3YmWUUfKTI7fM4wRQIhAN3c-VHubCCkUt\
    ZXfWL1aiEXU1qWRiM_ayKmWLUafyFbAiARTwlVocoamd9S-cYBosRKso_XGAPzA\
    edzpuE2tEjp1g==\", \"clientData\": \"eyAiY2hhbGxlbmdlIjogIllTMT\
    ludV9ZWWpnczI5WndrU3dRb2JyNzhPaURXRnoxeXFZZW85WUpmQnciLCAib3JpZ\
    2luIjogImh0dHA6XC9cL2RlbW8ueXViaWNvLmNvbSIsICJ0eXAiOiAibmF2aWdh\
    dG9yLmlkLmZpbmlzaEVucm9sbG1lbnQiIH0=\" }";

  u2fs_reg_res_t *res = NULL;;

  ck_assert_int_eq(u2fs_global_init(U2FS_DEBUG), U2FS_OK);
  ck_assert_int_eq(u2fs_init(&ctx), U2FS_OK);
  ck_assert_int_eq(u2fs_set_appid(ctx, "http://demo.yubico.com"), U2FS_OK);
  ck_assert_int_eq(u2fs_set_origin(ctx, "http://demo.yubico.com"),
                   U2FS_OK);
  ck_assert_int_eq(u2fs_set_challenge
                   (ctx, "0000000000000000000000000000000000000000000"),
                   U2FS_OK);
  ck_assert_int_eq(u2fs_registration_verify(ctx, reg_response, &res),
                   U2FS_CHALLENGE_ERROR);

  u2fs_free_reg_res(res);
  u2fs_done(ctx);
  u2fs_global_done();

}

END_TEST START_TEST(registration_origin_error)
{

  u2fs_ctx_t *ctx;

  char *reg_response =
      "{ \"registrationData\": \"BQRcbdE4PHGRaJUTK9hY4GrX_jZa5eWgjJK6\
    IfwezrndHvQi7QQtYA2qAg4NrebNkSCoOwJ0V1PzLlP1Wr_Oku_0QKfeNR0Ei4_\
    I40GCo5xjm4Q7hnZwzXQ5f5vjtnx7xIqCZ-z7GOGExeouBXxaMgleYpX7xMR6Y9\
    wa_qzLLTAr6IcwggIbMIIBBaADAgECAgR1o_Z1MAsGCSqGSIb3DQEBCzAuMSwwK\
    gYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0x\
    NDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowKjEoMCYGA1UEAwwfWXViaWN\
    vIFUyRiBFRSBTZXJpYWwgMTk3MzY3OTczMzBZMBMGByqGSM49AgEGCCqGSM49Aw\
    EHA0IABBmjfkNqa2mXzVh2ZxuES5coCvvENxDMDLmfd-0ACG0Fu7wR4ZTjKd9KA\
    uidySpfona5csGmlM0Te_Zu35h_wwujEjAQMA4GCisGAQQBgsQKAQIEADALBgkq\
    hkiG9w0BAQsDggEBAb0tuI0-CzSxBg4cAlyD6UyT4cKyJZGVhWdtPgj_mWepT3T\
    u9jXtdgA5F3jfZtTc2eGxuS-PPvqRAkZd40AXgM8A0YaXPwlT4s0RUTY9Y8aAQz\
    QZeAHuZk3lKKd_LUCg5077dzdt90lC5eVTEduj6cOnHEqnOr2Cv75FuiQXX7QkG\
    QxtoD-otgvhZ2Fjk29o7Iy9ik7ewHGXOfoVw_ruGWi0YfXBTuqEJ6H666vvMN4B\
    ZWHtzhC0k5ceQslB9Xdntky-GQgDqNkkBf32GKwAFT9JJrkO2BfsB-wfBrTiHr0\
    AABYNTNKTceA5dtR3UVpI492VUWQbY3YmWUUfKTI7fM4wRQIhAN3c-VHubCCkUt\
    ZXfWL1aiEXU1qWRiM_ayKmWLUafyFbAiARTwlVocoamd9S-cYBosRKso_XGAPzA\
    edzpuE2tEjp1g==\", \"clientData\": \"eyAiY2hhbGxlbmdlIjogIllTMT\
    ludV9ZWWpnczI5WndrU3dRb2JyNzhPaURXRnoxeXFZZW85WUpmQnciLCAib3JpZ\
    2luIjogImh0dHA6XC9cL2RlbW8ueXViaWNvLmNvbSIsICJ0eXAiOiAibmF2aWdh\
    dG9yLmlkLmZpbmlzaEVucm9sbG1lbnQiIH0=\" }";

  u2fs_reg_res_t *res = NULL;;

  ck_assert_int_eq(u2fs_global_init(U2FS_DEBUG), U2FS_OK);
  ck_assert_int_eq(u2fs_init(&ctx), U2FS_OK);
  ck_assert_int_eq(u2fs_set_appid(ctx, "http://demo.yubico.com"), U2FS_OK);
  ck_assert_int_eq(u2fs_set_origin(ctx, "http://example.com"), U2FS_OK);
  ck_assert_int_eq(u2fs_set_challenge
                   (ctx, "YS19nu_YYjgs29ZwkSwQobr78OiDWFz1yqYeo9YJfBw"),
                   U2FS_OK);
  ck_assert_int_eq(u2fs_registration_verify(ctx, reg_response, &res),
                   U2FS_ORIGIN_ERROR);

  u2fs_free_reg_res(res);
  u2fs_done(ctx);
  u2fs_global_done();

}

END_TEST START_TEST(authentication_verify_ok)
{

  u2fs_ctx_t *ctx;

  char *auth_response =
      "{ \"signatureData\": \"AQAAACYwRAIgXUFB4phCuqcc0-a9obD8S_eMuM\
    JbTC0_VrWizmwHadECIAXb_GaAEIuAJv806eUvMjc2Qi-ii5IMbNw2YU2t39Wp\
    \", \"clientData\": \"eyAiY2hhbGxlbmdlIjogInYzMUlLQkZkTGtkTl9a\
    OXRYZkF4eWR1cG9mQ2Y4OWs2QTRhN3RvME9qVG8iLCAib3JpZ2luIjogImh0dH\
    A6XC9cL2RlbW8ueXViaWNvLmNvbSIsICJ0eXAiOiAibmF2aWdhdG9yLmlkLmdl\
    dEFzc2VydGlvbiIgfQ==\", \"keyHandle\": \"kAbb2p57pxHg2mY8y_Kgc\
    dc7jnnAoncJm8vOgqfigyWTvPGFlvxA04ULD9IJ-KpSyn733LRbJ-CG573N9jC\
    Y1g\" }";

  u2fs_auth_res_t *res = NULL;;

  unsigned char src_userkey_dat[] = {
    0x04, 0x14, 0xc3, 0x2e, 0x41, 0x0b, 0x30, 0x9d, 0x6e, 0x93, 0x7f, 0x8b,
    0x5d, 0x81, 0xf9, 0xe5, 0x64, 0xfd, 0x11, 0x2c, 0xe5, 0xfe, 0xf0, 0x10,
    0x5e, 0xfb, 0xec, 0xd5, 0x55, 0x54, 0x52, 0x25, 0x25, 0xe4, 0x54, 0x29,
    0x0f, 0xf4, 0x2e, 0xa1, 0xd8, 0x77, 0x19, 0x36, 0x12, 0xe3, 0x6e, 0x39,
    0x17, 0x91, 0x24, 0xb5, 0x93, 0x8e, 0xe0, 0xfe, 0xf3, 0x69, 0xac, 0xb9,
    0x4c, 0x37, 0x97, 0x83, 0xcb
  };

  ck_assert_int_eq(u2fs_global_init(U2FS_DEBUG), U2FS_OK);
  ck_assert_int_eq(u2fs_init(&ctx), U2FS_OK);
  ck_assert_int_eq(u2fs_set_appid(ctx, "http://demo.yubico.com"), U2FS_OK);
  ck_assert_int_eq(u2fs_set_origin(ctx, "http://demo.yubico.com"),
                   U2FS_OK);
  ck_assert_int_eq(u2fs_set_challenge
                   (ctx, "v31IKBFdLkdN_Z9tXfAxydupofCf89k6A4a7to0OjTo"),
                   U2FS_OK);
  ck_assert_int_eq(u2fs_set_publicKey(ctx, src_userkey_dat), U2FS_OK);
  ck_assert_int_eq(u2fs_authentication_verify(ctx, auth_response, &res),
                   U2FS_OK);

  u2fs_free_auth_res(res);
  u2fs_done(ctx);
  u2fs_global_done();
}

END_TEST START_TEST(authentication_verify_challenge_error)
{

  u2fs_ctx_t *ctx;

  char *auth_response =
      "{ \"signatureData\": \"AQAAACYwRAIgXUFB4phCuqcc0-a9obD8S_eMuM\
    JbTC0_VrWizmwHadECIAXb_GaAEIuAJv806eUvMjc2Qi-ii5IMbNw2YU2t39Wp\
    \", \"clientData\": \"eyAiY2hhbGxlbmdlIjogInYzMUlLQkZkTGtkTl9a\
    OXRYZkF4eWR1cG9mQ2Y4OWs2QTRhN3RvME9qVG8iLCAib3JpZ2luIjogImh0dH\
    A6XC9cL2RlbW8ueXViaWNvLmNvbSIsICJ0eXAiOiAibmF2aWdhdG9yLmlkLmdl\
    dEFzc2VydGlvbiIgfQ==\", \"keyHandle\": \"kAbb2p57pxHg2mY8y_Kgc\
    dc7jnnAoncJm8vOgqfigyWTvPGFlvxA04ULD9IJ-KpSyn733LRbJ-CG573N9jC\
    Y1g\" }";

  u2fs_auth_res_t *res = NULL;

  unsigned char src_userkey_dat[] = {
    0x04, 0x14, 0xc3, 0x2e, 0x41, 0x0b, 0x30, 0x9d, 0x6e, 0x93, 0x7f, 0x8b,
    0x5d, 0x81, 0xf9, 0xe5, 0x64, 0xfd, 0x11, 0x2c, 0xe5, 0xfe, 0xf0, 0x10,
    0x5e, 0xfb, 0xec, 0xd5, 0x55, 0x54, 0x52, 0x25, 0x25, 0xe4, 0x54, 0x29,
    0x0f, 0xf4, 0x2e, 0xa1, 0xd8, 0x77, 0x19, 0x36, 0x12, 0xe3, 0x6e, 0x39,
    0x17, 0x91, 0x24, 0xb5, 0x93, 0x8e, 0xe0, 0xfe, 0xf3, 0x69, 0xac, 0xb9,
    0x4c, 0x37, 0x97, 0x83, 0xcb
  };

  ck_assert_int_eq(u2fs_global_init(U2FS_DEBUG), U2FS_OK);
  ck_assert_int_eq(u2fs_init(&ctx), U2FS_OK);
  ck_assert_int_eq(u2fs_set_appid(ctx, "http://demo.yubico.com"), U2FS_OK);
  ck_assert_int_eq(u2fs_set_origin(ctx, "http://demo.yubico.com"),
                   U2FS_OK);
  ck_assert_int_eq(u2fs_set_challenge
                   (ctx, "0000000000000000000000000000000000000000000"),
                   U2FS_OK);
  ck_assert_int_eq(u2fs_set_publicKey(ctx, src_userkey_dat), U2FS_OK);
  ck_assert_int_eq(u2fs_authentication_verify(ctx, auth_response, &res),
                   U2FS_CHALLENGE_ERROR);

  u2fs_free_auth_res(res);
  u2fs_done(ctx);
  u2fs_global_done();
}

END_TEST START_TEST(authentication_verify_signature_error)
{

  u2fs_ctx_t *ctx;

  char *auth_response =
      "{ \"signatureData\": \"AQAAACYwRAIgXUFB4phCuqcc0-a9obD8S_eMuM\
    JbTC0_VrWizmwHadECIAXb_GaAEIuAJv806eUvMjc2Qi-ii5IMbNw2YU2t39Wp\
    \", \"clientData\": \"eyAiY2hhbGxlbmdlIjogInYzMUlLQkZkTGtkTl9a\
    OXRYZkF4eWR1cG9mQ2Y4OWs2QTRhN3RvME9qVG8iLCAib3JpZ2luIjogImh0dH\
    A6XC9cL2RlbW8ueXViaWNvLmNvbSIsICJ0eXAiOiAibmF2aWdhdG9yLmlkLmdl\
    dEFzc2VydGlvbiIgfQ==\", \"keyHandle\": \"kAbb2p57pxHg2mY8y_Kgc\
    dc7jnnAoncJm8vOgqfigyWTvPGFlvxA04ULD9IJ-KpSyn733LRbJ-CG573N9jC\
    Y1g\" }";

  u2fs_auth_res_t *res = NULL;

  unsigned char src_userkey_dat[] = {
    0x04, 0xb4, 0x21, 0x96, 0x10, 0x25, 0xd3, 0x61, 0xe6, 0x3d, 0x3d, 0x68,
    0x0d, 0x64, 0xd1, 0x40, 0x7c, 0xeb, 0x7b, 0x7b, 0x58, 0x28, 0x6b, 0x47,
    0x77, 0xd4, 0x31, 0x97, 0x6a, 0xc6, 0xd4, 0xd3, 0x36, 0x86, 0xcf, 0xdb,
    0x79, 0x33, 0x04, 0x78, 0x70, 0x11, 0xaa, 0x75, 0x16, 0xfb, 0xae, 0x18,
    0xf5, 0x1d, 0xcd, 0x1e, 0x2c, 0x69, 0xab, 0xf3, 0x12, 0x75, 0xed, 0xed,
    0xfc, 0x5f, 0x8c, 0xad, 0x54
  };

  ck_assert_int_eq(u2fs_global_init(U2FS_DEBUG), U2FS_OK);
  ck_assert_int_eq(u2fs_init(&ctx), U2FS_OK);
  ck_assert_int_eq(u2fs_set_appid(ctx, "http://demo.yubico.com"), U2FS_OK);
  ck_assert_int_eq(u2fs_set_origin(ctx, "http://demo.yubico.com"),
                   U2FS_OK);
  ck_assert_int_eq(u2fs_set_challenge
                   (ctx, "v31IKBFdLkdN_Z9tXfAxydupofCf89k6A4a7to0OjTo"),
                   U2FS_OK);
  ck_assert_int_eq(u2fs_set_publicKey(ctx, src_userkey_dat), U2FS_OK);
  ck_assert_int_eq(u2fs_authentication_verify(ctx, auth_response, &res),
                   U2FS_SIGNATURE_ERROR);

  u2fs_free_auth_res(res);
  u2fs_done(ctx);
  u2fs_global_done();
}

END_TEST Suite *u2fs_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("u2fs_core");

  /* Core test case */
  tc_core = tcase_create("Core");

  tcase_add_test(tc_core, test_create);
  tcase_add_test(tc_core, set_challenge);
  tcase_add_test(tc_core, set_keyhandle);
  tcase_add_test(tc_core, set_publicKey);
  tcase_add_test(tc_core, set_origin);
  tcase_add_test(tc_core, set_appid);
  tcase_add_test(tc_core, registration_verify_ok);
  tcase_add_test(tc_core, registration_challenge_error);
  tcase_add_test(tc_core, registration_origin_error);
  tcase_add_test(tc_core, authentication_verify_ok);
  tcase_add_test(tc_core, authentication_verify_challenge_error);
  tcase_add_test(tc_core, authentication_verify_signature_error);
  suite_add_tcase(s, tc_core);

  return s;
}


int main(void)
{
  int number_failed;
  Suite *s;
  SRunner *sr;

  s = u2fs_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_NORMAL);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
