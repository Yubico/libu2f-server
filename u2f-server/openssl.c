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

#include "crypto.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

void dumpCert(const u2fs_X509_t * certificate)
{
  X509 *cert = (X509 *) certificate;
  BIO *out = BIO_new_fp(stderr, BIO_NOCLOSE);

  (void)X509_print_ex(out, cert, 0, 0);
  (void)PEM_write_bio_X509(out, cert);

  BIO_free(out);
}

void crypto_init(void)
{
  /* Crypto init functions are deprecated in openssl-1.1.0 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
   SSL_load_error_strings();
#endif
}

void crypto_release(void)
{
  /* Crypto deinit functions are deprecated in openssl-1.1.0. */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  RAND_cleanup();
  ERR_free_strings();
#endif
}

u2fs_rc set_random_bytes(char *data, size_t len)
{

  if (data == NULL)
    return U2FS_MEMORY_ERROR;

  if (RAND_status() != 1 || RAND_bytes((unsigned char *) data, len) != 1)
    return U2FS_CRYPTO_ERROR;

  return U2FS_OK;

}

u2fs_rc decode_X509(const unsigned char *data, size_t len,
                    u2fs_X509_t ** cert)
{

  const unsigned char *p;

  if (data == NULL || len == 0 || cert == NULL)
    return U2FS_MEMORY_ERROR;

  p = data;

  //Always set 1st param to NULL as per http://www.tedunangst.com/flak/post/analysis-of-d2i-X509-reuse
  *cert = (u2fs_X509_t *) d2i_X509(NULL, &p, len);
  if (*cert == NULL) {
    if (debug) {
      unsigned long err = 0;
      err = ERR_get_error();
      fprintf(stderr, "Error: %s, %s, %s\n",
              ERR_lib_error_string(err),
              ERR_func_error_string(err), ERR_reason_error_string(err));
    }
    return U2FS_CRYPTO_ERROR;
  }

  return U2FS_OK;
}

u2fs_rc decode_ECDSA(const unsigned char *data, size_t len,
                     u2fs_ECDSA_t ** sig)
{

  const unsigned char *p;

  if (data == NULL || len == 0 || sig == NULL)
    return U2FS_MEMORY_ERROR;

  p = data;

  *sig = (u2fs_ECDSA_t *) d2i_ECDSA_SIG(NULL, &p, len);

  if (*sig == NULL) {
    if (debug) {
      unsigned long err = 0;
      err = ERR_get_error();
      fprintf(stderr, "Error: %s, %s, %s\n",
              ERR_lib_error_string(err),
              ERR_func_error_string(err), ERR_reason_error_string(err));
    }
    return U2FS_CRYPTO_ERROR;
  }

  return U2FS_OK;
}

u2fs_rc decode_user_key(const unsigned char *data, u2fs_EC_KEY_t ** key)
{
  EC_GROUP *ecg = NULL;
  EC_POINT *point = NULL;
  point_conversion_form_t pcf = POINT_CONVERSION_UNCOMPRESSED;
  unsigned long err;
  u2fs_rc rc = U2FS_CRYPTO_ERROR;

  if (key == NULL)
    return U2FS_MEMORY_ERROR;

  ecg = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  *key = (u2fs_EC_KEY_t *) EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

  point = EC_POINT_new(ecg);
  EC_GROUP_set_point_conversion_form(ecg, pcf);

  if (EC_POINT_oct2point(ecg, point, data, U2FS_PUBLIC_KEY_LEN, NULL) == 0) {
    if (debug) {
      err = ERR_get_error();
      fprintf(stderr, "Error: %s, %s, %s\n",
              ERR_lib_error_string(err),
              ERR_func_error_string(err), ERR_reason_error_string(err));
    }
    goto done;
  }

  if (EC_KEY_set_public_key((EC_KEY *) * key, point) == 0) {
    if (debug) {
      err = ERR_get_error();
      fprintf(stderr, "Error: %s, %s, %s\n",
              ERR_lib_error_string(err),
              ERR_func_error_string(err), ERR_reason_error_string(err));
    }
    goto done;
  }

  rc = U2FS_OK;
done:
  EC_GROUP_free(ecg);
  EC_POINT_free(point);

  if (rc != U2FS_OK) {
    EC_KEY_free((EC_KEY *)*key);
    *key = NULL;
  }
  return rc;
}

u2fs_rc verify_ECDSA(const unsigned char *dgst, int dgst_len,
                     const u2fs_ECDSA_t * sig, u2fs_EC_KEY_t * eckey)
{
  if (dgst == NULL || dgst_len == 0 || sig == NULL || eckey == NULL)
    return U2FS_MEMORY_ERROR;

  int rc =
      ECDSA_do_verify(dgst, dgst_len, (ECDSA_SIG *) sig, (EC_KEY *) eckey);

  if (rc != 1) {
    if (rc == -1) {
      if (debug) {
        unsigned long err = 0;
        err = ERR_get_error();
        fprintf(stderr, "Error: %s, %s, %s\n",
                ERR_lib_error_string(err),
                ERR_func_error_string(err), ERR_reason_error_string(err));
      }
      return U2FS_CRYPTO_ERROR;
    } else {
      return U2FS_SIGNATURE_ERROR;
    }
  }

  return U2FS_OK;
}

u2fs_rc extract_EC_KEY_from_X509(const u2fs_X509_t * cert,
                                 u2fs_EC_KEY_t ** key)
{
  if (cert == NULL || key == NULL)
    return U2FS_MEMORY_ERROR;

  EVP_PKEY *pkey = X509_get_pubkey((X509 *) cert);

  if (pkey == NULL) {
    if (debug) {
      unsigned long err = 0;
      err = ERR_get_error();
      fprintf(stderr, "Error: %s, %s, %s\n",
              ERR_lib_error_string(err),
              ERR_func_error_string(err), ERR_reason_error_string(err));
    }
    return U2FS_CRYPTO_ERROR;
  }

  *key = (u2fs_EC_KEY_t *) EVP_PKEY_get1_EC_KEY(pkey);

  EVP_PKEY_free(pkey);
  pkey = NULL;

  if (*key == NULL) {
    if (debug) {
      unsigned long err = 0;
      err = ERR_get_error();
      fprintf(stderr, "Error: %s, %s, %s\n",
              ERR_lib_error_string(err),
              ERR_func_error_string(err), ERR_reason_error_string(err));
    }
    return U2FS_CRYPTO_ERROR;
  }

  EC_GROUP *ecg = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

  EC_KEY_set_asn1_flag((EC_KEY *) * key, OPENSSL_EC_NAMED_CURVE);
  EC_KEY_set_group((EC_KEY *) * key, ecg);

  EC_GROUP_free(ecg);
  ecg = NULL;

  return U2FS_OK;
}

u2fs_EC_KEY_t *dup_key(const u2fs_EC_KEY_t * key)
{
  return (u2fs_EC_KEY_t *) EC_KEY_dup((EC_KEY *) key);
}

void free_key(u2fs_EC_KEY_t * key)
{
  EC_KEY_free((EC_KEY *) key);
}

u2fs_X509_t *dup_cert(const u2fs_X509_t * cert)
{
  return (u2fs_X509_t *) X509_dup((X509 *) cert);
}

void free_cert(u2fs_X509_t * cert)
{
  X509_free((X509 *) cert);
}

void free_sig(u2fs_ECDSA_t * sig)
{
  ECDSA_SIG_free((ECDSA_SIG *) sig);
}

//TODO add PEM - current output is openssl octet string
u2fs_rc dump_user_key(const u2fs_EC_KEY_t * key, char **output)
{
  EC_GROUP *ecg = NULL;
  point_conversion_form_t pcf = POINT_CONVERSION_UNCOMPRESSED;
  const EC_POINT *point;
  u2fs_rc rc = U2FS_MEMORY_ERROR;

  if (key == NULL || output == NULL)
    return U2FS_MEMORY_ERROR;
  *output = NULL;

  ecg = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  if (ecg == NULL)
    goto done;

  point = EC_KEY_get0_public_key((EC_KEY *) key);

  *output = malloc(U2FS_PUBLIC_KEY_LEN);
  if (*output == NULL)
    goto done;

  if (EC_POINT_point2oct
      (ecg, point, pcf, (unsigned char *) *output, U2FS_PUBLIC_KEY_LEN,
       NULL) != U2FS_PUBLIC_KEY_LEN) {
    rc = U2FS_CRYPTO_ERROR;
    goto done;
  }

  rc = U2FS_OK;
done:
  EC_GROUP_free(ecg);
  if (rc != U2FS_OK) {
    free(*output);
    *output = NULL;
  }
  return rc;
}

u2fs_rc dump_X509_cert(const u2fs_X509_t * cert, char **output)
{
  //input: openssl X509 certificate
  //output: PEM-formatted char buffer

  if (cert == NULL || output == NULL)
    return U2FS_MEMORY_ERROR;

  *output = NULL;

  BIO *bio = BIO_new(BIO_s_mem());
  if (bio == NULL)
    return U2FS_MEMORY_ERROR;

  if(!PEM_write_bio_X509(bio, (X509 *)cert)) {
    BIO_free(bio);
    return U2FS_CRYPTO_ERROR;
  }

  char *PEM_data;
  int length = BIO_get_mem_data(bio, &PEM_data);
  *output = malloc(length);
  if (*output == NULL) {
    BIO_free(bio);
    return U2FS_MEMORY_ERROR;
  }

  memcpy(*output, PEM_data, length);
  BIO_free(bio);

  return U2FS_OK;
}

#ifdef MAKE_CHECK
#include <check.h>

START_TEST(test_errors)
{

  u2fs_X509_t *cert = NULL;
  u2fs_ECDSA_t *sig = NULL;
  u2fs_EC_KEY_t *key = NULL;

  char *output;

  unsigned char some_data[] = {
    0x0A, 0x0B, 0x0C, 0x0D, 0x0E
  };

  unsigned char wrong_key[] = {
    0x04, 0x5c, 0x6d, 0xd1, 0x38, 0x3c, 0x71, 0x91, 0x68, 0x95, 0x13, 0x2b,
    0xd8, 0x58, 0xe0, 0x6a, 0xd7, 0xfe, 0x36, 0x5a, 0xe5, 0xe5, 0xa0,
    0x8c, 0x92, 0xba, 0x21, 0xfc, 0x1e, 0xce, 0xb9, 0xdd, 0x1e, 0xf4,
    0x22, 0xed, 0x04, 0x2d, 0x60, 0x0d, 0xaa, 0x02, 0x0e, 0x0d, 0xad,
    0xe6, 0xcd, 0x91, 0x20, 0xa8, 0x3b, 0x02, 0x74, 0x57, 0x53, 0xf3,
    0x2e, 0x53, 0xf5, 0x5a, 0xbf, 0xce, 0x92, 0xaa, 0xaa
  };

  unsigned char userkey_dat[] = {
    0x04, 0x5c, 0x6d, 0xd1, 0x38, 0x3c, 0x71, 0x91, 0x68, 0x95, 0x13, 0x2b,
    0xd8, 0x58, 0xe0, 0x6a, 0xd7, 0xfe, 0x36, 0x5a, 0xe5, 0xe5, 0xa0,
    0x8c, 0x92, 0xba, 0x21, 0xfc, 0x1e, 0xce, 0xb9, 0xdd, 0x1e, 0xf4,
    0x22, 0xed, 0x04, 0x2d, 0x60, 0x0d, 0xaa, 0x02, 0x0e, 0x0d, 0xad,
    0xe6, 0xcd, 0x91, 0x20, 0xa8, 0x3b, 0x02, 0x74, 0x57, 0x53, 0xf3,
    0x2e, 0x53, 0xf5, 0x5a, 0xbf, 0xce, 0x92, 0xef, 0xf4
  };

  cert = (u2fs_X509_t *) & output;
  key = (u2fs_EC_KEY_t *) & output;
  sig = (u2fs_ECDSA_t *) & output;

  ck_assert_int_eq(decode_X509(some_data, 5, &cert), U2FS_CRYPTO_ERROR);
  ck_assert_int_eq(decode_ECDSA(some_data, 5, &sig), U2FS_CRYPTO_ERROR);
  ck_assert_int_eq(decode_user_key(wrong_key, &key), U2FS_CRYPTO_ERROR);

  //ck_assert_int_eq(dump_user_key(key, &output), U2FS_CRYPTO_ERROR);
  ck_assert_int_eq(decode_user_key(userkey_dat, &key), U2FS_OK);
  //ck_assert_int_eq(extract_EC_KEY_from_X509(cert, &key), U2FS_CRYPTO_ERROR);

}

END_TEST START_TEST(test_dup_key)
{

  u2fs_EC_KEY_t *key = NULL;
  u2fs_EC_KEY_t *key2 = NULL;

  unsigned char userkey_dat[] = {
    0x04, 0x5c, 0x6d, 0xd1, 0x38, 0x3c, 0x71, 0x91, 0x68, 0x95, 0x13, 0x2b,
    0xd8, 0x58, 0xe0, 0x6a, 0xd7, 0xfe, 0x36, 0x5a, 0xe5, 0xe5, 0xa0,
    0x8c, 0x92, 0xba, 0x21, 0xfc, 0x1e, 0xce, 0xb9, 0xdd, 0x1e, 0xf4,
    0x22, 0xed, 0x04, 0x2d, 0x60, 0x0d, 0xaa, 0x02, 0x0e, 0x0d, 0xad,
    0xe6, 0xcd, 0x91, 0x20, 0xa8, 0x3b, 0x02, 0x74, 0x57, 0x53, 0xf3,
    0x2e, 0x53, 0xf5, 0x5a, 0xbf, 0xce, 0x92, 0xef, 0xf4
  };

  ck_assert_int_eq(decode_user_key(userkey_dat, &key), U2FS_OK);
  key2 = dup_key(key);
  ck_assert(key2 != NULL);
  //ck_assert(memcmp(key, key2, sizeof(key)));

}

END_TEST Suite *u2fs_crypto_suite(void)
{
  Suite *s;
  TCase *tc_crypto;

  s = suite_create("u2fs_crypto");

  /* Crypto test case */
  tc_crypto = tcase_create("Crypto");

  tcase_add_test(tc_crypto, test_errors);
  tcase_add_test(tc_crypto, test_dup_key);
  suite_add_tcase(s, tc_crypto);

  return s;
}

int main(void)
{

  int number_failed;
  Suite *s;
  SRunner *sr;

  s = u2fs_crypto_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_NORMAL);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;

  return 0;

}
#endif
