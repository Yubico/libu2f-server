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
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

void dumpCert(const u2fs_X509_t * certificate)
{
  X509 *cert = (X509 *) certificate;

  BIO *bio_out = BIO_new_fp(stderr, BIO_NOCLOSE);

  BIO_printf(bio_out, "Certificate:\n  Data:\n");

  long l = X509_get_version((X509 *) cert);
  BIO_printf(bio_out, "    Version: %ld\n", l + 1);

  int i;
  ASN1_INTEGER *bs = X509_get_serialNumber((X509 *) cert);
  BIO_printf(bio_out, "    Serial Number: ");
  for (i = 0; i < bs->length; i++) {
    BIO_printf(bio_out, "%02x", bs->data[i]);
  }
  BIO_printf(bio_out, "\n");

  X509_signature_print(bio_out, cert->sig_alg, NULL);

  BIO_printf(bio_out, "    Issuer: ");
  X509_NAME_print(bio_out, X509_get_issuer_name((X509 *) cert), 0);
  BIO_printf(bio_out, "\n");
  BIO_printf(bio_out, "    Validity\n");
  BIO_printf(bio_out, "      Not Before: ");
  ASN1_TIME_print(bio_out, X509_get_notBefore((X509 *) cert));
  BIO_printf(bio_out, "\n");
  BIO_printf(bio_out, "      Not After : ");
  ASN1_TIME_print(bio_out, X509_get_notAfter((X509 *) cert));
  BIO_printf(bio_out, "\n");

  BIO_printf(bio_out, "    Subject: ");
  X509_NAME_print(bio_out, X509_get_subject_name((X509 *) cert), 0);
  BIO_printf(bio_out, "\n");
  EVP_PKEY *pkey = X509_get_pubkey((X509 *) cert);
  BIO_printf(bio_out, "    ");
  EVP_PKEY_print_public(bio_out, pkey, 0, NULL);
  EVP_PKEY_free(pkey);

  //Extensions
  X509_CINF *ci = cert->cert_info;
  X509V3_extensions_print(bio_out, "X509v3 extensions", ci->extensions,
                          X509_FLAG_COMPAT, 0);

  //Signature
  X509_signature_print(bio_out, cert->sig_alg, cert->signature);
  BIO_free(bio_out);
}

void crypto_init(void)
{
  SSL_load_error_strings();
}

void crypto_release(void)
{
  RAND_cleanup();
}

u2fs_rc set_random_bytes(char *data, size_t len)
{

  if (data == NULL)
    return U2FS_MEMORY_ERROR;

  if (RAND_status() != 1 || RAND_bytes(data, len) != 1)
    return U2FS_CRYPTO_ERROR;

  return U2FS_OK;

}

u2fs_rc decode_X509(const char *data, size_t len, u2fs_X509_t ** cert)
{

  const unsigned char *p;

  if (data == NULL || len == 0)
    return U2FS_MEMORY_ERROR;

  p = data;

  //Always set 1st param to NULL as per http://www.tedunangst.com/flak/post/analysis-of-d2i-X509-reuse
  *cert = (u2fs_X509_t *) d2i_X509(NULL, &p, len);
  if (cert == NULL || *cert == NULL) {
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

u2fs_rc decode_ECDSA(const char *data, size_t len, u2fs_ECDSA_t ** sig)
{

  const unsigned char *p;

  if (data == NULL || len == 0)
    return U2FS_MEMORY_ERROR;

  p = data;

  *sig = (u2fs_ECDSA_t *) d2i_ECDSA_SIG(NULL, &p, len);

  if (sig == NULL || *sig == NULL) {
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

  if (key == NULL)
    return U2FS_MEMORY_ERROR;

  EC_GROUP *ecg = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  *key = (u2fs_EC_KEY_t *) EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

  EC_POINT *point = EC_POINT_new(ecg);
  point_conversion_form_t pcf = POINT_CONVERSION_UNCOMPRESSED;
  EC_GROUP_set_point_conversion_form(ecg, pcf);

  if (EC_POINT_oct2point(ecg, point, data, U2FS_PUBLIC_KEY_LEN, NULL) == 0) {
    if (debug) {
      unsigned long err = 0;
      err = ERR_get_error();
      fprintf(stderr, "Error: %s, %s, %s\n",
              ERR_lib_error_string(err),
              ERR_func_error_string(err), ERR_reason_error_string(err));
    }
    *key = NULL;
    EC_GROUP_free(ecg);
    ecg = NULL;
    EC_POINT_free(point);
    point = NULL;
    return U2FS_CRYPTO_ERROR;
  }

  EC_GROUP_free(ecg);
  ecg = NULL;

  if (EC_KEY_set_public_key((EC_KEY *) * key, point) == 0) {
    if (debug) {
      unsigned long err = 0;
      err = ERR_get_error();
      fprintf(stderr, "Error: %s, %s, %s\n",
              ERR_lib_error_string(err),
              ERR_func_error_string(err), ERR_reason_error_string(err));
    }
    *key = NULL;
    EC_POINT_free(point);
    point = NULL;
    return U2FS_CRYPTO_ERROR;
  }

  EC_POINT_free(point);
  point = NULL;

  return U2FS_OK;

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
  if (cert == NULL)
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

  if (key == NULL || *key == NULL) {
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

u2fs_rc dump_user_key(const u2fs_EC_KEY_t * key, char **output)
{
  //TODO add PEM

  if (key == NULL || output == NULL)
    return U2FS_MEMORY_ERROR;

  EC_GROUP *ecg = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  point_conversion_form_t pcf = POINT_CONVERSION_UNCOMPRESSED;

  if (ecg == NULL)
    return U2FS_MEMORY_ERROR;

  const EC_POINT *point = EC_KEY_get0_public_key((EC_KEY *) key);

  *output = malloc(U2FS_PUBLIC_KEY_LEN);

  if (*output == NULL) {
    EC_GROUP_free(ecg);
    return U2FS_MEMORY_ERROR;
  }

  if (EC_POINT_point2oct
      (ecg, point, pcf, *output, U2FS_PUBLIC_KEY_LEN,
       NULL) != U2FS_PUBLIC_KEY_LEN) {
    free(ecg);
    free(*output);
    *output = NULL;
    return U2FS_CRYPTO_ERROR;
  }

  EC_GROUP_free(ecg);

  return U2FS_OK;

}
