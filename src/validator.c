/**
 * Copyright 2017, ScaleFT Inc
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include "xjwt/xjwt_validator.h"
#include "internal/xjwt_parse.h"
#include "internal/xjwt_key.h"
#include "internal/xjwt_keyset.h"

#include <stdlib.h>
#include <jansson.h>
#include <string.h>
#include <openssl/evp.h>

#define XJWT_MIN_JWT_SIZE (16)
#define XJWT_MAX_JWT_SIZE (16000)

static const EVP_MD *alg_to_evp_md(const char *alg, int *keysize) {
  if (alg == NULL) {
    return NULL;
  }
  if (strcmp("ES256", alg) == 0) {
    *keysize = 32;
    return EVP_sha256();
  } else if (strcmp("ES384", alg) == 0) {
    *keysize = 48;
    return EVP_sha384();
  } else if (strcmp("ES521", alg) == 0) {
    *keysize = 66;
    return EVP_sha512();
  } else {
    return NULL;
  }
}

static xjwt_error_t *xjwt__get_tv(json_t *payload, const char *key,
                                  uint64_t *t) {
  double v;
  json_t *num = json_object_get(payload, key);
  if (!json_is_number(num)) {
    return xjwt_error_createf(XJWT_EINVAL, "xjwt_verify: JWT .%s is not number",
                              key);
  }
  v = json_number_value(num);
  if (v < 946684800.0) {
    /* old old date, not reasonable. */
    return xjwt_error_createf(
        XJWT_EINVAL, "xjwt_verify: JWT .%s contains outlandish date", key);
  }
  *t = (uint64_t)v;
  return XJWT_SUCCESS;
}

static xjwt_error_t *xjwt__verify_payload_claims(xjwt_verify_options_t *opts,
                                                 json_t *payload, int *reason) {
  uint64_t now = 0;
  uint64_t nbf = 0;
  uint64_t expires = 0;
  xjwt_error_t *err = XJWT_SUCCESS;

  if (opts->now != NULL) {
    now = opts->now(opts->baton);
  } else {
    /* TODO(pquerna): use gettimeofday? */
    now = (uint64_t)time(NULL);
  }

  err = xjwt__get_tv(payload, "exp", &expires);
  if (err != XJWT_SUCCESS) {
    *reason = XJWT_VERIFY_MALFORMED;
    return err;
  }
  if (now > expires) {
    *reason = XJWT_VERIFY_EXPIRED;
    return xjwt_error_createf(
        XJWT_EINVAL, "xjwt_verify: JWT expired: now:'%d' is after exp:'%d'",
        now, expires);
  }

  err = xjwt__get_tv(payload, "nbf", &nbf);
  if (err != XJWT_SUCCESS) {
    *reason = XJWT_VERIFY_MALFORMED;
    return err;
  }
  if (now < nbf) {
    *reason = XJWT_VERIFY_EXPIRED;
    return xjwt_error_createf(
        XJWT_EINVAL,
        "xjwt_verify: JWT nbf is before now: now:'%d' is after nbf:'%d'", now,
        nbf);
  }

  if (opts->expected_issuer != NULL) {
    const char *issuer = json_string_value(json_object_get(payload, "iss"));
    if (issuer == NULL || strcmp(opts->expected_issuer, issuer) != 0) {
      *reason = XJWT_VERIFY_EXPECT_MISMATCH;
      return xjwt_error_createf(XJWT_EINVAL,
                                "xjwt_verify: Issuer mismatch. '%s' != '%s'",
                                opts->expected_issuer, issuer);
    }
  }

  if (opts->expected_subject != NULL) {
    const char *subject = json_string_value(json_object_get(payload, "sub"));
    if (subject == NULL || strcmp(opts->expected_subject, subject) != 0) {
      *reason = XJWT_VERIFY_EXPECT_MISMATCH;
      return xjwt_error_createf(XJWT_EINVAL,
                                "xjwt_verify: Subject mismatch. '%s' != '%s'",
                                opts->expected_subject, subject);
    }
  }

  if (opts->expected_audience != NULL) {
    int success = 0;
    size_t index;
    json_t *value;
    json_t *aud = json_object_get(payload, "aud");

    if (!json_is_array(aud)) {
      *reason = XJWT_VERIFY_MALFORMED;
      return xjwt_error_createf(XJWT_EINVAL,
                                "xjwt_verify: Audience is not an array",
                                opts->expected_audience);
    }

    json_array_foreach(aud, index, value) {
      const char *audname = json_string_value(value);
      if (audname != NULL && strcmp(opts->expected_audience, audname) == 0) {
        success = 1;
      }
    }

    if (success != 1) {
      *reason = XJWT_VERIFY_EXPECT_MISMATCH;
      return xjwt_error_createf(XJWT_EINVAL,
                                "xjwt_verify: Audience mismatch. Expected '%s'",
                                opts->expected_audience);
    }
  }

  return XJWT_SUCCESS;
}

XJWT_API(void)
xjwt_verify(xjwt_verify_options_t *opts, const char *data, size_t len,
            xjwt_verify_success_t **outsuccess,
            xjwt_verify_failure_t **outfailure) {
  int reason = -1;
  xjwt_error_t *err = XJWT_SUCCESS;
  int keysize = 0;
  xjwt_parsed_t *parsed = NULL;
  json_error_t jerror;
  json_t *jheader = NULL;
  json_t *jpayload = NULL;
  EVP_MD_CTX *md_ctx = NULL;
  const char *ec_sig = NULL;
  size_t ec_sig_len = 0;
  /* ref_ prefixed is memory managed by jansson, life time of owning doc is all
   * the matters */
  json_t *ref_v = NULL;
  const char *ref_hdr_alg = NULL;
  const char *ref_hdr_kid = NULL;
  xjwt_key_t *ref_pubkey;
  const EVP_MD *ref_md; /* static ref from openssl */

  if (len > XJWT_MAX_JWT_SIZE) {
    reason = XJWT_VERIFY_MALFORMED;
    err = xjwt_error_createf(
        XJWT_EINVAL, "xjwt_verify: invalid JWT: JWT is too large: %zd bytes",
        len);
    goto failed;
  }

  if (len <= XJWT_MIN_JWT_SIZE) {
    reason = XJWT_VERIFY_MALFORMED;
    err = xjwt_error_createf(
        XJWT_EINVAL, "xjwt_verify: invalid JWT: JWT is too small: %zd bytes",
        len);
    goto failed;
  }

  err = xjwt__parse_untrusted(data, len, &parsed);
  if (err != XJWT_SUCCESS) {
    reason = XJWT_VERIFY_MALFORMED;
    goto failed;
  }

  jheader = json_loads(parsed->header_decoded, 0, &jerror);
  if (jheader == NULL) {
    reason = XJWT_VERIFY_MALFORMED;
    err = xjwt_error_createf(XJWT_EINVAL,
                             "xjwt_verify: invalid JWT Header: %s @ %d:%d",
                             jerror.text, jerror.line, jerror.column);
    goto failed;
  }

  ref_v = json_object_get(jheader, "alg");
  if (!json_is_string(ref_v)) {
    reason = XJWT_VERIFY_MALFORMED;
    err = xjwt_error_create(
        XJWT_EINVAL, "xjwt_verify: invalid JWT Header: expected .alg field");
    goto failed;
  }
  ref_hdr_alg = json_string_value(ref_v);

  /* TODO(pquerna): factoring for EC vs Ed25519 */
  ref_md = alg_to_evp_md(ref_hdr_alg, &keysize);
  if (ref_md == NULL) {
    reason = XJWT_VERIFY_MALFORMED;
    err = xjwt_error_create(
        XJWT_EINVAL,
        "xjwt_verify: invalid JWT Header: .alg type is unsupported");
    goto failed;
  }

  ref_v = json_object_get(jheader, "kid");
  if (!json_is_string(ref_v)) {
    reason = XJWT_VERIFY_MALFORMED;
    err = xjwt_error_create(
        XJWT_EINVAL, "xjwt_verify: invalid JWT Header: expected .kid field");
    goto failed;
  }
  ref_hdr_kid = json_string_value(ref_v);

  ref_pubkey = xjwt_keyset__get_by_keyid(opts->keyset, ref_hdr_kid);
  if (ref_pubkey == NULL) {
    reason = XJWT_VERIFY_NO_VALIDATORS;
    err = xjwt_error_createf(
        XJWT_EINVAL,
        "xjwt_verify: invalid JWT Header: unknown key id (.kid): \"%s\"",
        ref_hdr_kid);
    goto failed;
  }

  err = xjwt__parse_ec_signature(parsed, &ec_sig, &ec_sig_len);
  if (err != XJWT_SUCCESS) {
    reason = XJWT_VERIFY_MALFORMED;
    goto failed;
  }

  md_ctx = EVP_MD_CTX_create();
  if (md_ctx == NULL) {
    reason = XJWT_VERIFY_UNKNOWN;
    err =
        xjwt_error_create(XJWT_ENOMEM, "xjwt_verify: failed to create md_ctx");
    goto failed;
  }

  if (EVP_DigestVerifyInit(md_ctx, NULL, ref_md, NULL, ref_pubkey->evp) != 1) {
    reason = XJWT_VERIFY_UNKNOWN;
    err = xjwt_error_create(XJWT_ENOMEM, "xjwt_verify: failed to init digest");
    goto failed;
  }

  if (EVP_DigestVerifyUpdate(md_ctx, parsed->signed_data,
                             parsed->signed_data_l) != 1) {
    reason = XJWT_VERIFY_UNKNOWN;
    err =
        xjwt_error_create(XJWT_ENOMEM, "xjwt_verify: failed to update digest");
    goto failed;
  }

  if (EVP_DigestVerifyFinal(md_ctx, (const unsigned char *)ec_sig,
                            ec_sig_len) != 1) {
    reason = XJWT_VERIFY_INVALID_SIGNATURE;
    err = xjwt_error_create(XJWT_EINVAL,
                            "xjwt_verify: failed to verify signature");
    goto failed;
  }

  /**
   * At this point, we have a basic validation of the JWT's signer;  Let's parse
   * the claims and keep rolling.
   */
  err = xjwt__parse_payload(parsed, &jpayload);
  if (err != XJWT_SUCCESS) {
    reason = XJWT_VERIFY_MALFORMED;
    goto failed;
  }

  err = xjwt__verify_payload_claims(opts, jpayload, &reason);
  if (err != XJWT_SUCCESS) {
    goto failed;
  }

  goto success;

failed:
  if (reason == -1) {
    reason = XJWT_VERIFY_UNKNOWN;
  }
  *outsuccess = NULL;
  *outfailure = calloc(1, sizeof(xjwt_verify_failure_t));
  (*outfailure)->reason = reason;
  (*outfailure)->err = err;
  goto cleanup;

success:
  *outfailure = NULL;
  *outsuccess = calloc(1, sizeof(xjwt_verify_success_t));
  json_incref(jpayload);
  (*outsuccess)->payload = jpayload;

  goto cleanup;

cleanup:
  if (md_ctx != NULL) {
    EVP_MD_CTX_destroy(md_ctx);
  }
  if (jpayload != NULL) {
    json_decref(jpayload);
  }
  if (jheader != NULL) {
    json_decref(jheader);
  }
  if (parsed != NULL) {
    xjwt__parsed_destroy(parsed);
  }
  if (ec_sig != NULL) {
    free((void *)ec_sig);
  }

  return;
}

XJWT_API(void) xjwt_verify_success_destroy(xjwt_verify_success_t *p) {
  if (p != NULL) {
    if (p->payload != NULL) {
      json_decref(p->payload);
    }
    free(p);
  }
}

XJWT_API(void) xjwt_verify_failure_destroy(xjwt_verify_failure_t *p) {
  if (p != NULL) {
    if (p->err != NULL) {
      xjwt_error_destroy(p->err);
    }
    free(p);
  }
}
