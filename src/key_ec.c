
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

#include "xjwt/xjwt_error.h"

#include "internal/xjwt_key.h"
#include "internal/xjwt_json.h"
#include "internal/xjwt_b64.h"

#include <string.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/err.h>

static int curve_to_nid(const char *type) {
  if (strcmp("P-256", type) == 0) {
    return NID_X9_62_prime256v1;
  } else if (strcmp("P-384", type) == 0) {
    return NID_secp384r1;
  } else if (strcmp("P-521", type) == 0) {
    return NID_secp521r1;
  } else {
    return -1;
  }
}

XJWT_API(xjwt_error_t *) xjwt_key__parse_ec(json_t *doc, xjwt_key_t *key) {
  xjwt_error_t *err = NULL;
  int nid;
  EC_KEY *pubkey = NULL;
  json_t *jcrv;
  json_t *jnum;
  size_t lbuf;
  char *buf;
  BIGNUM *bx;
  BIGNUM *by;

  jcrv = json_object_get(doc, "crv");
  if (!json_is_string(jcrv)) {
    return xjwt_error_create(XJWT_EINVAL,
                             "xjwt_key: invalid key document: .crv invalid");
  }

  nid = curve_to_nid(json_string_value(jcrv));
  if (nid == -1) {
    return xjwt_error_createf(
        XJWT_EINVAL, "xjwt_key: invalid key document: .crv unknown curve: '%s'",
        json_string_value(jcrv));
  }

  jnum = json_object_get(doc, "x");
  if (!json_is_string(jnum)) {
    return xjwt_error_create(XJWT_EINVAL,
                             "xjwt_key: invalid key document: .x invalid");
  }

  err = xjwt__url_base64_decode(json_string_value(jnum), &buf, &lbuf);
  if (err != XJWT_SUCCESS) {
    return xjwt_error_createf(
        XJWT_EINVAL, "xjwt_key: invalid key document: .x invalid: (%d) %s",
        err->err, err->msg);
  }
  bx = BN_bin2bn((const unsigned char *)buf, lbuf, NULL);
  free(buf);

  jnum = json_object_get(doc, "y");
  if (!json_is_string(jnum)) {
    BN_free(bx);
    return xjwt_error_create(XJWT_EINVAL,
                             "xjwt_key: invalid key document: .y invalid");
  }

  err = xjwt__url_base64_decode(json_string_value(jnum), &buf, &lbuf);
  if (err != XJWT_SUCCESS) {
    BN_free(bx);
    return xjwt_error_createf(
        XJWT_EINVAL, "xjwt_key: invalid key document: .y invalid: (%d) %s",
        err->err, err->msg);
  }
  by = BN_bin2bn((const unsigned char *)buf, lbuf, NULL);
  free(buf);

  pubkey = EC_KEY_new_by_curve_name(nid);
  if (pubkey == NULL) {
    BN_free(bx);
    BN_free(by);
    return xjwt_error_createf(
        XJWT_EINVAL,
        "xjwt_key: invalid key document: .crv unsupported curve: '%s'",
        json_string_value(jcrv));
  }

  if (EC_KEY_set_public_key_affine_coordinates(pubkey, bx, by) != 1) {
    /*
        ERR_print_errors_fp(stderr);
          BN_print_fp(stderr, bx);
        fprintf(stderr, "\n");
          BN_print_fp(stderr, by);
        fprintf(stderr, "\n");
        */
    BN_free(bx);
    BN_free(by);
    EC_KEY_free(pubkey);
    /* TODO(pquerna): openssl error conversion */
    return xjwt_error_create(XJWT_EINVAL,
                             "xjwt_key: invalid key document: EC "
                             "set_public_key_affine_coordinates failed");
  }
  BN_free(bx);
  BN_free(by);

  key->evp = EVP_PKEY_new();
  if (EVP_PKEY_assign_EC_KEY(key->evp, pubkey) != 1) {
    /* TODO(pquerna): openssl error conversion */
    EC_KEY_free(pubkey);
    return xjwt_error_create(
        XJWT_EINVAL, "xjwt_key: invalid key document: EVP set1 EC_KEY failed");
  }
  return XJWT_SUCCESS;
}
