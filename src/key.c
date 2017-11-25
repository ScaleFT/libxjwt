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

#include <stdlib.h>

#include "xjwt/xjwt_keyset.h"
#include "xjwt/xjwt_error.h"

#include "internal/xjwt_key.h"
#include "internal/xjwt_json.h"

#include <jansson.h>
#include <string.h>

XJWT_API(xjwt_error_t*)
xjwt_key_create_from_json(json_t* doc, xjwt_key_t** out) {
  xjwt_error_t* err = NULL;

  /**
   * doc is json with the following shape (EC key):
   *  {
   *    "use": "sig",
   *    "kty": "EC",
   *    "kid": "9872c4bc33d6903c",
   *    "crv": "P-256",
   *    "alg": "ES256",
   *    "x": "XWJ223wh78Bm1gARomGCZUXqIKI94wTYTYiYJcq-Z7E",
   *    "y": "PzlxP2N0CrEM4M2486cvwm3QyWSyW8QxKqfjcXdWBao"
   *  }
   *
   */
  xjwt_key_t* key = NULL;

  key = calloc(1, sizeof(xjwt_key_t));
  key->key_type = xjwt_json_strdup(doc, "kty");
  key->key_id = xjwt_json_strdup(doc, "kid");
  key->algorithm = xjwt_json_strdup(doc, "alg");
  key->use = xjwt_json_strdup(doc, "use");

  if (key->key_type == NULL) {
    xjwt_key_destroy(key);
    return xjwt_error_create(XJWT_EINVAL,
                             "xjwt_key: invalid key document: .kty invalid");
  }

  if (strcmp(key->key_type, "EC") == 0) {
    err = xjwt_key__parse_ec(doc, key);
    if (err != XJWT_SUCCESS) {
      xjwt_key_destroy(key);
      return err;
    }
  } else {
    err = xjwt_error_createf(
        XJWT_EINVAL,
        "xjwt_key: invalid key document: unsupported key type: '%s'",
        key->key_type);
    xjwt_key_destroy(key);
    return err;
  }
  *out = key;

  return XJWT_SUCCESS;
}

XJWT_API(void) xjwt_key_destroy(xjwt_key_t* ks) {
  if (ks != NULL) {
    if (ks->next != NULL) {
      xjwt_key_destroy(ks->next);
      ks->next = NULL;
    }
    if (ks->key_type != NULL) {
      free((void*)ks->key_type);
    }
    if (ks->key_id != NULL) {
      free((void*)ks->key_id);
    }
    if (ks->algorithm != NULL) {
      free((void*)ks->algorithm);
    }
    if (ks->use != NULL) {
      free((void*)ks->use);
    }
    if (ks->evp != NULL) {
      EVP_PKEY_free(ks->evp);
    }
    free(ks);
  }
}
