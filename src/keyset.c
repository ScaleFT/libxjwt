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
#include "internal/xjwt_keyset.h"

#include <jansson.h>
#include <string.h>

XJWT_API(xjwt_error_t*)
xjwt_keyset_create_from_memory(const char* buffer, size_t buflen,
                               xjwt_keyset_t** out) {
  xjwt_keyset_t* ks = NULL;
  size_t ikeys = 0;
  xjwt_error_t* err = NULL;
  json_error_t jerror;
  json_t* doc = NULL;
  json_t* keylist = NULL;

  doc = json_loadb(buffer, buflen, 0, &jerror);
  if (doc == NULL) {
    // TODO(pquerna): make generic error handle for json documents:
    return xjwt_error_createf(
        XJWT_EINVAL, "xjwt_keyset: invalid keyset document: %s @ %d:%d",
        jerror.text, jerror.line, jerror.column);
  }

  keylist = json_object_get(doc, "keys");
  if (!json_is_array(keylist)) {
    json_decref(doc);
    return xjwt_error_create(
        XJWT_EINVAL, "xjwt_keyset: invalid keyset document: missing .keys");
  }

  ks = calloc(1, sizeof(xjwt_keyset_t));

  for (ikeys = 0; ikeys < json_array_size(keylist); ikeys++) {
    xjwt_key_t* nextkey = NULL;
    json_t* key = json_array_get(keylist, ikeys);
    err = xjwt_key_create_from_json(key, &nextkey);
    if (err != XJWT_SUCCESS) {
      json_decref(doc);
      xjwt_keyset_destroy(ks);
      return err;
    }

    nextkey->next = ks->keys;
    ks->keys = nextkey;
  }

  json_decref(doc);
  *out = ks;

  return XJWT_SUCCESS;
}

XJWT_API(xjwt_key_t*)
xjwt_keyset__get_by_keyid(xjwt_keyset_t* ks, const char* keyid) {
  xjwt_key_t* key = ks->keys;
  if (keyid == NULL) {
    return NULL;
  }
  while (key != NULL) {
    if (key->key_id != NULL && strcmp(keyid, key->key_id) == 0) {
      return key;
    }
    key = key->next;
  }
  return NULL;
}

XJWT_API(void) xjwt_keyset_destroy(xjwt_keyset_t* ks) {
  if (ks != NULL) {
    if (ks->keys != NULL) {
      xjwt_key_destroy(ks->keys);
    }
    free(ks);
  }
}
