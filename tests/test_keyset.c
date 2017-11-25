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

#include "xjwt/xjwt.h"
#include "internal/xjwt_keyset.h"
#include "xjwt_tests.h"

#include <string.h>

static void keyset_parse_memory(void **state) {
  xjwt_keyset_t *ks;
  char *buf = NULL;
  size_t len = 0;
  xjwt_key_t *key;

  xjwt_load_fixture("jwk_af.json", &buf, &len);

  XJWT_NO_ERROR(xjwt_keyset_create_from_memory(buf, len, &ks));

  key = xjwt_keyset__get_by_keyid(ks, "9872c4bc33d6903c");

  XJWT_ASSERT(strcmp("9872c4bc33d6903c", key->key_id) == 0);
  XJWT_ASSERT(strcmp("ES256", key->algorithm) == 0);
  XJWT_ASSERT(strcmp("sig", key->use) == 0);
  XJWT_ASSERT(strcmp("EC", key->key_type) == 0);

  xjwt_keyset_destroy(ks);
  free(buf);
}

XJWT_TESTS_START(keyset)
XJWT_TESTS_ENTRY(keyset_parse_memory)
XJWT_TESTS_END()
