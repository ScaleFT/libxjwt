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

typedef struct tcb_baton_t {
  uint64_t now;
} tcb_baton_t;

static uint64_t tcb(void *baton) { return ((tcb_baton_t *)baton)->now; }

static void verify_no_validators(void **state) {
  char *buf = NULL;
  size_t len = 0;
  xjwt_verify_options_t opts = {0};
  xjwt_verify_failure_t *failed = NULL;
  xjwt_verify_success_t *success = NULL;
  tcb_baton_t baton = {0};

  xjwt_load_fixture("jwk_none.json", &buf, &len);
  XJWT_NO_ERROR(xjwt_keyset_create_from_memory(buf, len, &opts.keyset));
  free(buf);
  xjwt_load_fixture("e1_af.jwt", &buf, &len);

  opts.expected_issuer = "https://issuer.example.com";
  opts.expected_subject = "ab0edaf1-4ed1-40c0-afcb-18dcf75712e7";
  opts.expected_audience = "https://audience.example.com";
  opts.now = tcb;
  baton.now = 1510621410;
  opts.baton = &baton;

  xjwt_verify(&opts, buf, len, &success, &failed);
  XJWT_ASSERT(success == NULL);
  XJWT_ASSERT(failed != NULL);
  XJWT_ASSERT(failed->err != NULL);
  XJWT_ASSERT(failed->err->err == XJWT_EINVAL);
  XJWT_ASSERT(strstr(failed->err->msg, "unknown key id") != NULL);
  XJWT_ASSERT(
      strstr(failed->err->msg, "65289b19-e0c6-4918-8933-7961781adb0d") != NULL);
  xjwt_verify_failure_destroy(failed);
}

static void verify_e1(void **state) {
  char *buf = NULL;
  size_t len = 0;
  xjwt_verify_options_t opts = {0};
  xjwt_verify_failure_t *failed = NULL;
  xjwt_verify_success_t *success = NULL;
  tcb_baton_t baton = {0};

  xjwt_load_fixture("e1_jwk.json", &buf, &len);
  XJWT_NO_ERROR(xjwt_keyset_create_from_memory(buf, len, &opts.keyset));
  free(buf);

  xjwt_load_fixture("e1_af.jwt", &buf, &len);

  opts.expected_issuer = "https://issuer.example.com";
  opts.expected_subject = "ab0edaf1-4ed1-40c0-afcb-18dcf75712e7";
  opts.expected_audience = "https://audience.example.com";
  opts.now = tcb;
  baton.now = 1510621410;
  opts.baton = &baton;

  xjwt_verify(&opts, buf, len, &success, &failed);

  if (failed != NULL) XJWT_NO_ERROR(failed->err);
  XJWT_ASSERT(success != NULL);
  XJWT_ASSERT(failed == NULL);
  xjwt_verify_success_destroy(success);

  /* expire it */
  baton.now = 1510621414;
  xjwt_verify(&opts, buf, len, &success, &failed);
  XJWT_ASSERT(failed != NULL);
  XJWT_ASSERT(success == NULL);
  xjwt_verify_failure_destroy(failed);

  /* not before it... */
  baton.now = 1510621110;
  xjwt_verify(&opts, buf, len, &success, &failed);
  XJWT_ASSERT(failed != NULL);
  XJWT_ASSERT(success == NULL);
  xjwt_verify_failure_destroy(failed);

  free(buf);
  xjwt_keyset_destroy(opts.keyset);
}

XJWT_TESTS_START(verify)
XJWT_TESTS_ENTRY(verify_e1)
XJWT_TESTS_ENTRY(verify_no_validators)
XJWT_TESTS_END()
