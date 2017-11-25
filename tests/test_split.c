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
#include "internal/xjwt_parse.h"
#include "xjwt_tests.h"

#include <string.h>

static void split_jwt_parts(void **state) {
  char *buf = NULL;
  size_t len = 0;
  xjwt_parsed_t *parsed = NULL;

  xjwt_load_fixture("e1_af.jwt", &buf, &len);

  XJWT_NO_ERROR(xjwt__parse_untrusted(buf, len, &parsed));

  XJWT_ASSERT(parsed != NULL);

  XJWT_ASSERT(strcmp(parsed->header,
                     "eyJhbGciOiJFUzI1NiIsImtpZCI6ImNlZjhmNThmMmY4NDc4NmYiLCJub"
                     "25jZSI6IjczZWVlZmI3MTU2YjUwN2YifQ") == 0);
  XJWT_ASSERT(strcmp(parsed->payload,
                     "eyJhdWQiOlsiaHR0cHM6Ly90ZXN0LmtocnlvLmNvbSJdLCJlbWFpbCI6I"
                     "mJyYWQubW9yZ2FuQHNjYWxlZnQuY29tIiwiZXhwIjoxNTEwNjIxNDEzLC"
                     "JpYXQiOjE1MTA2MjEyMzMsImlzcyI6Imh0dHBzOi8vZGV2LnN1ZG8ud3R"
                     "mOjg0NDMiLCJuYmYiOjE1MTA2MjExMTMsInN1YiI6ImFiMGVkYWYxLTRl"
                     "ZDEtNDBjMC1hZmNiLTE4ZGNmNzU3MTJlNyJ9") == 0);
  XJWT_ASSERT(strcmp(parsed->signature,
                     "TrJq661jUVlfalXM8oS6RfELYPABmfkqyDlGuDXOQLr-"
                     "lOZVZqjRYwPRoZaQresGVvzoygBIf2QpduiDBkLVOA") == 0);

  xjwt__parsed_destroy(parsed);
  free(buf);
}

static void split_too_many(void **state) {
  const char *buf = "hello.world.there.1.f";
  size_t len = strlen(buf);
  xjwt_parsed_t *parsed = NULL;

  XJWT_FAIL(xjwt__parse_untrusted(buf, len, &parsed));
  XJWT_ASSERT(parsed == NULL);
}

static void split_too_few(void **state) {
  const char *buf = "hello.world";
  size_t len = strlen(buf);
  xjwt_parsed_t *parsed = NULL;

  XJWT_FAIL(xjwt__parse_untrusted(buf, len, &parsed));
  XJWT_ASSERT(parsed == NULL);
}

XJWT_TESTS_START(split)
XJWT_TESTS_ENTRY(split_jwt_parts)
XJWT_TESTS_ENTRY(split_too_many)
XJWT_TESTS_ENTRY(split_too_few)
XJWT_TESTS_END()
