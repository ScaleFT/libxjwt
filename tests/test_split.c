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
                     "eyJhbGciOiJFUzI1NiIsImtpZCI6IjY1Mjg5YjE5L"
                     "WUwYzYtNDkxOC04OTMzLTc5NjE3ODFhZGIwZCJ"
                     "9") == 0);
  XJWT_ASSERT(strcmp(parsed->payload,
                     "eyJhdWQiOlsiaHR0cHM6Ly9hdWRpZW5jZS5leGFtcGxlLmNvbSJdLCJlb"
                     "WFpbCI6InVzZXJAZXhhbXBsZS5jb20iLCJleHAiOjEuNTEwNjIxNDEzZS"
                     "swOSwiaWF0IjoxLjUxMDYyMTIzM2UrMDksImlzcyI6Imh0dHBzOi8vaXN"
                     "zdWVyLmV4YW1wbGUuY29tIiwibmJmIjoxLjUxMDYyMTExM2UrMDksInN1"
                     "YiI6ImFiMGVkYWYxLTRlZDEtNDBjMC1hZmNiLTE4ZGNmNzU3MTJlNyJ"
                     "9") == 0);
  XJWT_ASSERT(strcmp(parsed->signature,
                     "DOQpYvNU6VGg5Pp8fjQr6y8Ksa5H2v9mNe25dv"
                     "KKXTzAuOzeXIPKX0GuapiAs1aptCd5Gt8Gwqfu"
                     "KrPnGupfGQ") == 0);

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
