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

#ifndef _xjwt_tests_h_
#define _xjwt_tests_h_

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdio.h>
#include "cmockery.h"

#ifdef XJWT_TEST_ALL
#define XJWT_TESTS_START(module) \
  int xjwt_tests_##module() {    \
    int rv = 0;                  \
    const UnitTest tests[] = {
#define XJWT_TESTS_ENTRY(entry) unit_test(entry),

#define XJWT_TESTS_END() \
  }                      \
  ;                      \
  rv = run_tests(tests); \
  return rv;             \
  }

#else

#define XJWT_TESTS_START(module)     \
  int main(int argc, char *argv[]) { \
    const UnitTest tests[] = {
#define XJWT_TESTS_ENTRY(entry) unit_test(entry),

#define XJWT_TESTS_END()   \
  }                        \
  ;                        \
  xjwt_tests_setup();      \
  return run_tests(tests); \
  }
#endif

#undef XJWT_ASSERT
#define XJWT_ASSERT(expression) \
  mock_assert((int)(expression), #expression, __FILE__, __LINE__);

#define XJWT_NO_ERROR(expression)                                     \
  do {                                                                \
    xjwt_error_t *xjwt__xx__err = NULL;                               \
    xjwt__xx__err = (expression);                                     \
    if (xjwt__xx__err != XJWT_SUCCESS) {                              \
      fprintf(stderr, "xjwt_error: %s\n", xjwt__xx__err->msg);        \
    }                                                                 \
    mock_assert(xjwt__xx__err == XJWT_SUCCESS, #expression, __FILE__, \
                __LINE__);                                            \
  } while (0)

#define XJWT_FAIL(expression)                                         \
  do {                                                                \
    xjwt_error_t *xjwt__xx__err = NULL;                               \
    xjwt__xx__err = (expression);                                     \
    if (xjwt__xx__err == XJWT_SUCCESS) {                              \
      fprintf(stderr, "xjwt_error: %s\n", xjwt__xx__err->msg);        \
    }                                                                 \
    mock_assert(xjwt__xx__err != XJWT_SUCCESS, #expression, __FILE__, \
                __LINE__);                                            \
    xjwt_error_destroy(xjwt__xx__err);                                \
  } while (0)

#define XJWT_TEST_MODULE(name) int xjwt_tests_##name();

XJWT_TEST_MODULE(keyset)
XJWT_TEST_MODULE(split)
XJWT_TEST_MODULE(verify)

#define PATHMAX 1024
extern char executable_path[PATHMAX];
extern char testdir_path[PATHMAX];

void xjwt_tests_setup();
void xjwt_load_fixture(const char *fname, char **outbuf, size_t *outlen);

#endif
