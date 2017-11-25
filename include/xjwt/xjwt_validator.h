/**
 *  Copyright 2017, ScaleFT Inc
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
 *
 */

#ifndef _xjwt_validator_h_
#define _xjwt_validator_h_

#include <time.h>

#include <jansson.h>

#include "xjwt_error.h"
#include "xjwt_keyset.h"
#include "xjwt_visibility.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * JWT Validation Functions
 */
typedef struct xjwt_validator_t xjwt_validator_t;

typedef uint64_t(xjwt_time_cb)(void* baton);

typedef struct xjwt_verify_options_t {
  /* Baton passed into all callbacks */
  void* baton;

  xjwt_time_cb* now;
  xjwt_keyset_t* keyset;

  const char* expected_issuer;
  const char* expected_subject;
  const char* expected_audience;
} xjwt_verify_options_t;

typedef struct xjwt_verify_success_t {
  json_t* payload;
} xjwt_verify_success_t;

typedef enum XJWT_VERIFY_FAILURES {
  XJWT_VERIFY_UNKNOWN = 0,
  XJWT_VERIFY_NOT_PRESENT = 1,
  XJWT_VERIFY_EXPIRED = 2,
  XJWT_VERIFY_INVALID_SIGNATURE = 3,
  XJWT_VERIFY_NO_VALIDATORS = 4,
  XJWT_VERIFY_MALFORMED = 5,
  XJWT_VERIFY_EXPECT_MISMATCH = 6
} XJWT_VERIFY_FAILURES;

/**
 * Contains an enum of possible reasons valilcation failed for a JWT.
 *
 * *err may be empty, but reason will always contain a reason.
 *
 **/
typedef struct xjwt_verify_failure_t {
  XJWT_VERIFY_FAILURES reason;
  xjwt_error_t* err;
} xjwt_verify_failure_t;

/**
 * Verifies a JWT according to a strict sub-set of the JWT standards meant to
 * intersect with real world use cases.
 *
 * On Success, *outsucess is set to non-NULL.
 * On Failure, *outfailure is set to non-NULL and explains why verification
 * failed.
 */
XJWT_API(void)
xjwt_verify(xjwt_verify_options_t* opts, const char* data, size_t len,
            xjwt_verify_success_t** outsuccess,
            xjwt_verify_failure_t** outfailure);

XJWT_API(void) xjwt_verify_success_destroy(xjwt_verify_success_t* success);

XJWT_API(void) xjwt_verify_failure_destroy(xjwt_verify_failure_t* fail);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* _xjwt_validator_h_ */
