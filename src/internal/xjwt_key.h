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

#ifndef _xjwt_internal_key_h_
#define _xjwt_internal_key_h_

#include <stddef.h>

#include "xjwt/xjwt_error.h"
#include "xjwt/xjwt_visibility.h"

#include <jansson.h>
#include <openssl/evp.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct xjwt_key_t {
  struct xjwt_key_t* next;

  const char* key_type;
  const char* key_id;
  const char* algorithm;
  const char* use;

  EVP_PKEY* evp;
} xjwt_key_t;

XJWT_API(xjwt_error_t*)
xjwt_key_create_from_json(json_t* doc, xjwt_key_t** out);

XJWT_API(void) xjwt_key_destroy(xjwt_key_t* ks);

XJWT_API(xjwt_error_t*)
xjwt_key__parse_ec(json_t* doc, xjwt_key_t* key);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* _xjwt_internal_key_h_ */
