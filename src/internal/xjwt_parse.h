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

#ifndef _xjwt_internal_parse_h_
#define _xjwt_internal_parse_h_

#include "xjwt/xjwt_error.h"
#include "xjwt/xjwt_visibility.h"

#include <stddef.h>
#include <jansson.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct xjwt_parsed_t {
  /* fields that are split into untrusted parts */
  const char *header;
  size_t header_decoded_l;
  const char *header_decoded;
  const char *payload;
  const char *signature;
  size_t signature_decoded_l;
  const char *signature_decoded;
  size_t signed_data_l;
  const char *signed_data;
} xjwt_parsed_t;

XJWT_API(xjwt_error_t *)
xjwt__parse_untrusted(const char *input, size_t len, xjwt_parsed_t **out);

XJWT_API(void) xjwt__parsed_destroy(xjwt_parsed_t *p);

XJWT_API(xjwt_error_t *)
xjwt__parse_ec_signature(xjwt_parsed_t *jwt, const char **outecsig,
                         size_t *outlen);

XJWT_API(xjwt_error_t *)
xjwt__parse_payload(xjwt_parsed_t *jwt, json_t **doc);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* _xjwt_internal_parse_h_ */
