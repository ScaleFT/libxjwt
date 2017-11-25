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

#ifndef _xjwt_internal_json_h_
#define _xjwt_internal_json_h_

#include <stddef.h>

#include "xjwt/xjwt_error.h"
#include "xjwt/xjwt_visibility.h"

#include <jansson.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

XJWT_API(const char *)
xjwt_json_strdup(json_t *doc, const char *key);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* _xjwt_internal_json_h_ */
