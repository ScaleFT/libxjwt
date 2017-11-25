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

#ifndef _xjwt_keyset_t_
#define _xjwt_keyset_t_

#include <stddef.h>

#include "xjwt_error.h"
#include "xjwt_visibility.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct xjwt_keyset_t xjwt_keyset_t;

XJWT_API(xjwt_error_t*)
xjwt_keyset_create_from_memory(const char* buffer, size_t buflen,
                               xjwt_keyset_t** ks);

XJWT_API(void) xjwt_keyset_destroy(xjwt_keyset_t* ks);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* _xjwt_keyset_t_ */
