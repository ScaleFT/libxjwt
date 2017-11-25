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

#ifndef _xjwt_internal_keyset_h_
#define _xjwt_internal_keyset_h_

#include "xjwt_key.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct xjwt_keyset_t {
  xjwt_key_t* keys;
};

XJWT_API(xjwt_key_t*)
xjwt_keyset__get_by_keyid(xjwt_keyset_t* ks, const char* keyid);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* _xjwt_internal_keyset_h_ */
