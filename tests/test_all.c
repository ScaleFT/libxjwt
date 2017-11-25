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
#include "xjwt_tests.h"
#include <stdio.h>

#define RUNT(module)                \
  do {                              \
    int rv = xjwt_tests_##module(); \
    if (rv != 0) {                  \
      return rv;                    \
    }                               \
  } while (0);

int main(int argc, char* argv[]) {
  xjwt_tests_setup();

  RUNT(keyset);
  RUNT(split);
  RUNT(verify);

  return 0;
}
