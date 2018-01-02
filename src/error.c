/**
 * Copyright 2017, ScaleFT Inc
 * Copyright 2007-2010 Paul Querna.
 * Copyright 2006 Garrett Rooney.
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

#ifdef __linux__
#define _GNU_SOURCE
#endif

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xjwt/xjwt_error.h"

xjwt_error_t* xjwt_error_create_impl(xjwt_status_t err, const char* msg,
                                     uint32_t line, const char* file) {
  xjwt_error_t* e;

  e = malloc(sizeof(*e));

  e->err = err;
  e->msg = strdup(msg);
  e->line = line;
  e->file = strdup(file);

  return e;
}

xjwt_error_t* xjwt_error_createf_impl(xjwt_status_t err, uint32_t line,
                                      const char* file, const char* fmt, ...) {
  int rv;
  xjwt_error_t* e;
  va_list ap;

  e = malloc(sizeof(*e));

  e->err = err;

  va_start(ap, fmt);
  rv = vasprintf((char**)&e->msg, fmt, ap);
  va_end(ap);

  if (rv == -1) {
    e->msg = strdup(
        "vasprintf inside xjwt_error_createf_impl returned -1, you likely "
        "have larger problems here");
  }

  e->line = line;
  e->file = strdup(file);

  return e;
}

xjwt_error_t* xjwt_error_dup(xjwt_error_t* err) {
  xjwt_error_t* e;

  e = malloc(sizeof(*e));

  e->err = err->err;
  e->msg = strdup(err->msg);
  e->line = err->line;
  e->file = strdup(err->file);

  return e;
}

void xjwt_error_destroy(xjwt_error_t* err) {
  if (err) {
    free((void*)err->msg);
    free((void*)err->file);
    free(err);
  }
}
