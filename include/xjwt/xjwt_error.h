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

/* Based off of ETL's error types (which is based off of Subversion's) */

/**
 * @file xjwt_error.h
 */

#include <stdint.h>
#include "xjwt_visibility.h"

#ifndef _xjwt_error_h_
#define _xjwt_error_h_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * Check if the @c xjwt_error_t returned by @a expression is equal to
 * @c XJWT_SUCCESS.  If it is, do nothing, if not, then return it.
 */
#define XJWT_ERR(expression)                    \
  do {                                          \
    xjwt_error_t* xjwt__xx__err = (expression); \
    if (xjwt__xx__err) return xjwt__xx__err;    \
  } while (0)

/** A low level error code. */
typedef int xjwt_status_t;

/** Successful return value for a function that returns @c xjwt_error_t. */
#define XJWT_SUCCESS NULL

/** The available buffer space was exhausted. */
#define XJWT_ENOSPACE -1

/** The input was invalid. */
#define XJWT_EINVAL -2

/** The requested functionality has not been implemented. */
#define XJWT_ENOTIMPL -3

/** The I/O operation in question failed. */
#define XJWT_EIO -4

/* Unable to allocate memory */
#define XJWT_ENOMEM -5

/** An exception object. */
typedef struct {
  /** The underlying status code. */
  xjwt_status_t err;

  /** A human readable error message. */
  const char* msg;

  /** The line on which the error occurred. */
  uint32_t line;

  /** The file in which the error occurred. */
  const char* file;
} xjwt_error_t;

/**
 * Return a new @c xjwt_error_t with underlying @c xjwt_status_t @a err
 * and message @a msg.
 */
#define xjwt_error_create(err, msg) \
  xjwt_error_create_impl(err, msg, __LINE__, __FILE__)

/**
 * The underlying function that implements @c xjwt_error_t_error_create.
 *
 * This is an implementation detail, and should not be directly called
 * by users.
 */
XJWT_API(xjwt_error_t*)
xjwt_error_create_impl(xjwt_status_t err, const char* msg, uint32_t line,
                       const char* file);

/**
 * Return a new @c xjwt_error_t with underlying @c xjwt_status_t @a err
 * and message created @c printf style with @a fmt and varargs.
 */
#define xjwt_error_createf(err, fmt, ...) \
  xjwt_error_createf_impl(err, __LINE__, __FILE__, fmt, __VA_ARGS__)

/**
 * The underlying function that implements @c xjwt_error_createf.
 *
 * This is an implementation detail, and should not be directly called
 * by users.
 */
XJWT_API(xjwt_error_t*)
xjwt_error_createf_impl(xjwt_status_t err, uint32_t line, const char* file,
                        const char* fmt, ...);

/** Destroy @a err. */
XJWT_API(void)
xjwt_error_destroy(xjwt_error_t* err);

/** Duplicates an error object */
XJWT_API(xjwt_error_t*)
xjwt_error_dup(xjwt_error_t* err);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
