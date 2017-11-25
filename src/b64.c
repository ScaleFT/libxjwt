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

#include "internal/xjwt_b64.h"

#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

static char *b64_mutate_url_to_normal(const char *input) {
  size_t i = 0;
  size_t inlen = strlen(input);
  size_t outlen = inlen + ((4 - inlen % 4) % 4);
  char *output = calloc(1, outlen + 1);
  for (; input[i] != 0; i++) {
    char c = input[i];
    switch (c) {
      case '-':
        output[i] = '+';
        break;
      case '_':
        output[i] = '/';
        break;
      default:
        output[i] = c;
        break;
    }
  }
  for (; i < outlen; i++) {
    output[i] = '=';
  }
  return output;
}

static size_t b64_decode_len(const char *src, size_t len) {
  size_t p = 0;

  if (len < 4) {
    /* invalid base64 src.  prob empty string */
    return 0;
  }

  if (src[len - 1] == '=' && src[len - 2] == '=') {
    p = 2;
  } else if (src[len - 1] == '=') {
    p = 1;
  }
  return (len * 3) / 4 - p;
}

XJWT_API(xjwt_error_t *)
xjwt__url_base64_decode(const char *xsrc, char **out, size_t *len) {
  BIO *b64;
  BIO *bio;
  size_t outlen;
  char *outbuf;
  /**
   * TODO(pquerna): implement URL safe natively using a table
   * (using a BIO requires a bunch of allocs and i'm are doing this
   * in an ultra terrible way)
   */
  char *src = b64_mutate_url_to_normal(xsrc);
  size_t slen = strlen(src);

  outlen = b64_decode_len(src, slen);
  if (outlen == 0) {
    free(src);
    return xjwt_error_create(
        XJWT_EINVAL, "xjwt_b64: invalid base64 data: less than 4 bytes");
  }

  outbuf = calloc(1, outlen + 1);

  bio = BIO_new_mem_buf(src, slen);
  b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bio = BIO_push(b64, bio);

  /* NOTE: not sure if we should assert outlen === expected outlen. */
  outlen = BIO_read(bio, outbuf, outlen);
  BIO_free_all(bio);

  if (outlen <= 0) {
    free(src);
    free(outbuf);
    return xjwt_error_create(XJWT_EINVAL, "xjwt: failed to decode base64");
  }
  free(src);

  *out = outbuf;
  if (len != NULL) {
    *len = outlen;
  }

  return XJWT_SUCCESS;
}
