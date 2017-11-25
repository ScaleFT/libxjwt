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

#include "internal/xjwt_parse.h"
#include "internal/xjwt_b64.h"

#include <openssl/ecdsa.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

XJWT_API(xjwt_error_t *)
xjwt__parse_untrusted(const char *input, size_t len, xjwt_parsed_t **out) {
  xjwt_error_t *err = XJWT_SUCCESS;
  size_t i = 0;
  int count = 0;
  xjwt_parsed_t *rv = NULL;
  char *header = NULL;
  char *payload = NULL;
  char *signature = NULL;
  char *header_decoded = NULL;
  size_t header_decoded_l = 0;
  char *signature_decoded = NULL;
  size_t signature_decoded_l = 0;
  char *buf = calloc(1, len + 1);

  header = buf;

  for (; i < len; i++) {
    char c = input[i];
    switch (c) {
      case '.':
        buf[i] = 0;
        switch (count) {
          case 0:
            payload = buf + i + 1;
            break;
          case 1:
            signature = buf + i + 1;
            break;
          default:
            free(buf);
            return xjwt_error_create(
                XJWT_EINVAL, "xjwt_verify: invalid JWT: too many periods");
        }
        count++;
        break;
      default:
        buf[i] = c;
        break;
    }
  }

  if (count != 2) {
    free(buf);
    return xjwt_error_create(XJWT_EINVAL,
                             "xjwt_verify: invalid JWT: missing periods");
  }

  err = xjwt__url_base64_decode(header, &header_decoded, &header_decoded_l);
  if (err != XJWT_SUCCESS) {
    free(buf);
    return err;
  }

  err = xjwt__url_base64_decode(signature, &signature_decoded,
                                &signature_decoded_l);
  if (err != XJWT_SUCCESS) {
    free(buf);
    free(header_decoded);
    return err;
  }

  rv = calloc(1, sizeof(xjwt_parsed_t));
  rv->header_decoded = header_decoded;
  rv->header_decoded_l = header_decoded_l;
  rv->signature_decoded = signature_decoded;
  rv->signature_decoded_l = signature_decoded_l;
  rv->header = strdup(header);
  rv->payload = strdup(payload);
  rv->signature = strdup(signature);
  rv->signed_data_l = strlen(header) + strlen(payload) + 1;
  rv->signed_data = calloc(1, rv->signed_data_l + 1);
  /* TODO(pquenra): this is stupid / lazy */
  snprintf((char *)rv->signed_data, rv->signed_data_l + 1, "%s.%s", header,
           payload);

  *out = rv;

  free(buf);
  return XJWT_SUCCESS;
}

XJWT_API(void) xjwt__parsed_destroy(xjwt_parsed_t *p) {
  if (p != NULL) {
    if (p->header != NULL) {
      free((void *)p->header);
    }
    if (p->header_decoded != NULL) {
      free((void *)p->header_decoded);
    }
    if (p->payload != NULL) {
      free((void *)p->payload);
    }
    if (p->signature != NULL) {
      free((void *)p->signature);
    }
    if (p->signature_decoded != NULL) {
      free((void *)p->signature_decoded);
    }
    if (p->signed_data != NULL) {
      free((void *)p->signed_data);
    }

    free(p);
  }
}

XJWT_API(xjwt_error_t *)
xjwt__parse_payload(xjwt_parsed_t *jwt, json_t **doc) {
  xjwt_error_t *err = XJWT_SUCCESS;
  json_error_t jerror;
  char *decoded = NULL;
  json_t *payload;
  size_t dlen = 0;

  err = xjwt__url_base64_decode(jwt->payload, &decoded, &dlen);
  if (err != XJWT_SUCCESS) {
    return err;
  }

  payload = json_loadb(decoded, dlen, 0, &jerror);
  if (payload == NULL) {
    free(decoded);
    return xjwt_error_createf(
        XJWT_EINVAL, "xjwt_verify: payload failed to parse: %s @ %d:%d",
        jerror.text, jerror.line, jerror.column);
  }

  free(decoded);
  *doc = payload;
  return XJWT_SUCCESS;
}

XJWT_API(xjwt_error_t *)
xjwt__parse_ec_signature(xjwt_parsed_t *jwt, const char **outecsig,
                         size_t *outlen) {
  unsigned char *p = NULL;
  size_t len;
  size_t offset = jwt->signature_decoded_l / 2;
  ECDSA_SIG *sig = ECDSA_SIG_new();

  /* TODO(pquerna): assert signature size constraints here? */
  BN_bin2bn((const unsigned char *)jwt->signature_decoded,
            jwt->signature_decoded_l / 2, sig->r);
  BN_bin2bn((const unsigned char *)jwt->signature_decoded + offset,
            jwt->signature_decoded_l / 2, sig->s);

  len = i2d_ECDSA_SIG(sig, &p);
  if (len <= 0) {
    ECDSA_SIG_free(sig);
    return xjwt_error_create(XJWT_ENOMEM, "xjwt_verify: i2d_ECDSA_SIG failed");
  }

  *outecsig = calloc(1, len + 1);
  memcpy((void *)*outecsig, p, len);
  *outlen = len;

  ECDSA_SIG_free(sig);
  if (p) {
    OPENSSL_free(p);
  }
  return XJWT_SUCCESS;
}
