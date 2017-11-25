# libxjwt: minimal C library for validation of real-world JWTs

[![Build Status](https://travis-ci.org/ScaleFT/libxjwt.svg?branch=master)](https://travis-ci.org/ScaleFT/libxjwt)

`libxjwt` seeks to provide a minimal c89-style library and API surface for validating a compact-form JWT against a set of JWKs. This is not meant to be a general purpose JOSE library.  If you are looking for a more general purpose C library, consider [cjose](https://github.com/cisco/cjose).

# Whats New

## 1.0.0

Initial open source release.

## API

`libxjwt` exports two primary API surfaces:

1) Validating a JWT using the `xjwt_verify` function in [xjwt_validator.h](./include/xjwt/xjwt_validator.h)
2) Loading a JWK keyset, using `xjwt_keyset_create_from_memory` function in [xjwt_keyset.h](./include/xjwt/xjwt_keyset.h)

An example of using these APIs is in [test_verify.c](./tests/test_verify.c)

## Dependencies

- [OpenSSL](https://www.openssl.org/): libxjwt uses EC and EVP APIs.
- [Jansson](http://www.digip.org/jansson/): JSON Parser
- (build-only) c89 compiler
- (build-only) scons

## Security

`libxjwt` is commonly used in parsing untrusted data from network sources. 

- Compact form JWTs are limited to 16kb maximum size.
- `libxjwt` only supports the `ES256`, `ES384` and `ES521` algorithm types for signature validation.
- Before cryptographic verification of a JWT, `libxjwt` must parse some data:
  - Splitting the compact form into header, payload and signature.  This is done by the `xjwt__parse_untrusted` function in [parse.c](./src/parse.c)
  - Decoding the JWT Header.  This requires a url-safe base64 decoding.  This is currently implemented by using OpenSSL's Base64 BIOs in [b64.c](./src/b64.c).
  - Parsing the JWT Header object.  This pases data to the Jansson's `json_loads`(http://jansson.readthedocs.io/en/2.8/apiref.html#c.json_loads) function in [validator.c](./src/validator.c)
  - Parsing the JWT Signature. This is done by `xjwt__parse_ec_signature` function in [parse.c](./src/parse.c).
  - Validation of the EC Signature for the Header+Payload is done using OpenSSL's EVP API.

# License

`libxjwt` is licensed under the Apache License Version 2.0. See the [LICENSE file](./LICENSE) for details.