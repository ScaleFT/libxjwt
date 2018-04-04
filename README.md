# libxjwt: minimal C library for validation of real-world JWTs

[![Build Status](https://travis-ci.org/ScaleFT/libxjwt.svg?branch=master)](https://travis-ci.org/ScaleFT/libxjwt)

`libxjwt` seeks to provide a minimal c89-style library and API surface for validating a compact-form JWT against a set of JWKs. This is not meant to be a general purpose JOSE library.  If you are looking for a more general purpose C library, consider [cjose](https://github.com/cisco/cjose).

# What's New

## 1.0.3 (in development)

## 1.0.2

- Add autotools based build (classic `./configure && make && make install`) [#9](https://github.com/ScaleFT/libxjwt/pull/9)
- Add spec file for RPM Packaging  [#8](https://github.com/ScaleFT/libxjwt/pull/8)

## 1.0.1

- Support for API changes in OpenSSL version 1.1 [#5](https://github.com/ScaleFT/libxjwt/pull/5)

## 1.0.0

- Initial open source release.

## API

`libxjwt` exports two primary API surfaces:

1) Validating a JWT using the `xjwt_verify` function in [xjwt_validator.h](./include/xjwt/xjwt_validator.h)
2) Loading a JWK keyset, using `xjwt_keyset_create_from_memory` function in [xjwt_keyset.h](./include/xjwt/xjwt_keyset.h)

An example of using these APIs is in [test_verify.c](./tests/test_verify.c)

## Dependencies

- [OpenSSL](https://www.openssl.org/): libxjwt uses EC and EVP APIs.
- [Jansson](http://www.digip.org/jansson/): JSON Parser

## Building

### RPM base Distributions

Assuming a proper rpmbuild environment exists on the build host, a pair of rpms (bin and devel), can be built using the included spec file like so:

```
rpmbuild --undefine=_disable_source_fetch -bb dist/rpm/libxjwt.spec
```

### Ubuntu Xenial

```
sudo apt-get update
sudo apt-get upgrade -y
sudo apt-get install autoconf-archive libjansson-dev libssl-dev build-essential -y
git clone https://github.com/ScaleFT/libxjwt.git
cd libxjwt/
./configure
make
sudo make install
```

### Others

After Jansson and OpenSSL development headers are available, building libxjwt should just take:

```
./configure
make
make install
```

## Security Model

ScaleFT takes security seriously. If you discover a security issue, please bring it to our attention right away!

Please DO NOT file a public issue or pull request, [instead send your report privately to the ScaleFT Security Team](https://www.scaleft.com/company/security/), reachable at [security@scaleft.com](mailto:security@scaleft.com).

`libxjwt` is commonly used in parsing untrusted data from network sources, as such we have tried to be careful and take this into consideration in design of the library.

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
