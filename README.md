# Bee2 OpenSSL Provider

An OpenSSL 3.x/4.x provider backed by the [Bee2](https://github.com/agievich/bee2)
cryptographic library. Algorithm names and interoperability behavior follow
[bee2evp](https://github.com/bcrypto/bee2evp).

The project is under active development. It has not undergone an independent
security audit and must not be treated as a validated or FIPS provider.

## Supported operations

- Ciphers: BELT ECB, CBC, CFB, CTR, BDE, SDE, CHE, DWP and KWP; BASH-PRG-AE.
- Digests: `belt-hash`, `bash256`, `bash384`, `bash512`.
- MACs: `belt-hmac` with `belt-hash`, `bash256`, `bash384` or `bash512` as
  the selected digest; `belt-mac128`, `belt-mac192`, `belt-mac256`.
- KDF: `belt-pbkdf`.
- Random generators: `brng-ctr-hbelt`, `brng-hmac-hbelt`.
- Public-key operations: BIGN key management, signatures, Diffie--Hellman
  agreement (raw or with BAKE-KDF), key transport, PEM/DER codecs and store
  loading for the 256-, 384- and 512-bit curves.

BIGN uses three fixed key types: `bign-256`, `bign-384` and `bign-512`.
Key generation therefore needs no separate curve parameter. Deterministic
signatures accept the standard `deterministic` parameter and the
bee2evp-compatible `sig:deterministic` spelling. BIGN key encoding accepts
`encoding:explicit` or the compatible `enc_params:specified`;
`enc_params:cofactor` includes the optional cofactor in explicit domain
parameters.

The GitLab development repository contains the authoritative export-parity and
interoperability tests. BELT BDE/SDE and the additional BASH-PRG-AE parameter
sets are documented provider-native extensions; CI rejects any other
accidental exports.

The four legacy bee2evp TLS record-cipher aliases are deliberately not
exported. CHE, DWP and BASH-PRG-AE use the OpenSSL provider AEAD interface:
the authentication tag is read or supplied separately through
`OSSL_CIPHER_PARAM_AEAD_TAG`.

BELT-CFB and BELT-CTR accept a final partial block. ECB, CBC, BDE and SDE
require block-aligned input with provider padding disabled; adding and removing
padding is the caller's responsibility.

BELT-SDE and BELT-KWP are whole-message constructions. Each EVP operation
therefore accepts exactly one non-empty `EVP_EncryptUpdate` or
`EVP_DecryptUpdate`; split-input streaming is intentionally rejected.

## Requirements

- C11 compiler;
- CMake 3.20 or newer;
- OpenSSL 3.0 or newer development files;
- Python 3 when tests are enabled;
- Git for initializing the Bee2 submodule.

## Build and test

```sh
git clone --recurse-submodules <repository-url> bee2-provider
cd bee2-provider
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

The complete GitLab checkout can enable its test suite explicitly:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DBEE2_PROVIDER_BUILD_TESTS=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure -LE interop
```

Interop tests additionally require a working bee2evp installation. Their
OpenSSL executable, engine and environment are configured through
`BEE2EVP_OPENSSL`, `BEE2EVP_ENGINE`, `BEE2EVP_LD_LIBRARY_PATH` and
`BEE2EVP_OPENSSL_CONF`.

## Load without installing

```sh
OPENSSL_MODULES="$PWD/build" \
OPENSSL_CONF=/dev/null \
openssl list -provider bee2_provider -providers
```

To list the algorithms, add the default provider and select the required
operation, for example:

```sh
OPENSSL_MODULES="$PWD/build" OPENSSL_CONF=/dev/null \
openssl list -provider default -provider bee2_provider -cipher-algorithms
```

## Install

By default, the module is installed below `lib/ossl-modules` relative to the
chosen prefix. Override the directory when the target OpenSSL installation
uses another module path.

```sh
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DBEE2_PROVIDER_BUILD_TESTS=OFF \
  -DBEE2_PROVIDER_INSTALL_DIR=lib/ossl-modules
cmake --build build --parallel
cmake --install build --prefix /usr/local
```

An OpenSSL configuration can activate the installed module:

```ini
openssl_conf = openssl_init

[openssl_init]
providers = provider_section

[provider_section]
default = default_section
bee2_provider = bee2_section

[default_section]
activate = 1

[bee2_section]
module = /usr/local/lib/ossl-modules/bee2_provider.so
activate = 1
```

The extension is platform-specific (`.so`, `.dylib` or `.dll`). Confirm the
actual OpenSSL module directory with the packaging rules of the target system.

## Security and compatibility

Secret buffers are cleared before release, authentication comparisons are
constant-time, and CI runs KAT, interoperability and sanitizer checks. See
`SECURITY.md` for vulnerability reporting and supported release policy.

The GitLab pipeline currently qualifies Linux x86-64. Windows and macOS code
paths are best-effort until dedicated runners are added.

## License

This project is licensed under the Apache License, Version 2.0. See `LICENSE`.
Bee2 remains governed by its own Apache-2.0 license; see
`THIRD_PARTY_NOTICES.md`.
