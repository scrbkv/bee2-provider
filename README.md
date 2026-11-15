# Bee2 Provider

## What is Bee2 Provider?

Bee2 Provider integrates the [Bee2](https://github.com/agievich/bee2)
cryptographic library with [OpenSSL](https://www.openssl.org/) through the
OpenSSL 3 provider interface. Algorithm names and behavior are compatible with
[bee2evp](https://github.com/bcrypto/bee2evp) where the provider interface
permits it.

## Algorithms

Bee2 Provider implements:

- BELT block ciphers: ECB, CBC, CFB, CTR, BDE and SDE;
- BELT authenticated encryption and key wrapping: CHE, DWP and KWP;
- BASH-PRG authenticated encryption;
- `belt-hash`, `bash256`, `bash384` and `bash512` digests;
- HMAC with `belt-hash`, `bash256`, `bash384` and `bash512`;
- `belt-mac128`, `belt-mac192` and `belt-mac256`;
- `belt-pbkdf`;
- `brng-ctr-hbelt` and `brng-hmac-hbelt` random generators;
  these deterministic generators require caller-supplied keys and do not
  independently obtain entropy or provide prediction resistance;
- `bign-256`, `bign-384` and `bign-512` key generation, signatures,
  Diffie--Hellman key agreement, key transport and PEM/DER encoding.

For BIGN signatures, `bign-with-hspec` uses an explicitly selected digest,
not a default digest. The digest must have a registered OID and produce 32,
48 or 64 bytes, matching the BIGN curve. Bee2 receives the DER-encoded
**digest OID**. The hSpec signature AlgorithmIdentifier carries this OID
as an ASN.1 OBJECT parameter. Selecting a compatible non-STB digest (for example, SHA-256
with `bign-256`) also selects the hSpec signature identifier. Digests with
fixed BIGN signature identifiers continue to use those identifiers.

BIGN keys in PKCS#8 and SPKI PEM/DER formats use the standard OpenSSL
`file:` store loader and this provider's key decoders. Load both the `default`
and `bee2_provider` providers when using `openssl storeutl`. The separate
`bign:` URI scheme is not supported.

BELT-ECB and BELT-CBC use PKCS#7 padding by default. Applications can disable
it with `EVP_CIPHER_CTX_set_padding(ctx, 0)` or `openssl enc -nopad`.
Without padding, inputs of at least 16 bytes are accepted, including a partial
last block: the provider uses Bee2's STB ciphertext stealing (CTS). An incomplete
block is retained until finalization, so the last one or two blocks can be
emitted by `EVP_CipherFinal_ex()`. With PKCS#7 enabled, plaintext may have any
length, but the result is PKCS#7-padded BELT, **not** the STB CTS construction.
BELT-CFB, BELT-CTR, BELT-CHE/DWP, BASH-PRG-AE and BELT-KWP accept non-aligned
input lengths. BELT-KWP requires at least 16 bytes of plaintext. BELT-BDE and
BELT-SDE still require complete 16-byte blocks (SDE requires at least 32 bytes).
BELT-CBC exposes its current chaining value through
`EVP_CIPHER_CTX_get_updated_iv()`; BELT-CFB and BELT-CTR also expose the
current byte offset through `OSSL_CIPHER_PARAM_NUM`.

BIGN key transport accepts a provider-specific `header` octet-string parameter
of exactly 16 bytes through `EVP_PKEY_CTX_set_params()`. Its default is an
all-zero header, preserving the original behavior. `belt-pbkdf` accepts
explicitly set zero-length passwords and salts.

## Requirements

- a C11 compiler;
- CMake 3.20 or newer;
- OpenSSL 3.0 or newer;
- Git.

## Build

```sh
git clone --recurse-submodules <repository-url> bee2-provider
cd bee2-provider

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

If the repository was cloned without submodules, initialize Bee2 separately:

```sh
git submodule update --init --recursive
```

To use a non-system OpenSSL installation, pass its prefix to CMake:

```sh
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DOPENSSL_ROOT_DIR=/path/to/openssl
cmake --build build --parallel
```

## Install

```sh
cmake --install build --prefix /usr/local
```

The provider module is installed into `lib/ossl-modules` below the selected
prefix by default. The directory can be changed at configure time:

```sh
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DBEE2_PROVIDER_INSTALL_DIR=lib/ossl-modules
```

## Configure OpenSSL

The provider can be activated in `openssl.cnf`:

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

The module filename is platform-specific. Use `.dylib` on macOS and `.dll` on
Windows where applicable.

The provider can also be loaded directly from the build directory:

```sh
OPENSSL_CONF=/dev/null \
OPENSSL_MODULES="$PWD/build" \
openssl list -provider bee2_provider -providers
```

List the available implementations with the corresponding OpenSSL command:

```sh
OPENSSL_CONF=/dev/null \
OPENSSL_MODULES="$PWD/build" \
openssl list -provider default -provider bee2_provider -cipher-algorithms
```

Replace `-cipher-algorithms` with `-digest-algorithms`, `-mac-algorithms`,
`-kdf-algorithms`, `-random-generators`, `-signature-algorithms` or
`-key-managers` as required.

## Testing

The public test suite is included in this repository. From a recursive clone:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DBEE2_PROVIDER_BUILD_TESTS=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

GitHub Actions verifies Linux builds against pinned OpenSSL 3.0, 3.5, 4.0
and 4.1 releases, runs ASan/UBSan checks, and builds a separate `bee2evp`
engine for fixed, boundary and deterministic pseudorandom interoperability
tests. EVP streaming and BIGN public-key validation regressions are part of
the standard CTest suite. See [STB coverage](docs/STB_COVERAGE.md),
[Testing](docs/TESTING.md), [CI](docs/CI.md) and
[Contributing](CONTRIBUTING.md) for details.

**Security note:** successful functional tests are not a security audit. The
provider has not been independently audited or FIPS validated.

## License

Bee2 Provider is distributed under the Apache License, Version 2.0. See
[`LICENSE`](LICENSE). Bee2 is distributed under its own Apache-2.0 license;
see [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
