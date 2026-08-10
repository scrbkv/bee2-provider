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
- `bign-256`, `bign-384` and `bign-512` key generation, signatures,
  Diffie--Hellman key agreement, key transport and PEM/DER encoding.

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

## License

Bee2 Provider is distributed under the Apache License, Version 2.0. See
[`LICENSE`](LICENSE). Bee2 is distributed under its own Apache-2.0 license;
see [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
