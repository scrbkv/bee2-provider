# Bee2 Provider

Bee2 Provider makes Belarusian STB cryptographic algorithms from the
[Bee2 library](https://github.com/agievich/bee2) available through the
[OpenSSL 3 provider API](https://docs.openssl.org/3.0/man7/provider/).
It supports OpenSSL EVP, provider-based key management, encoding and decoding.

## Algorithms

| Family | Interfaces |
| --- | --- |
| BELT | ECB, CBC, CFB, CTR, BDE, SDE; DWP, CHE; KWP-128/192/256; BELT-Hash; BELT-MAC-128/192/256; BELT-PBKDF |
| BASH | BASH-256/384/512; BASH-PRG-AE (128/192/256, profiles 1 and 2) |
| HMAC | HMAC with BELT-Hash and BASH-256/384/512 |
| BRNG | BRNG-CTR-HBELT, BRNG-HMAC-HBELT |
| BIGN | BIGN-256/384/512 key generation, signatures, key agreement, key transport, PKCS#8/SPKI DER and PEM |

BIGN supports named curve identifiers and explicit parameters. Signature
algorithms include BIGN with BELT-Hash, BASH digests and explicit hSpec digest
identifiers. With `bign-with-hspec`, select a digest of the appropriate length
and a registered digest OID; hSpec signature identifiers contain its OID as
an ASN.1 OBJECT parameter.

The supported algorithm identifiers and normative test references are listed in
[STB algorithms and test vectors](docs/STB_COVERAGE.md).

## Requirements and build

- C11 compiler and CMake 3.20 or newer
- OpenSSL 3.0 or newer (headers, libcrypto and command-line utility)
- Git for the Bee2 submodule

```sh
git clone --recurse-submodules https://github.com/scrbkv/bee2-provider.git
cd bee2-provider
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

With a separately installed OpenSSL, configure
`-DOPENSSL_ROOT_DIR=/path/to/openssl`. The runtime dynamic linker must load
`libcrypto` from the same OpenSSL installation used for building the provider.

## Installation and loading

```sh
cmake --install build --prefix /usr/local
```

By default the module is installed under `lib/ossl-modules` within the prefix.
Set `BEE2_PROVIDER_INSTALL_DIR` at CMake configuration time to choose another
relative module directory. The actual module filename depends on the platform.

For a session using the build-tree module:

```sh
OPENSSL_CONF=/dev/null OPENSSL_MODULES="$PWD/build" \
    openssl list -provider default -provider bee2_provider -providers
OPENSSL_CONF=/dev/null OPENSSL_MODULES="$PWD/build" \
    openssl list -provider default -provider bee2_provider -cipher-algorithms
```

For persistent loading, configure the provider in `openssl.cnf`:

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

Set `module` to the actual installed path. Load the `default` provider alongside
`bee2_provider` for standard ciphers, ASN.1 decoder chaining and `file:` STORE.

Use `openssl list -provider default -provider bee2_provider` with
`-digest-algorithms`, `-mac-algorithms`, `-kdf-algorithms`,
`-random-generators`, `-signature-algorithms` or `-key-managers` to inspect
other interfaces.

## Encrypted BIGN private keys

BIGN private keys use PKCS#8 `PrivateKeyInfo` and
`EncryptedPrivateKeyInfo`; public keys use `SubjectPublicKeyInfo`. Both DER
and PEM encodings are supported. The OpenSSL `file:` STORE loader is supported.

When an application explicitly requests private-key encryption through
`OSSL_ENCODER_CTX_set_cipher()`, `"default"` selects BELT-KWP-256. The
STB PBES2 profile uses OpenSSL's `X509_SIG`, `PBE2PARAM` and `PBKDF2PARAM`
ASN.1 structures with PBKDF2-HMAC-HBELT and BELT-KWP-256. The PBKDF2 PRF and
KWP `AlgorithmIdentifier` parameters are ASN.1 `NULL`, as required by
STB 34.101.45, Annex E. The BELT-KWP authentication header is 16 zero bytes.

Applications may explicitly request `belt-kwp128` or `belt-kwp192` as
additional BELT-KWP variants. The precisely specified Annex E BIGN profile
uses the 256-bit key. Standard CBC ciphers such as `AES-256-CBC`,
`AES-192-CBC` or `AES-128-CBC` select OpenSSL's native PBES2/PBKDF2
implementation instead of the STB profile. An encoder without an encryption
request writes unencrypted PKCS#8.

The STB PBES2 encoder defaults to 10,000 iterations and a fresh 16-byte salt.
Use `OSSL_ENCODER_CTX_set_params()` with `stb-pbkdf2-iterations` (unsigned int)
and `stb-pbkdf2-saltlen` (`size_t`) to customize these values. The encoder
requires at least 10,000 iterations and 8 salt bytes, following the guidance
in Annex E. These minimums are a key-container policy; the standalone
`belt-pbkdf` primitive follows its own algorithm contract.

The STB private-key decoder permits at most 1,000,000 PBKDF2 iterations by
default. Applications can adjust this limit using decoder context parameter
`stb-pbkdf2-max-decode-iterations` (unsigned int, at least 10,000).
This bound applies to the provider's STB and standard-PBKDF2 decoding paths,
not to unrelated OpenSSL decoders. Passwords and plaintext key material are
cleared from provider temporary buffers on cleanup.

## Cipher behavior

BELT-ECB and BELT-CBC use PKCS#7 padding by default. Disable padding with
`EVP_CIPHER_CTX_set_padding(ctx, 0)` or `openssl enc -nopad` for STB
ciphertext stealing. Nonaligned CTS input must contain at least one complete
16-byte block, and the final partial input must be supplied in a single
`EVP_CipherUpdate()` operation. Aligned input can be streamed across updates.
With padding enabled, the output is PKCS#7 ciphertext rather than STB CTS.

BELT-CFB, BELT-CTR, BELT-DWP, BELT-CHE, BELT-KWP and BASH-PRG-AE accept
non-block-aligned data. BELT-KWP requires at least 16 plaintext bytes.
BELT-BDE requires whole 16-byte blocks; BELT-SDE requires whole sectors of at
least 32 bytes, also a multiple of 16. `EVP_CIPHER_CTX_get_updated_iv()`
reports CBC chaining state, while CFB and CTR expose the current byte offset
through `OSSL_CIPHER_PARAM_NUM`.

BIGN key transport accepts a 16-byte provider-specific `header` octet-string
parameter through `EVP_PKEY_CTX_set_params()`. Its default is all zeroes.
BRNG instances require caller-provided key material; they do not automatically
collect entropy or independently offer prediction resistance.

## Testing and project resources

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
    -DBEE2_PROVIDER_BUILD_TESTS=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

The suite covers published STB known-answer examples, EVP contracts, key
encoding/decoding, interoperability and error handling. GitHub Actions tests
selected OpenSSL releases on Linux, runs ASan/UBSan and a separate `bee2evp`
interoperability matrix. See [Testing](docs/TESTING.md) and
[CI](docs/CI.md).

Security issues should be reported privately as described in
[Security Policy](SECURITY.md). The project is not FIPS validated.

## License

Apache License 2.0. See [LICENSE](LICENSE) and
[Third-party notices](THIRD_PARTY_NOTICES.md) for the Bee2 dependency.
