# Testing Bee2 Provider

The public test suite lives in `tests/`. It runs against the OpenSSL
installation selected at CMake configuration time, not necessarily the system
installation. The tested OpenSSL executable and `libcrypto` must belong to the
same OpenSSL build.

## Standard build

Clone the GitHub repository with its Bee2 submodule:

```sh
git clone --recurse-submodules https://github.com/scrbkv/bee2-provider.git
cd bee2-provider
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
    -DBEE2_PROVIDER_BUILD_TESTS=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

The tests use public OpenSSL APIs. The native `bee2_stb_kat` executable
checks published STB answers for BELT, BASH, HMAC-HBELT, key wrapping,
PBKDF and BIGN transport. The test suite also exercises provider exports,
cipher round trips and negative authentication checks,
BIGN key operations, BRNG and independent library contexts.

When using a custom OpenSSL, pass its installation prefix and executable:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
    -DBEE2_PROVIDER_BUILD_TESTS=ON \
    -DOPENSSL_ROOT_DIR=/opt/openssl \
    -DBEE2_OPENSSL_EXECUTABLE=/opt/openssl/bin/openssl
```

Depending on how OpenSSL was built, the runtime loader may also need the
installation's `lib` directory in `LD_LIBRARY_PATH`, or an equivalent dynamic
library path for the platform. The CI jobs explicitly set this path.

## Optional bee2evp interoperability tests

These require a separate OpenSSL installation with the `bee2evp` engine
installed and working. Do not enable them without providing that environment.

```sh
cmake -S . -B build-interop -DBEE2_PROVIDER_BUILD_TESTS=ON \
    -DBEE2_PROVIDER_ENABLE_INTEROP=ON \
    -DBEE2_INTEROP_PROVIDER_OPENSSL=/opt/openssl/bin/openssl \
    -DBEE2_INTEROP_BEE2EVP_OPENSSL=/opt/bee2evp/bin/openssl \
    -DBEE2_INTEROP_BEE2EVP_LD_LIBRARY_PATH=/opt/bee2evp/lib \
    -DBEE2_INTEROP_BEE2EVP_OPENSSL_CONF=/opt/bee2evp/openssl.cnf
cmake --build build-interop --parallel
ctest --test-dir build-interop -L interop --output-on-failure
```

`bee2evp` tests are not a replacement for independent known-answer vectors:
comparison between two implementations cannot establish correctness when
both implement the same mistake.

## EVP and BIGN validation tests

The standard CTest run includes `bee2_evp_streaming_contract`, six
`bee2_evp_padding_*` cases, `bee2_bign_public_check` and
`bee2_bign_asn1_negative`, `bee2_bign_der_framing`, `bee2_sde_min_sector`,
`bee2_bde_mode_metadata`, `bee2_brng_contract`, and
`bee2_provider_isolation`. These cover CFB/CTR streaming, ECB/CBC PKCS#7
padding and one-shot ciphertext stealing (aligned data also support split updates), modified ciphertext rejection, malformed
PKCS#8 and SPKI structures, and public-key validation. The ASN.1 key
reader rejects inputs exceeding 1 MiB. The RAND contract test verifies that
unsupported features fail explicitly; provider isolation uses a null global
provider to detect accidental global RAND/digest fetches. Run these separately
with:

```sh
ctest --test-dir build -L regression --output-on-failure
```

## Test categories and limitations

The test suite contains known-answer and end-to-end tests. A test name
containing `_kat` does not by itself guarantee an independent reference vector.
The suite does not yet establish complete fuzz coverage of ASN.1, all BIGN
validation paths, multithreaded calls, every size boundary, or memory safety
under malicious input. Fuzzing and additional property-based tests are release
blockers, not optional polish.

The native `bee2_bign_codec_crypto` test checks PBES2 with the HMAC-HBELT PRF
OID, BELT-KWP-128/192/256 identifiers, caller-selected 12,000 iterations and
24-byte salt, minimum-parameter rejections, and incorrect password rejection.
It also exercises AES-128-CBC, AES-192-CBC and AES-256-CBC via standard OpenSSL PBES2
for all three BIGN key lengths in both DER and PEM, including incorrect
password rejection. The separate legacy PBKDF2 test checks the provider's
work-limit policy (OpenSSL's default decoder has its own resource policy).
Older OpenSSL PBES2/PBKDF2 remains supported by the bounded legacy fallback.
The `bee2_bign_legacy_pbkdf2_limit` test rejects over-limit and unsupported
legacy KDF parameters without performing an expensive password derivation.
The native test also checks the configurable PBKDF2 decode work limit, and
`bee2_provider_negative_contract` checks failed BELT-SDE reinitialization.

The mandatory `bee2_bign_codec_roundtrip` test covers PKCS#8 and SPKI PEM/DER
round trips, explicit/cofactor domain parameters, and the OpenSSL standard
`file:` STORE loader for all three BIGN curves (private and public keys).
It checks encoded key equality and successful store loading, not ASN.1
conformance beyond the dedicated negative tests.

## STB 34.101.31-2020 key expansion

`bee2_belt_keyexpand_stb` checks the provider's BELT key expansion using
normative section 8.1.2 and Table A.27 for 128- and 192-bit keys, plus the
256-bit identity. It also checks in-place expansion and independently
computed, varied inputs. The OpenSSL `belt-keyexpand` KAT group checks that
ECB, CBC, CFB and CTR with 128/192-bit keys give the same ciphertext as the
corresponding, *normatively expanded* 256-bit keys. The existing block-mode
KATs check the standard's 256-bit ciphertext examples.

The provider uses Bee2 `beltKeyExpand2()` with `u32To()` to expand
keys; tests verify its output against the normative STB values.

## Instrumented provider coverage

Configure with `-DBEE2_PROVIDER_ENABLE_COVERAGE=ON` (GCC and tests required),
run the full CTest suite, then generate gcovr reports restricted to `src/`.
GitHub Actions publishes per-line HTML, XML and JSON summary artifacts. Only
the provider, not Bee2, is instrumented. The measured percentage is not the
same as the percentage of tests that pass. No unreachable branches should be
silently excluded merely to improve the number.

The engine matrix replaces duplicate fixed-only cipher/MAC/digest cases.
BIGN CSR/certificate interop verifies certificate signatures using both
implementations rather than merely printing their ASN.1 descriptions.

## Legacy AEAD and key-wrap interop

The extended interop job compiles `interop_cipher_tool.c` once with OpenSSL
3.x and once with OpenSSL 1.1.1. The harness normalizes legacy appended AEAD
tags into the provider's explicit-tag wire representation and cross-decrypts
both sides. It covers 128/192/256-bit BELT-DWP, BELT-CHE, BELT-KWP, and the
legacy BASH-PRG-AE2561 profile (empty announcement), with zero, patterned,
and deterministic pseudorandom inputs, boundary lengths, AAD and tag tampering.
BELT-KWP uses the legacy engine's zero-header profile.

## Multithreading and EVP context duplication

The native `bee2_provider_concurrent` test uses eight threads that share an
`OSSL_LIB_CTX` but independently create and duplicate digest/MAC contexts,
then generate, sign and verify BIGN keys. It is included automatically in the
sanitizer and coverage jobs. Production should never share a mutable EVP
operation context between threads without its own synchronization.

ECB/CBC normative ciphertext-stealing vectors A.9-2, A.10-2, A.11-2 and
A.12-2 (47/36-byte inputs) are kept alongside the 48-byte KATs in the
native `stb_kat.c` test. Only one final partial block is passed per Update,
matching the provider's documented CTS API contract.
