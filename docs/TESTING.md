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

## EVP-to-provider validation boundary

Provider callbacks are called by libcrypto with a context returned by the
corresponding `newctx` callback. The cipher and MAC operations use the
documented output-length pointer. The provider therefore does not need to
recheck these context and output-length pointers on every operation. Context
allocation failures are still handled when creating contexts; a null
`freectx` argument remains safe.

This does **not** make `OSSL_PARAM` values trusted. An application may supply
parameters of the wrong type or with unsupported values, and OpenSSL passes
provider-specific parameters to their implementation. Keep the `OSSL_PARAM`
conversion and validation, fixed STB key/IV/tag requirements, actual
`outsize` bounds, missing-key/state checks, and rejection of invalid operation
sequences. `set_ctx_params(NULL)` must remain a successful no-op where the
provider API specifies it. A KDF must itself reject unsupported output sizes.

OpenSSL 3.5 and newer also have `EVP_CipherInit_SKEY()`. When a cipher
does not implement an SKEY-specific initialization callback, libcrypto may
pass the raw key and its actual length to the ordinary provider initializer.
Therefore the provider must still validate fixed key and IV lengths in that
callback; the EVP cipher's advertised fixed length is not sufficient on its
own. The native negative-contract test covers this public SKEY fallback
when building against OpenSSL 3.5+.

Tests should preferentially exercise malformed inputs through public EVP,
encoder/decoder, and STORE interfaces. Direct provider dispatch is useful for
valid operation equivalence and for explicit provider contracts, but not to
simulate invalid libcrypto-owned contexts just to count coverage branches.
Algorithm correctness and memory-safety tests take precedence over any
line or branch coverage percentage.

References: OpenSSL 3.0 `provider-cipher(7)`, `provider-kdf(7)`,
`provider-mac(7)`, and `EVP_MAC(3)`.

## Instrumented coverage and regression tests

Use `-DBEE2_PROVIDER_BUILD_TESTS=ON -DBEE2_PROVIDER_ENABLE_COVERAGE=ON`
with GCC, then run the complete CTest suite. GitHub Actions publishes gcovr
HTML, XML and JSON reports for production `src/` code, including ASN.1 sources
compiled directly into unit tests. The Bee2 dependency and test harnesses do
not contribute to the reported percentages.

The coverage job enforces 100% function execution and regression floors of
80% line and 60% branch coverage. Successful tests are not equivalent to
complete behavioral coverage. Do not hide defensive error-handling branches
or exclude them merely to improve the numbers. Atomic GCC coverage counters
are required because the native concurrency test exercises shared provider
code from eight threads; ordinary counters produced invalid gcov branch data.

The native contract suite exercises one-shot and streaming EVP operations,
copying cipher, MAC and BIGN contexts, BIGN signing and key agreement,
`EVP_KDF_CTX_reset`, and BIGN generic aliases, template-based generation,
key comparison and decoder object exports. The BIGN DER tests check PKCS#8
and SPKI with named and explicit curves, including malformed points,
scalars and framing. On Linux, linker-wrapped PKCS#8 and SPKI ownership
transfer failures verify ASN.1 cleanup without fault hooks in the provider.

Published ECB/CBC ciphertext-stealing vectors A.9-2, A.10-2, A.11-2 and
A.12-2 (36/47 bytes) accompany the full-block KATs. These cases supply the
entire final partial block in one EVP Update, matching the API contract.

## Legacy bee2evp interoperability

The CI interoperability job builds pinned OpenSSL 1.1.1 with bee2evp alongside
OpenSSL 3.x with the provider. The engine matrix compares fixed, boundary and
pseudorandom input cases for supported BELT modes, digests and MACs. The
extended matrix compares 128/192/256-bit BELT-DWP, BELT-CHE and BELT-KWP,
plus BASH-PRG-AE2561, using zero, patterned and deterministic pseudorandom
data, cross-decryption, AAD and tampered authentication tags. BELT-KWP uses the
legacy engine's zero-header profile.

The old engine cannot decrypt its own zero-plaintext BASH-PRG-AE2561 result
(tag-only payload). This does not limit Bee2 or the provider: zero-length BASH
cases remain tested directly with Bee2, and only the failing legacy case is
excluded from that matrix.

BIGN interoperability checks cross-load private PKCS#8 keys, verify signatures
in both directions, and verify CSRs and self-signed X.509 certificates using
both implementations, including explicit curve parameters.

The ASN.1 tests include exhaustive one-byte and single-bit mutation of valid
BIGN PKCS#8/SPKI encodings and every shorter length. If a modified encoding
still describes a valid key, the decoder's key invariants must hold; truncated
and trailing DER must be rejected. The fault-injection target also walks
failure positions for provider-owned OpenSSL allocations, with ASan checking
cleanup across named and explicit parameter encodings.
