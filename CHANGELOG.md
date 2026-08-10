# Changelog

All notable changes to this project will be documented in this file. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- OpenSSL provider implementations for the bee2evp-compatible BELT, BASH,
  BRNG and BIGN algorithm set.
- KAT, export-parity, certificate and bee2evp interoperability tests.
- Negative authentication tests for AEAD and KWP operations.
- GitLab CI pipeline for isolated OpenSSL 3.x/4.x interoperability testing.
- CMake installation support for the provider module.
- An opt-in test build and a source-only GitHub publication workflow; the
  complete test suite and GitLab CI remain in the canonical GitLab repository.
- BIGN Diffie--Hellman key agreement with optional BAKE-KDF processing.
- A common HMAC implementation selectable with `belt-hash`, `bash256`,
  `bash384` or `bash512`; the BELT branch uses Bee2's native `beltHMAC`.
- Fixed `bign-256`, `bign-384` and `bign-512` key types, deterministic BIGN
  signatures and named/explicit parameter encoding with optional cofactor.

### Changed

- Replaced the legacy backend with the upstream Bee2 submodule.
- Unified provider contexts, secret-buffer handling and algorithm naming.
- Made BELT-SDE and BELT-KWP obey the EVP update/final output contract without
  buffering secret input dynamically.
- Removed misleading `provider=default` registrations from Bee2-owned
  key-management, signature, codec and store implementations.
- Removed the legacy bee2evp TLS-record cipher aliases; the provider exposes
  only the underlying modern AEAD interfaces with separate authentication tags.
- Limited partial-block input to the streaming BELT-CFB and BELT-CTR modes;
  padding for block modes remains the caller's responsibility.
- Bound BIGN encoders and decoders to their advertised fixed key type and
  consolidated checked input-buffer growth for codec and store reads.
- Standardized provider allocations and context cleanup on the OpenSSL memory
  API, removing unused buffer and string utility wrappers.
- Moved retained BELT and BASH key/IV material into the Bee2 adapter contexts,
  eliminating duplicate copies in provider operation contexts.
- Applied cipher and MAC parameters supplied directly to `EVP_*Init_ex2`, with
  fixed-size validation shared with the corresponding context setters.
- Moved test targets into `tests/CMakeLists.txt`, leaving the default source
  build independent of the private test tree.

### Security

- Authentication checks use constant-time comparison.
- Secret-bearing contexts and temporary key material are explicitly cleansed
  before release.
- BIGN random generation fails closed when OpenSSL randomness is unavailable.
- Failed unwrap and key-transport operations clear partial output.
