# Changelog

Bee2 Provider is being prepared for its initial public release.

## Unreleased

### Functionality

- BELT block ciphers, authenticated encryption, MAC, key wrapping and PBKDF.
- BASH hashes and authenticated encryption.
- BRNG random generators.
- BIGN key management, generation, signatures, key agreement, key transport,
  and PEM/DER encoding.
- OpenSSL 3 provider interface with CMake build and installation support.

### Verification

- Known-answer, interoperability and EVP integration tests.
- GitHub Actions builds and tests against selected OpenSSL releases.
- Additional regression and security tests required before release; see
  [Testing](docs/TESTING.md) and [CI](docs/CI.md).

This entry describes the planned initial release, not a released version.
