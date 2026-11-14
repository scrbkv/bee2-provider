# STB algorithm coverage

This document describes algorithms **exposed by the OpenSSL provider**. The
linked Bee2 submodule implements further algorithms that are not necessarily
available through the provider. Functional tests do not constitute an
independent certification of compliance with any STB standard.

| Standard | Exposed implementations | Scope and gaps |
| --- | --- | --- |
| STB 34.101.31 (BELT) | ECB, CBC, CFB, CTR, MAC, DWP, CHE, KWP, hash, BDE, SDE | `belt-fmt`, `belt-krp` and a separate wide-block interface are not exported. The current ECB/CBC EVP interface defaults to PKCS#7; the standard's ciphertext stealing semantics for partial blocks are not exposed as a separate mode. The provider does not enforce per-key usage quotas. |
| STB 34.101.45 (BIGN) | Named curves 256/384/512, key validation/generation, signatures, key transport, SPKI/PKCS#8, and PBKDF using the Bee2 backend | Identification signatures and the complete set of password-based key protection procedures are not exposed. Independent fixed signature and transport vectors and exhaustive ASN.1 profiles are still required. |
| STB 34.101.47 (BRNG/HMAC) | HMAC-HBELT, BRNG-CTR-HBELT and BRNG-HMAC-HBELT | BRNG delegates its cryptographic state transitions to Bee2 Start/Step functions. Caller-supplied key material is required. Prediction resistance and nonempty personalization are rejected, as is additional input for BRNG-HMAC; reseed replaces the supplied key. Declared strength bounds the supplied key length, not independently measured entropy. |
| STB 34.101.77 (BASH) | BASH-256/384/512 digests and six BASH-PRG-AE variants | The full set of BASH PRG operations is not exposed. The named algorithms have functional coverage but not yet independent fixed vectors for every parameter and streaming combination. |
| STB 34.101.66 (BAKE) | None | BIGN key agreement and the optional BAKE-related KDF are not implementations of the BMQV, BSTS or BPACE protocols. |

Other STB standards, such as those defining secret sharing, X.509/CMS
profiles, or network protocols, are outside the provider's current declared
primitive API. Their full implementation must not be inferred from the presence
of the underlying algorithms.

## Evidence and validation

- The compiled provider is tested on Linux using pinned OpenSSL 3.5, 4.0 and
  4.1 releases and the pinned Bee2 submodule.
- `tests/openssl_kat.py` contains fixed STB appendix vectors for selected
  BELT, HMAC-HBELT and BASH operations.
- `tests/brng_kat.c` contains fixed BRNG-CTR and BRNG-HMAC appendix vectors.
- Other algorithms are often checked by round trips, cross-variant coverage
  or internal consistency, which is weaker than independent known-answer tests.
- Optional interoperability tests with `bee2evp` are not part of the default
  GitHub Actions matrix.
- The main build matrix does not cover Windows or macOS.
- A full conformity claim requires the relevant normative edition, algorithm
  profiles and OIDs, exhaustive fixed vectors, boundary and negative tests,
  interoperability, security review, and applicable certification processes.

## API distinctions

OpenSSL EVP represents a generic application interface, not an STB protocol
interface. EVP defaults (for example PKCS#7 padding) and standard-specific
semantics (for example BELT ECB/CBC ciphertext stealing) must be documented
and tested separately. BELT-BDE is not AES-XTS and has no defined EVP cipher mode. The provider
uses mode `0` as an OpenSSL compatibility fallback (which OpenSSL labels
`STREAM_CIPHER`), and supplies the `bee2-mode=belt-bde` algorithm parameter.
Clients should use the cipher name rather than infer BELT-BDE properties from
the generic EVP mode value.

The pinned Bee2 API is the primary source of truth for low-level call
preconditions. In particular, `beltSDEStepE()` and `beltSDEStepD()` accept only
whole sectors of at least 32 bytes, a multiple of 16.
