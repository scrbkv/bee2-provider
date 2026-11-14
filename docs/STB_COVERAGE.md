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
- `tests/openssl_kat.py`, `tests/stb_extended_kat.py` and
  `tests/belt_aead_stb.c` check independent STB appendix vectors for
  BELT block modes, BDE, SDE, DWP, CHE, KWP, MAC, Hash, PBKDF and
  BASH-256/384/512. The fixed outputs are not produced by the provider
  under test.
- `tests/brng_kat.c` contains fixed BRNG-CTR and BRNG-HMAC appendix vectors.
- Other algorithms are often checked by round trips, cross-variant coverage
  or internal consistency, which is weaker than independent known-answer tests.
- Interoperability with a pinned `bee2evp` engine is exercised in an
  independent GitHub Actions job. Its supported cipher, MAC and digest
  algorithms are checked with fixed boundary sizes and deterministic
  pseudorandom buffers, including cross-decryption. Existing BIGN
  certificate interoperability checks are included in that job.
  The engine is a separate implementation interface over Bee2; it is
  not an independent cryptographic implementation.
- The main build matrix does not cover Windows or macOS.
- A full conformity claim requires the relevant normative edition, algorithm
  profiles and OIDs, exhaustive fixed vectors, boundary and negative tests,
  interoperability, security review, and applicable certification processes.

## Test coverage by operation

The terms in this table are deliberately distinct: a **standard KAT**
compares against a fixed answer published with an STB example; an
**interoperability** check compares against bee2evp; a **round-trip** only
establishes internal consistency. They must not be counted as equivalent.

| Operation | STB known-answer evidence | Additional validation |
| --- | --- | --- |
| BELT ECB/CBC/CFB/CTR | 256-bit keys, STB 34.101.31 Appendix A; 128/192-bit key-expansion equivalence to the A.27 expanded key | Round-trips for all key lengths; bee2evp fixed/boundary/random inputs |
| BELT BDE/SDE | 256-bit keys, A.24 | Round-trips for 128/192/256; no bee2evp counterpart |
| BELT DWP/CHE | 256-bit keys, A.19-1/2 (ciphertext and authentication tag) | Round-trips and tag-rejection for all key lengths |
| BELT KWP | 256-bit keys, A.21 | Round-trips and tamper tests for all key lengths |
| BELT MAC | 256-bit keys, A.17 | Round-trips/functional coverage for 128/192; bee2evp MAC comparison for 256 |
| BELT-Hash | A.23 (multiple lengths) | Streaming/one-shot API equivalence and bee2evp comparison |
| BELT-PBKDF | STB 34.101.45 Appendix E.5 | EVP KDF integration |
| HMAC-HBELT | STB 34.101.47 B.1 | bee2evp comparison, plus HMAC construction tests |
| BRNG-CTR-HBELT / BRNG-HMAC-HBELT | STB 34.101.47 B.2/B.4 | RAND contract tests |
| BASH-256/384/512 | STB 34.101.77 A.3, multiple boundary lengths | Streaming/one-shot and bee2evp comparisons |
| BASH-PRG-AE (six provider variants) | **Not yet covered by an independent published STB vector per variant** | Functional round-trips and authentication failures |
| BIGN signature/key agreement/key transport | **Not yet covered by an independent STB answer for each exposed variant and operation** | Deterministic repeatability, sign/verify, DH agreement, encoding checks and selected bee2evp certificate interoperability |

The missing per-algorithm standard KATs remain release blockers for a claim
of exhaustive normative coverage. In particular, the 128/192-bit variants
of several BELT algorithms and all six BASH-PRG-AE EVP profiles still
require a carefully matched normative reference rather than generated
expected values.

## BELT key expansion against the standard

The key expansion reference is **STB 34.101.31-2020**, section 8.1.2
and Table A.27. The provider uses Bee2 `beltKeyExpand2()` followed by
`u32To()`. `tests/belt_keyexpand_stb.c` checks the provider path for
128-, 192- and 256-bit keys against the normative example and additional
inputs. The `belt-keyexpand` OpenSSL KAT group verifies ECB, CBC, CFB and CTR
results against normatively expanded 256-bit keys.

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
