# STB algorithms and normative test vectors

This document describes the OpenSSL algorithms exported by Bee2 Provider and
the independently published STB examples used by its tests. The underlying
Bee2 library supports additional procedures that are not exported as separate
provider operations.

## Standards and algorithm identifiers

| Standard | Provider interfaces |
| --- | --- |
| STB 34.101.31 (BELT) | ECB, CBC, CFB, CTR, DWP, CHE, KWP, MAC, Hash, BDE, SDE |
| STB 34.101.45 (BIGN) | BIGN-256/384/512 keys, signatures, key agreement, key transport, SPKI/PKCS#8, password protection |
| STB 34.101.47 | HMAC-HBELT, BRNG-CTR-HBELT, BRNG-HMAC-HBELT |
| STB 34.101.77 (BASH) | BASH-256/384/512 and BASH-PRG-AE profiles |

The authoritative algorithm identifiers and ASN.1 definitions are available
in the original specification sources:

- [BIGN ASN.1 module](https://github.com/bcrypto/bign/blob/master/spec/bign-module-v2.asn) and [password-protection annex](https://github.com/bcrypto/bign/blob/master/spec/96Password.tex)
- [BELT ASN.1 module](https://github.com/bcrypto/belt/blob/master/spec/belt-module-v2.asn)
- [BASH ASN.1 module](https://github.com/bcrypto/bash/blob/master/spec/bash-module-v2.asn)
- [STB 34.101.50 OID registry](https://github.com/bcrypto/stb/blob/master/34.101.50/oids.md)
- [STB 34.101.19 X.509 profile](https://github.com/bcrypto/stb/blob/master/34.101.19/x509.md)

## Published examples exercised by the suite

| Standard and examples | Provider test | Operation |
| --- | --- | --- |
| BELT 34.101.31, A.1–A.2 | `stb_kat.c` | Single-block BELT answers embedded in the ECB encryption/decryption KATs |
| BELT 34.101.31, A.9–A.16 | `stb_kat.c` | ECB/CBC on complete blocks and CFB/CTR encryption/decryption; nonaligned ECB/CBC CTS vectors are outside the provider contract |
| BELT 34.101.31, A.17 | `stb_kat.c` | MAC outputs |
| BELT 34.101.31, A.19–A.20 | `belt_aead_stb.c` | DWP and CHE encryption, authentication and decryption |
| BELT 34.101.31, A.21–A.22 | `stb_kat.c` | KWP wrapping and unwrapping |
| BELT 34.101.31, A.23 | `stb_kat.c` | BELT-Hash |
| BELT 34.101.31, A.24–A.25 | `stb_kat.c` | BDE and SDE encryption and decryption |
| BELT 34.101.31, A.27 and §8.1.2 | `belt_keyexpand_stb.c` | 128/192/256-bit key expansion |
| BIGN 34.101.45, G.1–G.3 | `bign_stb_verify.c` | Published BIGN key and signature verification examples |
| BIGN 34.101.45, G.4–G.5 | `stb_kat.c` | Published key-transport token decryption |
| BIGN 34.101.45, E.5 | `stb_kat.c` | PBKDF2-HMAC-HBELT key and protected private scalar |
| STB 34.101.47, B.1 | `stb_kat.c` | HMAC-HBELT |
| STB 34.101.47, B.2/B.4 | `brng_kat.c` | BRNG-CTR and BRNG-HMAC |
| BASH 34.101.77, A.3 | `stb_kat.c` | BASH-256/384/512 |
| BASH 34.101.77, A.4 | `bash_prgae_stb.c` | PRG encryption (128-bit security level, profile 1) |
| BASH 34.101.77, A.6 | `bash_prgae_evp_stb.c` | BASH-PRG-AE2561 ciphertext and tag |

Additional sizes and cipher variants are verified by EVP integration tests,
Bee2 direct comparisons, and a separate `bee2evp` engine interoperability
matrix. These comparisons are distinct from fixed, published STB outputs.

A published example for an internal transformation is not a provider API test:
BELT wide-block encryption, compression, FMT, key replication, BASH's internal
permutation and standalone PRG-hash, BIGN identification signatures and
one-time secret generation are not exposed as dedicated provider operations.
Published examples with input lengths unsupported by an advertised EVP
operation's contract cannot be replayed through that operation.

## ASN.1 and encrypted private keys

BIGN `SubjectPublicKeyInfo` uses the STB `bign-pubkey` OID, encoded public
point and `DomainParameters` (named curve or supported explicit parameters).
The ASN.1 `Curve.seed` field is mandatory, as specified by the BIGN module.
BIGN private keys use OpenSSL's standard PKCS#8 `PrivateKeyInfo` structure.
The container DER is produced and parsed by the OpenSSL ASN.1 APIs rather
than a parallel provider ASN.1 codec.

STB 34.101.45, Annex E uses PBKDF2 with HMAC-HBELT, a 32-byte derived key,
and BELT-KWP-256 on the **private scalar**, rather than on DER-encoded PKCS#8.
Both nested PRF and KWP identifiers require ASN.1 `NULL` parameters. The
provider emits and decodes this exact scalar protection scheme, reconstructing
PKCS#8 with OpenSSL after authentication; the published Annex E.5 token is
also tested through the public key decoder. Only the 256-bit KWP key is used
for BIGN protection, regardless of BIGN curve size. KWP-128/192 are separate
public cipher operations. Explicit selection of a conventional CBC cipher
uses OpenSSL's native PBES2 and encrypts full PKCS#8 instead.

The encoder defaults to 10,000 PBKDF2 iterations and a fresh 16-byte salt.
Both values are caller-configurable; the Annex E recommendations are not
minimum decoding or encoding constraints. Zero values are rejected because
they cannot express a usable explicit count or randomly generated salt in the
PKCS#8 API. A configurable per-decoder upper bound limits PBKDF2 work on
untrusted encrypted keys. The standalone `belt-pbkdf` KDF is tested against
the standard's example.

## EVP-specific details

ECB/CBC support PKCS#7 padding by default. Without padding, ECB/CBC
accept only complete 16-byte blocks; STB ciphertext stealing is not exposed
as ECB/CBC through EVP. Published nonaligned CTS cases are not EVP KATs. For SDE, sectors are
at least 32 bytes and multiples of 16. Short or nonaligned inputs that are
rejected by an operation's documented contract are not substituted with
synthetic expected ciphertexts.
