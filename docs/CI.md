# GitHub Actions CI

The workflow `.github/workflows/ci.yml` runs on pushes to `main`, pull
requests and manual dispatch. Linux is the first supported CI environment;
additional platforms require validated build and test configurations.

## OpenSSL build matrix

The main matrix builds and tests against pinned OpenSSL release commits:

| OpenSSL | Compiler | Commit |
| --- | --- | --- |
| 3.0.21 | GCC | `51ea949dc1436e865935b47874b21a3bb31a102e` |
| 3.5.9 | GCC | `45e844fa2a14ec92d146bd8f5778ac130b6625fb` |
| 4.0.3 | Clang | `af1775b60dfa141a4ad762585052cabeb9f37e9e` |
| 4.1.0 | GCC | `2f4e3a5fec05394068cfa7379890ab552483a8a6` |

Each job checks out the pinned Bee2 git submodule, compiles OpenSSL under the
job's private temporary prefix, builds the provider and public tests, runs
CTest, and verifies installation and packaging. OpenSSL tag contents are
checked against the commit IDs above.

## Additional jobs

The sanitizer job runs the native C tests against a debug build with ASan and
UBSan.

A separate interoperability job builds the pinned legacy OpenSSL required by
`bee2evp`, builds the engine and runs the fixed, boundary and deterministic
pseudorandom interoperability tests. It covers BELT ECB/CBC/CFB/CTR, BELT and
BASH digests, BELT MAC/HMAC, and BIGN CSR, certificate and signature exchange.
This job runs on the same push, pull-request and manual-dispatch events as the
main matrix.

The workflow does not require repository secrets. It uses `contents: read`
permissions and immutable action revisions. The exact OpenSSL tags and action
revisions should be reviewed periodically for updates.

## Branch protection

To make CI results blocking, configure a GitHub ruleset for `main` that
requires all matrix jobs, the sanitizer job and the bee2evp interoperability
job. Review requirements should be configured separately according to the
repository's contribution policy.

macOS and Windows jobs should be added only after their OpenSSL and Bee2 builds
are reproducible and their failures can be meaningfully interpreted.

Source formatting is not yet enforced by CI. The current `.clang-format`
configuration is a project-specific LLVM-derived style; review it against
OpenSSL's conventions before enabling a formatting gate.

## Instrumented source coverage

The `coverage` job compiles provider sources with GCC `--coverage`, runs all
standard tests and publishes `coverage.html`, `coverage.xml` and
`coverage-summary.json` for `src/` (excluding Bee2 and harnesses).
These reports quantify line and branch coverage; passing test counts do not.

The sanitizer job selects every registered CTest except the three Python CLI
integration tests, preventing new native tests from bypassing instrumentation.
The engine interop matrix subsumes duplicate fixed-only cipher/MAC/digest cases.
