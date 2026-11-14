# GitHub Actions CI

The workflow `.github/workflows/ci.yml` runs on pushes to `main`, pull
requests and manual dispatch. Linux is the first supported CI environment;
additional platforms require validated build and test configurations.

The main matrix builds and tests against pinned OpenSSL release commits:

| OpenSSL | Compiler | Commit |
| --- | --- | --- |
| 3.5.9 | GCC | `45e844fa2a14ec92d146bd8f5778ac130b6625fb` |
| 4.0.3 | Clang | `af1775b60dfa141a4ad762585052cabeb9f37e9e` |
| 4.1.0 | GCC | `2f4e3a5fec05394068cfa7379890ab552483a8a6` |

Each job checks out the pinned Bee2 git submodule, compiles OpenSSL under the
job's private temporary prefix, builds the provider and public tests, runs
CTest, and verifies installation and packaging. OpenSSL tag contents are
checked against the commit IDs above. The separate sanitizer job runs native
C tests against a debug build with ASan and UBSan.

The workflow does not require repository secrets. It uses `contents: read`
permissions and immutable action revisions. The exact OpenSSL tags and action
revisions should be reviewed periodically for updates.

## Before making checks mandatory

1. Obtain approval for the workflow and test-source changes.
2. Run the first CI builds and inspect compiler errors, test failures and
   sanitizer output.
3. Fix confirmed failures without hiding tests or silently ignoring error
   codes. Regression tests described in `TESTING.md` must eventually be
   enabled by default.
4. Once the workflow is green, configure a GitHub ruleset protecting `main`
   with the required matrix job names. Include reviews before merging.
5. Add macOS and Windows jobs only after their OpenSSL and Bee2 builds are
   reproducible and their failures can be meaningfully interpreted.

`bee2evp` interoperability is opt-in and has a separate toolchain requirement.
It should become a distinct CI job after the engine build has been independently
validated; it must not prevent the normal tests from running.

Source formatting is not yet enforced by CI: `.clang-format` currently uses
LLVM defaults. Review changes needed to comply with OpenSSL's conventions
separately from functional fixes, then enable the formatting gate.
