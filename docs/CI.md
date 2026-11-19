# Continuous integration

The GitHub Actions workflow in `.github/workflows/ci.yml` runs on pushes to
`main`, pull requests and manual dispatch. All workflow jobs run on GitHub's
Linux runners. The workflow is a verification environment, not a statement of
native support for every operating system.

## OpenSSL compatibility matrix

| OpenSSL | Compiler | Pinned source commit |
| --- | --- | --- |
| 3.0.21 | GCC | `51ea949dc1436e865935b47874b21a3bb31a102e` |
| 3.5.9 | GCC | `45e844fa2a14ec92d146bd8f5778ac130b6625fb` |
| 4.0.3 | Clang | `af1775b60dfa141a4ad762585052cabeb9f37e9e` |
| 4.1.0 | GCC | `2f4e3a5fec05394068cfa7379890ab552483a8a6` |

Each matrix job verifies its OpenSSL source revision, builds the pinned Bee2
submodule and provider, runs CTest and checks the installable module.

## Verification jobs

The sanitizer job runs native tests with AddressSanitizer and
UndefinedBehaviorSanitizer. The coverage job instruments production `src/`
code and publishes line- and branch-level gcovr reports. Coverage is
diagnostic: deterministic functional tests do not attempt to induce allocator,
entropy or operating-system failures to inflate a percentage.

The interoperability job builds a separate `bee2evp` engine and compares
supported algorithms against the provider using fixed inputs, size boundaries,
deterministic pseudorandom data, authenticated-tag rejection, cross-decryption,
and BIGN key and certificate operations. STB known-answer tests remain
independent of this shared-Bee2 implementation comparison.

The workflow uses read-only repository permissions and pinned action revisions.
It does not require repository secrets. For protected branches, require the
OpenSSL matrix, sanitizers and interoperability job to pass before merge.

See [Testing](TESTING.md) for local commands and test categories.
