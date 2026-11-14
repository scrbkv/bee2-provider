# Contributing

Bee2 Provider is a cryptographic OpenSSL provider. Compatibility, correctness,
and maintainability take priority over adding more algorithms or changing
existing code solely for appearance.

## Code style

Follow OpenSSL's C coding conventions and its `STYLE.md`, including sensible
function size, explicit ownership and error handling, consistent naming, and
comments that explain non-obvious behavior rather than paraphrase the code.
Use the repository's existing public provider interfaces; do not depend on
OpenSSL private headers or internals. New code should be straightforward to
review and maintain, with no unnecessary wrappers or mechanical boilerplate.

Match OpenSSL's formatting conventions when editing source files. Keep
formatting-only changes separate from behavioral fixes so they can be
reviewed independently.

## Changes and tests

Prefer small, auditable changes with a clear purpose. Any cryptographic or EVP
behavior change needs an appropriate regression test. Known-answer values must
come from independently checked references, not merely an encrypt/decrypt
round trip. Check buffer limits, invalid inputs, and failure paths.

Run the tests documented in `docs/TESTING.md`. A pull request should describe
what was tested and any missing verification. Maintainers review changes before
merge. Do not treat a passing CI pipeline as a security audit.

Proposed upstream contributions must additionally follow OpenSSL's current
contributor, license, and assisted-development disclosure requirements.
