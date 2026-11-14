# Release procedure

This document describes the intended GitHub release process. It is not a
record of a completed release.

1. Review and approve all source changes. Do not commit unreviewed changes.
2. Ensure `main` is protected with required CI checks. Complete the release
   candidate review, including the regression tests documented in TESTING.md.
3. Check that the Bee2 submodule points to a reviewed, immutable commit and
   that third-party licenses are correct.
4. Build from a clean recursive clone; run CTest with all required backends,
   sanitizers, and representative supported OpenSSL releases.
5. Update CHANGELOG.md, README.md, version in CMakeLists.txt and release
   notes. Review API/algorithm naming and compatibility changes.
6. Create a signed annotated release tag after approval, then publish the
   corresponding source archive and build artifacts through GitHub Releases.
7. Verify that a clean user can install and load the released provider without
   the developer's build directory.

Source archives alone do not contain the contents of the Bee2 git submodule.
Publish a self-contained distribution archive or provide explicit source
retrieval instructions; do not advertise a normal GitHub source ZIP as a
complete offline build artifact.

Do not create an automatic release on a normal branch push. Release publishing
should require an explicit maintainer decision.
