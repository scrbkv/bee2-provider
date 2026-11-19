# Release procedure

A release is cut from a reviewed commit on `main` after its required GitHub
Actions checks pass.

1. Review cryptographic behavior, OIDs, ASN.1 formats, API compatibility and
   dependency versions. Confirm the Bee2 submodule is pinned to a reviewed
   immutable commit.
2. Run the complete native CTest suite and the separate `bee2evp`
   interoperability suite. Verify the OpenSSL compatibility matrix,
   ASan/UBSan results and coverage report in GitHub Actions.
3. Confirm the README examples, install layout, package licenses and
   third-party notices match the release candidate.
4. Build from a clean recursive checkout. Install into a temporary prefix and
   confirm that OpenSSL loads the installed module without build-tree paths.
5. Set the release version in CMake and prepare GitHub release notes describing
   the included algorithms and relevant compatibility changes.
6. Create a signed, annotated tag from the approved commit and publish the
   source distribution and release notes through GitHub Releases.
7. Confirm that the published source distribution contains or retrieves the
   pinned Bee2 submodule. A GitHub-generated ZIP does not embed submodule
   contents and is not, by itself, an offline source distribution.

Publication is an explicit maintainer action; regular branch pushes do not
publish releases.
