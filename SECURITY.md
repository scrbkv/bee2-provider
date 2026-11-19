# Security Policy

## Reporting security issues

Please do not publish exploit details in a GitHub issue. Use GitHub private
vulnerability reporting when available, or contact the repository maintainer
privately. Include the affected algorithm and operation, OpenSSL and Bee2
versions, a reproducible input or test, the observed behavior, and any known
impact or disclosure constraints.

The maintainer coordinates verification, remediation and public disclosure.
Supported versions are identified by their published GitHub release tags and
security advisories.

## Security scope

Bee2 Provider implements cryptographic interfaces using the Bee2 library and
OpenSSL. The published test suite checks functional correctness and selected
malformed-input behavior. The project does not claim FIPS validation or an
independent third-party security certification.
