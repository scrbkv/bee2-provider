# Security Policy

## Development status

Bee2 Provider is under development ahead of its initial public release.
Security fixes are reviewed for the current `main` branch; no stable release
is available yet.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub private
vulnerability reporting if it is enabled for this repository. Otherwise,
contact the maintainer privately before sharing technical details. Include:

- the affected operation and algorithm;
- the OpenSSL, Bee2, compiler and operating-system versions;
- a minimal reproducer or failing test vector;
- the expected and observed behavior;
- any known impact or disclosure deadline.

Maintainers should acknowledge a report before discussing public disclosure.
No response-time guarantee is made until a dedicated security contact is
published.

## Scope

This provider is not independently audited, FIPS validated or certified for a
particular regulatory environment. Passing the bundled test vectors establishes
functional compatibility, not suitability for a specific deployment.
