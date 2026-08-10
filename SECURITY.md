# Security Policy

## Supported versions

Until the first stable release, only the latest commit on the primary GitLab
branch is supported. Older snapshots do not receive security fixes.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use a private
security report on the repository hosting service and include:

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
