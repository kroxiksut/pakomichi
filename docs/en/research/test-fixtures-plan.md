# Plan of synthetic artifacts for research

**English** · [Русский](../../ru/research/test-fixtures-plan.md)

Only **laboratory** DEB/RPM files created by the agent during R-001/R-002 are needed (do not distribute them as production packages).

- `sampleapp 0.9-1`, `1.0-1`, `1.1-1`: contain a simple executable that prints the build fingerprint.
- `sampleapp 1.0-1` from two sources: identical name/version/architecture, **different sha**.
- `sampleapp-helper 1.1-1`: required by the main package at an exact version.
- `sampleapp-suspicious 1.1-1`: `Provides` metadata on a critical system namespace; for inspection only, **do not install on production**.
- Signed RPM, unsigned RPM, invalid-signature RPM, signed repodata.
- A GitHub test Release: immutable with an attestation, and mutable with an attested artifact.

For all fixtures, record `sha256sum`, the native package metadata dump, the build commands, and the operating system used. Do not put private signatures/tokens into Git.
