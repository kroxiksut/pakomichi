# Negative tests (mandatory)

**English** · [Русский](../../ru/testing/negative.md)

| ID | Input / attack | Expected behavior |
|---|---|---|
| N-001 | A fork with a higher version of the same application | Ignore, repo ID mismatch |
| N-002 | Another repo of the same owner releases a package with the same name | Do not consider |
| N-003 | An old URL leads to a newly created repo | Suspend + `E_REPO_ID_CHANGED` |
| N-004 | Transfer of the original repo to another owner | Suspend until confirmation |
| N-005 | A mutable asset replaced with different bytes | `E_ASSET_MUTATED`, do not overwrite the SHA |
| N-006 | An attestation certificate of another repo/signer | Reject |
| N-007 | Only an API digest without a signature | Insufficient for automatic verified |
| N-008 | `sampleapp-glibc` with Provides glibc | Hold / system namespace conflict |
| N-009 | An unsatisfiable glibc from the next release | Hold the version, download nothing from Git |
| N-010 | The same version of two DEBs with different sha | No automatic source switch |
| N-011 | An unsigned RPM under a mandatory policy | Block |
| N-012 | Invalid InRelease/repomd signature | Native manager error |
| N-013 | GitHub unavailable / 429 | Last verified snapshot within freshness, diagnostics |
| N-014 | A reference to a package deleted from GitHub, and no blob | Correct error, without substitution |
| N-015 | Crash during index publication | No mixing of generations |
| N-016 | Disk full during download | Do not serve a partial package, the active snapshot is intact |
| N-017 | A package in the cache was changed after verification | Digest mismatch, do not serve |
| N-018 | `../` and symlink in a blob path | Does not escape its own directory |
| N-019 | Asset redirect to 127.0.0.1/169.254.169.254 | SSRF prohibited, no requests to local services |
| N-020 | Malicious malformed DEB/RPM | Do not execute installation scripts, limits, process not root |
| N-021 | The user manually removed/upgraded the installed program | Reconcile state; without automatic reinstallation |
| N-022 | Remove Pakomichi after installing a program | The program remains, third-party repo files are not changed |
| N-023 | Loss of the local signer key | No silent reinitialization of trust; recovery procedure |
| N-024 | DNF/APT configuration error during apply | Rollback or an explicit recoverable state |
| N-025 | POST to the loopback repository endpoint | Does not perform configuration actions |

Each test must record the actual result, the expected reason code, and the test environment versions. A single `unit test passes` must not be treated as verification of real APT/DNF operation.
