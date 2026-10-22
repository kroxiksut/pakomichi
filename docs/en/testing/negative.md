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
| N-022 | Remove Pakomichi after installing a program | The program remains, third-party repo files are not changed; no Pakomichi `.repo`/`.sources` file remains, and DNF/APT operations on the distribution repositories succeed (ADR-021) |
| N-023 | Loss of the local signer key | No silent reinitialization of trust; recovery procedure |
| N-024 | DNF/APT configuration error during apply | Rollback or an explicit recoverable state |
| N-025 | POST to the loopback repository endpoint | Does not perform configuration actions |
| N-026 | An artifact whose `Obsoletes`/`Replaces` names a system-namespace package, with any version constraint | Hold, `E_SYSTEM_PACKAGE_CONFLICT`, before publication (ADR-022) |
| N-027 | Another source, including a distribution security update, offers a higher version of an activated name or family member | The publisher does not change under the distribution's ordinary update command; a notice names the other source and version (ADR-022) |
| N-028 | The Pakomichi DNF repository is down (connection refused or 503) | The DNF error names the Pakomichi repository, the installed instance is kept, Pakomichi does not switch to `skip_if_unavailable=True` or touch other repository files (ADR-021) |
| N-029 | The socket is in `service-start-limit-hit` after a crash loop | `pchi doctor` reports the outage and the recovery command; recovery runs only after explicit administrator confirmation, never through the status API or HTTP (ADR-021) |
| N-030 | A request to disable RPM signature checks globally, or an Attested-exception RPM whose digest or attestation does not match | Global disable refused before DNF runs; the RPM is held with `E_SIGNATURE_POLICY` or rejected (ADR-023) |
| N-031 | The effective DNF setting read back after writing differs from the written one | `E_ADMIN_APPLY_FAILED`, rollback (ADR-023) |
| N-032 | A DNF source passes its maximum freshness | A signed empty generation is published; installed packages stay; distribution DNF operations succeed; the source's packages are no longer offered; a successful `sync` restores them; `E_SOURCE_STALE` (ADR-024) |
| N-033 | A replayed older signed generation, or a request to move `current` back | Never served as `current`; generation IDs are not reused (ADR-024) |
| N-034 | An unprivileged local user binds the loopback port while the socket is down | Measured with the socket on a privileged port; the port choice follows the result (ADR-024 point 6) |
| N-035 | Astra Linux with the closed software environment on, configured but not running, or unreadable | Activation refused, every artifact held with `E_EXECUTION_POLICY` (ADR-025) |
| N-036 | An apply started from integrity level 0 on Astra Linux | Reported as an integrity-level problem (`E_SECURITY_CONTEXT`), not a package error; nothing partially applied (ADR-025) |
| N-037 | A Pinned source with `--policy preferred`, or a Pinned package name that belongs to the system namespace or is installed from a distribution source | Refused; a distribution package is never displaced, not even by an explicit migration (ADR-027) |
| N-038 | A release with weaker evidence than the source's trust floor | Hold with `E_EVIDENCE_DOWNGRADE`; the floor is not lowered (ADR-027) |
| N-039 | A Pinned release without approval; an asset changed after approval | Not published (`E_RELEASE_APPROVAL_REQUIRED`); the changed asset is `E_ASSET_MUTATED` (ADR-027) |
| N-040 | Pinned consent or release approval through the status API, HTTP, or `--yes` | Refused (ADR-027) |

Each test must record the actual result, the expected reason code, and the test environment versions. A single `unit test passes` must not be treated as verification of real APT/DNF operation.
