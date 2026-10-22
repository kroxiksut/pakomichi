# Matrix of platforms under test

**English** · [Русский](../../ru/testing/matrix.md)

This is a test plan, not a statement of support. The final alpha must list **only actually tested** combinations. Admission of a build to the 0.1 claim follows ADR-026: on that exact build, the R-001 selection matrix; for RPM, the R-002 matrix; the R-004 delivery subset (socket activation, generations with native clients, third-party repositories and removal) on a VM with real systemd and the distribution's default SELinux or AppArmor mode; the SQLite version recorded and the migration tests passed (ADR-020); and E2E-01 or E2E-02 plus the applicable N-tests with Pakomichi's own package.

| Ecosystem | Environment | Status for 0.1 | Missing before a claim |
|---|---|---|---|
| APT 2.6 | Debian 12 amd64 | First target | MAC mode check, E2E and N-tests |
| APT 2.6 | Astra Linux 1.8.6 `base(orel)` amd64 | First target (ordinary command `apt-get dist-upgrade`) | R-004 delivery subset, E2E and N-tests |
| DNF4 | AlmaLinux 9 amd64 | First target | Delivery subset and E2E with SELinux enforcing, N-tests |
| DNF5 | Fedora 44 amd64 | First target | Delivery subset and E2E with SELinux enforcing, N-tests |
| APT 3.0 | Debian 13 amd64 | Conditional | Everything of ADR-026 point 1 except R-001 |
| APT 2.8 | Ubuntu 24.04 amd64 | Conditional | Everything of ADR-026 point 1 except R-001 |
| APT 3.2 | Ubuntu 26.04 amd64 | Conditional | Everything of ADR-026 point 1 except R-001 |
| DNF4 | AlmaLinux 10 amd64 | Conditional | Everything of ADR-026 point 1 except R-001 |
| DNF4 | RED OS 8 / 7.3 amd64 | Later target | Everything of ADR-026 point 1 except R-001 (R-001 with deviations; SQLite on 7.3 not checked) |
| APT | Astra Linux with the closed software environment | Not claimed (ADR-025) | Pakomichi binaries signed through the Astra Linux key chain, R-006 cells 2–5 again |
| APT | Astra Linux 1.7 | Not claimed at any level (outdated; owner decision of 2026-10-21) | — |
| APT/RPM | arm64 / aarch64, ALT Linux | Not claimed | — |

Do not infer the system version `bookworm/trixie/...` from the machine name; save `os-release`, `uname -a`, the manager versions, and the list of sources. Socket activation requires an environment with real systemd, not an arbitrary container without init. Every selection rule is verified per distribution build, not inferred from the manager's version.

## For each test environment

- Fresh VM snapshot, local test repos, and laboratory keys.
- Isolation of `dpkg/rpm` state from production.
- The SELinux/AppArmor mode and, on Astra Linux, the security level, the closed-environment state, and integrity control.
- Command logs: `apt-cache policy`, `apt-get -s`, `dnf repolist`, actual SHAs of downloaded artifacts, repository signature.
- Negative cases: matching versions, GPG refusal, stale snapshot, offline behavior.
- PASS/FAIL/INCONCLUSIVE with a reason, links to the R report.
