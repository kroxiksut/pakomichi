# Matrix of platforms under test

**English** · [Русский](../../ru/testing/matrix.md)

This is a test plan, not a statement of support. The final alpha must list **only actually tested** combinations.

| Ecosystem | Experiment environment | Checks |
|---|---|---|
| APT | Debian 12 amd64 | `apt --version`, systemd, signature, install→upgrade, equal version conflict |
| APT | Debian 13 amd64 | The same + modern deb822 source |
| APT | Ubuntu 24.04 amd64 | The same + system libraries |
| DNF4 | a distribution image with DNF4 actually installed | RPM signatures, policy, family, origin collision |
| DNF5 | a distribution image with DNF5 actually installed | pkg/repo GPG semantics, command differences |
| APT | Debian arm64 (if CI/VM is available) | asset selection and native metadata |
| RPM | aarch64 (if CI/VM is available) | ABI/arch, dependencies |
| Astra Linux | **do not claim support without a separate test** | real environment and OS policy |

Do not infer the system version `bookworm/trixie/...` from the machine name; save `os-release`, `uname -a`, the manager versions, and the list of sources. Socket activation requires an environment with real systemd, not an arbitrary container without init.

## For each test environment

- Fresh VM snapshot, local test repos, and laboratory keys.
- Isolation of `dpkg/rpm` state from production.
- Command logs: `apt-cache policy`, `apt-get -s`, `dnf repolist`, actual SHAs of downloaded artifacts, repository signature.
- Negative cases: matching versions, GPG refusal, stale snapshot, offline behavior.
- PASS/FAIL/INCONCLUSIVE with a reason, links to the R report.
