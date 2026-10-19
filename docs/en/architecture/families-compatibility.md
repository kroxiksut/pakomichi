# Package families and system compatibility

**English** · [Русский](../../ru/architecture/families-compatibility.md)

## Admitted family

One Git repository with one CI may deliver `app`, `app-cli`, `app-service`, `app-common`. On the first connection, the user confirms the set of names and the corresponding native packages; new versions of the same names follow the policy. A new package, even with a similar prefix, requires a review of the composition.

Native `Depends`, `Pre-Depends`, `Provides`, `Conflicts`, `Breaks`, `Replaces`, `Obsoletes`, and architecture requirements are parsed from confirmed files. An ordinary `Provides` should not always be prohibited, but replacement of critical system packages or capture of another party's namespace must not be allowed automatically.

## System dependencies

- They are resolved by the native package manager from already configured OS sources; Pakomichi does not search for arbitrary Git projects.
- We do not initiate library changes from other OS releases; on a conflict with base packages, we hold the release.
- Compatibility conditions are split into `format_arch_ok`, `declared_dependency_satisfiable`, `platform_claimed`, `platform_tested`; without the last one, the result must **not** be treated as a guarantee of successful operation.
- A preliminary dependency check does not replace the real `apt upgrade` or `dnf upgrade` transaction.
- Applications may have implicit requirements for the kernel, API, systemd/paths; report the degree of certainty.

## Family updates

The snapshot provides consistent version metadata. If `app (= 0.6)` depends on `app-service (= 0.6)`, both must be available in the published snapshot, or the new version of `app` is not admitted. **Do not require** the same version number for all components unless the native dependencies require it.

## Build variant changes

GitHub static musl vs COPR dynamic `libpcap` NetWatch: the same publisher, but not necessarily an equivalent package. The `build_variant` field allows `unknown`. A change of variant and vendor is a separate user decision, not a "next update" based only on a higher version.

## Limitation of responsibility

Without global interception of native transactions, Pakomichi cannot guarantee the absence of any system dependency changes during future APT/DNF commands. We ensure the admissibility of *our publication* and honestly state the limits of transactional protection.
