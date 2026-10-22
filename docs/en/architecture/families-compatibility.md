# Package families and system compatibility

**English** · [Русский](../../ru/architecture/families-compatibility.md)

## Admitted family

One Git repository with one CI may deliver `app`, `app-cli`, `app-service`, `app-common`. On the first connection, the user confirms the set of names and the corresponding native packages; new versions of the same names follow the policy. A new package, even with a similar prefix, requires a review of the composition.

Native `Depends`, `Pre-Depends`, `Provides`, `Conflicts`, `Breaks`, `Replaces`, `Obsoletes`, and architecture requirements are parsed from confirmed files. An ordinary `Provides` should not always be prohibited, but replacement of critical system packages or capture of another party's namespace must not be allowed automatically.

## System namespace (ADR-022)

The system namespace is the set of package names and `Provides` (package names and virtual capabilities, file provides, soname provides) of the packages from the distribution's own sources. An artifact is held with `E_SYSTEM_PACKAGE_CONFLICT` when any of its `Provides` names a member of the system namespace, and also when its `Obsoletes` or `Replaces` names one, whatever the version constraint. Capabilities provided only by the admitted family itself stay allowed. R-001 showed that every tested manager accepts a third-party `Provides` of the C library and uses it to satisfy a versioned requirement, so this check runs in Pakomichi's admission. Which configured sources count as the distribution's own sources on each supported build, what the namespace contains, and how names compare are fixed in [`specifications/system-namespace.md`](../specifications/system-namespace.md).

Every member of an activated family has the same publisher protection as the main package: a higher version from another source does not change its publisher (ADR-022 point 3). Family dependencies across sources are resolved silently by the native managers, so the published snapshot must contain the whole consistent family.

## System dependencies

- They are resolved by the native package manager from already configured OS sources; Pakomichi does not search for arbitrary Git projects.
- We do not initiate library changes from other OS releases; on a conflict with base packages, we hold the release.
- Compatibility conditions are split into `format_arch_ok`, `declared_dependency_satisfiable`, `platform_claimed`, `platform_tested`; without `platform_tested`, compatibility must **not** be presented as confirmed, and even `platform_tested` is not a guarantee of successful operation.
- A preliminary dependency check does not replace the real `apt upgrade` or `dnf upgrade` transaction.
- Applications may have implicit requirements for the kernel, API, systemd/paths; report the degree of certainty.

## Family updates

The snapshot provides consistent version metadata. If `app (= 0.6)` depends on `app-service (= 0.6)`, both must be available in the published snapshot, or the new version of `app` is not admitted. **Do not require** the same version number for all components unless the native dependencies require it.

## Build variant changes

GitHub static musl vs COPR dynamic `libpcap` NetWatch: the same publisher, but not necessarily an equivalent package. The `build_variant` field allows `unknown`. A change of variant and vendor is a separate user decision, not a "next update" based only on a higher version.

## Astra Linux protected levels (ADR-025)

With the closed software environment on, `dpkg` and APT install a package with an unsigned ELF with exit 0, but the program is killed with `SIGSEGV`; a key not signed by the Astra Linux root key cannot be trusted. Pakomichi therefore refuses to activate sources and holds every artifact while the closed environment is on or cannot be ruled out, never signs or modifies third-party files, never adds keys to `/etc/digsig/keys`, and never changes the security level. When the closed environment is on, an installed program that exits with `SIGSEGV` is reported as a probable refusal of an unsigned executable, not as a package defect. R-006 did not cover the `external_sig` and xattr modes, the interpreter, `chmod +x`, and `bash` locks (which can affect maintainer scripts), or shared libraries.

## Limitation of responsibility

Without global interception of native transactions, Pakomichi cannot guarantee the absence of any system dependency changes during future APT/DNF commands. We ensure the admissibility of *our publication* and honestly state the limits of transactional protection.
