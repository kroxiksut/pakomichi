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

## Family admission (P2-007)

A family is in one of two states. **Proposed:** found on the first connection; nothing is admitted until the administrator confirms the set of names. **Approved:** confirmed at a revision; new versions of these names follow the policy. A confirmation names the revision it was shown, so a confirmation of an older revision is refused. Both the first confirmation and every extension come only from an interactive administrator action, never from an automatic `yes`.

For one target, the admission decides every known artifact of the family, the new ones and the already published ones, in this order:

1. **Composition.** A name outside the family, or a member built for an architecture that was not confirmed, is held with `E_FAMILY_UNAPPROVED` and listed in a composition review. Nothing the package claims (`Provides`, `Replaces`, `Obsoletes`, or a member that depends on it) makes it a member. Confirming the review creates the next revision with those names. An artifact that an earlier check holds (the system namespace, the trust level, the channel) keeps that check's reason.
2. **Identity.** The same bytes twice keep the first artifact. Two different files of one name and architecture whose versions compare equal under the native rules are both held with `E_SOURCE_AMBIGUOUS`; `1.0` and `1.00` are the same dpkg version.
3. **Family dependencies.** A dependency entry is the family's own when every alternative names something only the family offers: a member name, or a `Provides` of a member artifact that the system namespace does not contain. Another admissible artifact of the family must satisfy it under the native rules (dpkg: an unversioned `Provides` never satisfies a versioned dependency; RPM: range overlap, an unversioned `Provides` matches every version, and a requirement without a release matches every release). Otherwise the artifact is held with `E_DEPENDENCY_UNSATISFIABLE`, repeated until no more holds follow. Entries that the system may satisfy, file dependencies, and `rpmlib()` features are left to the native manager. An RPM rich dependency that names a member is not evaluated and holds the artifact.
4. **Publication.** The newest admissible version of every name and architecture is published, together with every older artifact that its family dependencies need.

Versions are compared with the native algorithms (dpkg `verrevcmp`, RPM `rpmvercmp` and `rpmverOverlap`), never lexicographically. The shared vectors in `tests/data/native-versions.tsv` are checked against Pakomichi's comparators by `cargo test` and against the native tools by `scripts/check-native-versions.py`. A malformed version or relationship field rejects the bytes with `E_ARTIFACT_MALFORMED`. This includes what dpkg accepts only with a warning (an invalid character in the version or revision), except an upstream version that does not start with a digit.

## Build variant changes

GitHub static musl vs COPR dynamic `libpcap` NetWatch: the same publisher, but not necessarily an equivalent package. The `build_variant` field allows `unknown`. A change of variant and vendor is a separate user decision, not a "next update" based only on a higher version.

## Astra Linux protected levels (ADR-025)

With the closed software environment on, `dpkg` and APT install a package with an unsigned ELF with exit 0, but the program is killed with `SIGSEGV`; a key not signed by the Astra Linux root key cannot be trusted. Pakomichi therefore refuses to activate sources and holds every artifact while the closed environment is on or cannot be ruled out, never signs or modifies third-party files, never adds keys to `/etc/digsig/keys`, and never changes the security level. When the closed environment is on, an installed program that exits with `SIGSEGV` is reported as a probable refusal of an unsigned executable, not as a package defect. R-006 did not cover the `external_sig` and xattr modes, the interpreter, `chmod +x`, and `bash` locks (which can affect maintainer scripts), or shared libraries.

## Limitation of responsibility

Without global interception of native transactions, Pakomichi cannot guarantee the absence of any system dependency changes during future APT/DNF commands. We ensure the admissibility of *our publication* and honestly state the limits of transactional protection.
