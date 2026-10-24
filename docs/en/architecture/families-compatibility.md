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

## Operating system compatibility (P2-008a)

`src/compat` decides, for one artifact and one target, the four facts above, a confidence, and the reason to hold the artifact. In this order:

1. **Execution policy.** While the operating system's execution policy is on or cannot be ruled out (on Astra Linux the closed software environment), every artifact is held with `E_EXECUTION_POLICY` and sources are not activated (ADR-025, N-035). "Unknown" is never read as "off".
2. **Format and architecture.** A package of another ecosystem, or of an architecture other than the target's native or universal one, is held with `E_PLATFORM_UNSUPPORTED` (`format_arch_ok`).
3. **Build tags.** Tags of the version's own ecosystem are read: `.elN`/`.fcN` in an RPM release; `debN`, `bpoN`, Debian and Ubuntu code names, `ubuntu`, `astra` in a DEB version. When the target's own tag is present it decides, so a rebuild that keeps its origin tag (`+deb12u4+astra1`) is not foreign.
   - A tag of the target distribution and release: `platform_claimed`.
   - A tag of another distribution (`.fc44` on AlmaLinux 9, `ubuntu` on Debian or on Astra Linux) is held with `E_PLATFORM_UNSUPPORTED`.
   - Another release of the target distribution (`~bpo11` on Debian 12, `.el8` on AlmaLinux 9) follows the setting `other_release_builds`: `dependencies` (default) lets the dependencies decide with low confidence, `hold` holds it (owner decision of 2026-10-23). A build for the distribution the target is based on counts the same way: Astra Linux 1.8 is based on Debian 12, so `+deb12u1` there is another release, not a foreign build (owner decision of 2026-10-23).
   - No known tag: a generic build; the dependencies decide.
4. **System data.** Without data about the system's packages of the target ecosystem nothing can be checked, so the artifact is held with `E_SYSTEM_NAMESPACE_UNKNOWN`.
5. **Dependencies.** Every clause the family does not offer must be satisfied by a system package or `Provides` under the native rules (`family::offer_satisfies`, the same rule as the family admission; `2.36-9+deb12u10` is newer than `2.36-9+deb12u9`, `3.0.17-1~deb12u2` older than `3.0.17-1`). A name the system knows is always checked against the system, even when the family claims to offer it, so a family cannot make a newer C library look satisfied. Offers carry their origin: the distribution, an installed package, or another enabled source (a vendor repository, a PPA, a COPR; ADR-032). A name of the system namespace is satisfied only by the distribution and installed packages; any other name also by other sources, so `postgresql-16` from a configured vendor repository satisfies an application, while a newer `libc6` from it does not (owner decision of 2026-10-23). A clause nothing satisfies is held with `E_DEPENDENCY_UNSATISFIABLE`, and nothing is looked for elsewhere (N-009). RPM rich dependencies are left to the native manager and lower the confidence.

Confidence: `tested` (a test record exists for the target and nothing is held), `claimed` (a build for the target whose dependencies are satisfied), `dependencies satisfiable` (a generic build), otherwise `low`. A test record never overrides a hold. **Collection (P2-008b).** The collector of the system namespace (`namespace::collect`, `specifications/system-namespace.md`) reads in the same pass, without root, the versions and versioned `Provides` of the distribution's packages (APT indexes, `dnf -C repoquery … %{evr} %{provides}`), of installed packages (dpkg `status`, `rpm -qa … %{EVR} [%{PROVIDENEVRS}]`), and of every other enabled source except Pakomichi's own. Another source whose metadata cannot be read is listed and contributes nothing, so a dependency only it offers is held. The execution policy is read by `compat::policy`: on Astra Linux `DIGSIG_ELF_MODE` in `/etc/digsig/digsig_initramfs.conf` (any value but `0` is on); `0` counts as off only when the file was not changed after the current boot (`btime` of `/proc/stat`), otherwise, and when the file or the key is missing, the policy cannot be ruled out (ADR-025 point 1). Other first targets have no execution policy that refuses files installed by the package manager. Live run without root on Debian 12, AlmaLinux 9.8, Fedora 44 and Astra Linux 1.8.6 `base(orel)` (`research/p2-008b/`): N-009 holds a dependency on a C library from a future release and admits the system's own; the policy is `Off` everywhere, on Astra Linux from `DIGSIG_ELF_MODE=0` in a file older than the boot. With the PostgreSQL PGDG repository added on Debian 12, `postgresql-16` (only PGDG) is admitted and `libpq5 (>= 17)` is held, although PGDG offers 18.6, because Debian ships `libpq5` 15. A consequence: an application that needs a vendor's newer build of a library the distribution also ships is held, even where the native manager would install it from the vendor. The live N-035 run with the closed environment on was deferred by the owner on 2026-10-23; the rule is covered by tests on the file contents R-006 recorded.

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
