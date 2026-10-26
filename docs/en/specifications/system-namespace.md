# System namespace

**English** · [Русский](../../ru/specifications/system-namespace.md)

ADR-022 point 2 holds an artifact with `E_SYSTEM_PACKAGE_CONFLICT` when any of its `Provides`, or any `Replaces` (DEB) or `Obsoletes` (RPM) whatever its version constraint, names a member of the system namespace: the package names and capabilities of the distribution's own packages and of installed packages that did not come from Pakomichi. The native managers accept such packages (R-001 N-008/N-009), so the check is Pakomichi's own. This specification fixes which sources count as the distribution's own on each first target (ADR-026), what the namespace contains, and how names are compared. The comparison is implemented in `src/namespace`, and reading the namespace from a running system in `src/namespace/collect`.

## Distribution sources

A configured package source is a distribution source when its metadata is authenticated by a key that the distribution itself ships, as recorded in the package database. Names that a repository chooses for itself (`Origin`, `Label`, `Suite`, host names, repository IDs, `name=`) are never used: any repository can write them, and Astra Linux 1.8.6 publishes no `Origin` at all.

- **APT.** The keyring that authenticates the source must be a file owned, in the dpkg database, by the distribution's archive keyring package: the `Signed-By` file of the source, or, for a source without `Signed-By`, a keyring under `/etc/apt/trusted.gpg.d` or `/usr/share/keyrings` owned by that package that verifies the source's `InRelease` (checked with `gpgv`). The file that lists the source does not have to be owned by a package: installers write it.
- **DNF.** The repository section must be in a `.repo` file owned, in the rpm database, by the distribution's repository package, have `gpgcheck=1`, and every `gpgkey` must be a file owned by the distribution's key package.
- Pakomichi's own repositories are never distribution sources.

| Target | Manager | Distribution keyring or key package | Repository-definition package | Observed on 2026-10-21 |
|---|---|---|---|---|
| Debian 12 | APT 2.6 | `debian-archive-keyring` | — (not required) | `/etc/apt/sources.list.d/debian.sources` (owned by no package) lists `bookworm`, `bookworm-updates`, `bookworm-security` with `Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg`, owned by `debian-archive-keyring` |
| Debian 13 (observed 2026-10-25) | APT 3.0 | `debian-archive-keyring` | — (not required) | as Debian 12: `debian.sources` lists `trixie`, `trixie-updates`, `trixie-security` signed by `/usr/share/keyrings/debian-archive-keyring.gpg` |
| Ubuntu 24.04 (observed 2026-10-25) | APT 2.8 | `ubuntu-keyring` | — (not required) | `/etc/apt/sources.list.d/ubuntu.sources` lists `noble`, `noble-updates`, `noble-backports` (`archive.ubuntu.com`) and `noble-security` (`security.ubuntu.com`) with `Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg`, owned by `ubuntu-keyring` |
| Astra Linux 1.8.6 `base(orel)` | APT 2.6 | `astra-archive-keyring` | — (not required) | one-line `/etc/apt/sources.list` without `Signed-By` (`main` and `extended` repositories); key `/etc/apt/trusted.gpg.d/astra-archive.gpg`, owned by `astra-archive-keyring`; `InRelease` has `Label: main` / `extended` and no `Origin`. A third-party source on the same system (`signed-by=/usr/share/keyrings/clickhouse-keyring.gpg`, owned by no package) is correctly not a distribution source |
| AlmaLinux 9.8 | DNF 4.14 | `almalinux-gpg-keys` | `almalinux-repos` | `/etc/yum.repos.d/almalinux-*.repo` owned by `almalinux-repos`; `gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-9`, owned by `almalinux-gpg-keys`; `baseos`, `appstream`, `extras` enabled, `crb` and the rest disabled |
| Fedora 44 | DNF5 5.4 | `fedora-gpg-keys` | `fedora-repos` | `fedora.repo`, `fedora-updates.repo`, `fedora-updates-testing.repo`, `fedora-cisco-openh264.repo` owned by `fedora-repos`; `gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-$releasever-$basearch`, owned by `fedora-gpg-keys`; `fedora`, `updates`, `fedora-cisco-openh264` enabled |

Another distribution build is supported only after its row is added from the same observation.

## Members

- Every package available in an **enabled** distribution source: its name and its `Provides` (DEB), or its provides including file provides and soname provides (RPM), read from the metadata the native manager already downloaded.
- Every installed package (dpkg database, rpm database) that was not installed from a Pakomichi repository: its name and provides (owner decision 2). An installed version counts as Pakomichi's only when the same version with the same digest is in a Pakomichi repository; a name and a version alone never decide it.
- A disabled distribution source contributes nothing, because no metadata exists for it; enabling it changes the source configuration, and the namespace is computed again.

## Comparison

- A relation entry is reduced to its name. DEB: the text before whitespace, `(`, or `:` (`foo (>= 1.0)`, `foo(=1)`, `foo:any` give `foo`). RPM: the first whitespace-separated token, because parentheses belong to capability names (`libc.so.6()(64bit)`, `config(openssl)`, `/usr/bin/ssh`).
- Names compare exactly, case-sensitively.
- Any `Provides` that names a member is a conflict. RPM's automatic self-provides of the package (`name = evr`, `name(arch)`) are not conflicts.
- Any DEB `Replaces` or RPM `Obsoletes` that names a member is a conflict, whatever its version constraint. A stray `|` in a DEB `Provides` or `Replaces` list is split, so nothing hides behind it.
- The package's own name is classified by the role of the member with that name (owner decision 1):
  - a part of the operating system: held with `E_SYSTEM_PACKAGE_CONFLICT`, no migration. A part of the operating system is a DEB package with `Essential: yes` or `Priority: required` or `important`, or in the section `libs` or `oldlibs`; an RPM package in the DNF protected packages (`/etc/dnf/protected.d/`) or among the mandatory and default packages of the comps group `core` (the minimal installation); or a package that provides a shared library (a soname provide such as `libssl.so.3()(64bit)`, or an installed DEB package that ships `shlibs` or `symbols`). The `core` group was added after observation: the protected packages are only `dnf`, `yum`, `setup`, and `systemd` on AlmaLinux 9.8 and `setup` and `sudo` on Fedora 44, while `bash`, `coreutils`, and `curl` belong to `core`;
  - a distribution application or a package installed from elsewhere: not a conflict; the artifact stays `observing` until an explicit migration (ADR-022 point 3, ADR-012), which a Strict or Attested source may offer and a Pinned source never does (ADR-027 point 5);
  - a name that Pakomichi activated before the distribution added a package with that name keeps its publisher, with the notice of ADR-022 point 3; the policy core applies this exception, because only it knows the activation.
- These signals were confirmed on each first target by the collector run below; another build is checked the same way before admission is enabled there.

## Collection

The collector runs unprivileged and reads only what the native managers already have; it never downloads metadata.

- **APT.** `apt-get indextargets` lists the package indexes and the sources entry of each; `apt-get indextargets --no-release-info` also lists the targets whose Release file is still missing. The source's `Signed-By` (one-line or deb822) or, without it, `gpgv` against the keyrings of the archive keyring package decides whether the source is the distribution's; `dpkg-query -S` and `-L` read the ownership. Indexes are read with `apt-helper cat-file` (any compression APT uses), installed packages from `/var/lib/dpkg/status`, and `shlibs`/`symbols` from `/var/lib/dpkg/info`. Keyrings whose name marks them as removed keys never vouch for a source.
- **DNF.** `.repo` files under `/etc/yum.repos.d` owned by the repository package (`rpm -qf`; a path owned by several packages does not count), `gpgkey` paths with `$releasever` and `$basearch` expanded, owned by the key package. Available packages and provides come from `dnf -q -C --repo=<id> repoquery`, the `core` group from `dnf -q -C group info core`, and installed packages from `rpm -qa`. `-C` reads the cache only; DNF5 copies the system cache into the user's home when it runs unprivileged, so the collector gives `dnf` a private, writable `HOME`.
- Every tool runs without a shell, with a cleared environment (`PATH`, `LC_ALL=C`, and `HOME` only for `dnf`), standard input closed, a 300-second deadline, and a 512 MiB output cap; a failure, a timeout, or too much output makes the namespace unknown.
- Missing metadata of a distribution source (no Release file, no index, no DNF cache) is reported as missing metadata with the source named; a system with no enabled distribution source at all is reported as such. Both hold with `E_SYSTEM_NAMESPACE_UNKNOWN`.

The same pass also reads the versions and versioned `Provides` of these packages, and of every other enabled source except Pakomichi's own, for the operating system compatibility check (P2-008b, `architecture/families-compatibility.md`); a name of this namespace is satisfied only by the distribution and installed packages.

## Freshness and unknown state

The namespace is computed again on every synchronization and whenever the OS inventory changes (P2-008). If the metadata of an enabled distribution source is missing or unreadable (before the first `apt update` or `dnf makecache`, after `dnf clean all`, damaged lists), the namespace is unknown: unknown never means "no conflict" (owner decision 3).

- New admissions are held with `E_SYSTEM_NAMESPACE_UNKNOWN`.
- The published generation stays as it is; a cleaned metadata cache never empties Pakomichi's repositories.
- Pakomichi never refreshes the native metadata itself (that is a root package-manager operation with network access); `pchi doctor` and `pchi status` name the source and the command that refreshes it.

## Trust of the inputs

The ownership checks read the dpkg and rpm databases, which only root writes. The members come from the metadata lists that the native manager verified when it downloaded them. On Astra Linux with integrity control, a level-0 process can write the APT lists (ADR-025 point 7); an attacker who can rewrite them can shrink the namespace, but already controls what APT itself selects from those lists. Pakomichi never takes package bytes from these lists.

## Tests

- In code (`src/namespace/tests.rs`): N-008 (a `Provides` of the C library, by package name, soname, and file), N-026 (`Replaces` and `Obsoletes` with any version), self-provides, a stray `|`, the own-name roles (part of the operating system held, distribution application and package installed from elsewhere needing a migration), a package installed from elsewhere protected from `Obsoletes`, and stable reporting.
- In code (`src/namespace/collect/parse_tests.rs`): build profiles from `os-release`, deb822 and one-line sources, `Signed-By` forms, list file names, `dpkg-query -S` owners, DEB roles, `.repo` sections with DNF defaults and continuation lines, `gpgkey` expansion, repoquery output, the `core` group in DNF4 and DNF5 output, protected package files, and soname provides.
- Before admission is enabled on a target: the collector on that exact build classifies its sources as in the table above, refuses a third-party source that copies the distribution's names or repository ID, and holds N-008 and N-026 with real metadata (`src/namespace/collect/system_tests.rs`, ignored by default, run on the target).

Live run of 2026-10-21, as an unprivileged user (uid 65534 in fresh WSL distributions from the digest-pinned R-001 images; the owner's Astra Linux 1.8.6 VM resumed from its saved state, uid 1000):

| Target | Distribution sources found | Members | Time | Third-party source refused | Unknown state |
|---|---|---|---|---|---|
| Debian 12 | `bookworm`, `bookworm-updates`, `bookworm-security` | 98 730 | 2.7–3.5 s | a `ftp.debian.org` source signed by an unowned copy of the Debian keyring | lists removed: missing metadata of `bookworm` |
| Astra Linux 1.8.6 | `main` and `extended` from both mirrors | 51 191 | 14.3 s (4.3 s warm) | ClickHouse | — (owner's VM, not changed) |
| AlmaLinux 9.8 | `baseos`, `appstream`, `extras` | 104 425 | 19.6–20.6 s | a copy of the `baseos` section in an unowned `.repo` file | after `dnf clean all`: missing metadata |
| Fedora 44 | `fedora`, `updates`, `fedora-cisco-openh264` | 581 302 | 9.7 s | a copy of the `fedora` section in an unowned `.repo` file | after `dnf clean all`: missing metadata |
| Debian 13 (2026-10-25, `research/p2-008b/run.ps1 -Target debian13 [-Vendor copy]`) | `trixie`, `trixie-updates`, `trixie-security` | 134 627 | 4.8 s | a `ftp.debian.org` `trixie` source signed by an unowned copy of the Debian keyring | not run |
| Ubuntu 24.04 (2026-10-25, `-Target ubuntu2404 [-Vendor copy]`) | `noble`, `noble-updates`, `noble-backports`, `noble-security` | 140 986 | 12.2 s | a `mirrors.edge.kernel.org` `noble` source signed by an unowned copy of the Ubuntu keyring | not run |

On every target `bash`, `coreutils`, `systemd`, and the C library are parts of the operating system and `openssl` is a distribution application; `curl` is a distribution application on Debian and Astra Linux and a part of the operating system on AlmaLinux and Fedora (group `core`); `gh` is a distribution application where the distribution ships it (Debian, Fedora). A `Provides` plus a `Replaces` (DEB) or `Obsoletes` (RPM) of the C library gives two conflicts on every target.

## Owner decisions of 2026-10-21

1. **The own name** follows the role of the existing package: a part of the operating system is held; a distribution application or a package installed from elsewhere needs an explicit migration (Strict or Attested only); a name activated before the distribution added it keeps its publisher. Holding every collision was rejected, because ADR-027 point 5 and ADR-012 allow an explicit migration away from a distribution application; never holding was rejected, because it would let one consent replace `openssl` or `glibc`.
2. **Installed packages from other sources** are members, so that an artifact cannot replace or obsolete, silently on an ordinary upgrade, a program the user installed from a PPA, COPR, or by hand. This is stricter than the letter of ADR-022 point 2; the cost is an occasional, explained hold, for example when a project renames its package and the old one was installed by hand.
3. **An unknown namespace** has its own reason code, `E_SYSTEM_NAMESPACE_UNKNOWN`, because the remedy (refresh the native metadata) differs from that of a conflict (change the package); new admissions are held and the published generation stays.
4. **The comps group `core`** marks a part of the operating system on DNF targets, because the protected packages alone leave `bash` and `coreutils` replaceable through a migration. As a result, a package such as `curl` is a part of the operating system on AlmaLinux and Fedora (it is in `core`) and a distribution application on Debian and Astra Linux; this difference is accepted.
