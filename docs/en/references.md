# Primary technical sources and verifiable claims

**English** · [Русский](../ru/references.md)

The links were available for re-verification as of **2026-10-18**; before coding, take into account the version of the installed package and possible documentation changes.

## APT

- [apt_preferences(5), Debian](https://manpages.debian.org/bookworm/apt/apt_preferences.5.en.html) — a pin affects the **version**; when two sources offer the same version, the chosen instance may depend on the order of the sources.
- [sources.list(5), Debian](https://manpages.debian.org/testing/apt/sources.list.5.en.html) — `Signed-By`, `Valid-Until` checks, deb822.
- [apt-secure(8), Debian](https://manpages.debian.org/bookworm/apt/apt-secure.8.en.html) — trust in signed metadata and packages.
- [apt-ftparchive(1)](https://manpages.debian.org/bookworm/apt-utils/apt-ftparchive.1.en.html) — generation of indexes and Release.

## DNF/RPM

- [DNF4 configuration](https://man7.org/linux/man-pages/man5/dnf4.conf.5.html) — `gpgcheck`, `repo_gpgcheck`, `priority`, filters, and enforced RPM policy.
- [DNF5 configuration](https://dnf5.readthedocs.io/en/stable/dnf5.conf.5.html) — `pkg_gpgcheck`, `repo_gpgcheck`, `gpgcheck_policy`, `includepkgs`.
- [RPM signing](https://rpm.org/docs/4.20.x/manual/signatures.html) — package signatures and checks (the documentation version may differ from the package under test).

## GitHub

- [REST API Releases](https://docs.github.com/en/rest/releases/releases) — `immutable`, release ID, assets.
- [REST API release assets](https://docs.github.com/en/rest/releases/assets) — asset ID, `digest`.
- [Immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases) — what is locked and which attestations are produced.
- [Offline verification of attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline) — sourceRepositoryIdentifier, numeric repo ID comparison.
- [Artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations) — signed provenance, limits of the guarantees.
- [gh attestation verify](https://cli.github.com/manual/gh_attestation_verify) — reference verifier, predicate, signer identity, and flags.

## systemd and an external example

- [systemd.socket](https://www.freedesktop.org/software/systemd/man/latest/systemd.socket.html) — `ListenStream`, `Accept=no`, and socket activation.
- [NetWatch](https://github.com/matthart1983/netwatch), [PACKAGING.md](https://github.com/matthart1983/netwatch/blob/main/docs/PACKAGING.md) — a real-world combination of GitHub `.deb/.rpm`, a separate APT repository, and COPR.

**Status:** the sources provide grounds for architectural decisions; they do not replace the `R-001...R-004` experiment on the target OS.
