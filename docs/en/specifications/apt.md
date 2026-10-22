# APT contract

**English** · [Русский](../../ru/specifications/apt.md)

## Adapter outputs

- For each active logical source: a Pakomichi-owned `.sources`/`.list` file (modern deb822 where possible), unique `Origin`, `Label`, `Suite` fields, and `Signed-By` set to *our* keyring; do not use the global `apt-key`/`trusted=yes`. Each provenance level of a source has its own logical repository with a distinct `Label`/`Origin`, so that `apt policy` shows the level (ADR-027).
- A signed `InRelease` (and `Release.gpg` when needed), `Packages`/`Packages.gz`, correct checksums/architectures fields, and time-bounded `Valid-Until` validity equal to the confirmed freshness.
- `Acquire-By-Hash: yes` is mandatory, and every index is served under its `by-hash` path. Only `InRelease`, `Release`, `Release.gpg`, and the plain compatibility index paths are mutable, and they are served only from the current generation (ADR-024).
- An **initially low priority** for the Git source. For every activated name, including every member of the activated family, a targeted preference with `Pin-Priority: 990` matched by `Pin: release o=…,l=…` of the source's logical repository (ADR-022 point 3), verified with `apt-cache policy`. `Pin: origin` is not used, because one loopback host serves all logical repositories; a priority of 1000 or higher is never written, because it allows downgrades.

## Constraints

- `apt_preferences` selects a **version**, not an instance of the same version among several URLs. APT 2.6 merges equal versions and source order decides; APT 2.8+ binds the instance only for a fresh install. An equal version with different bytes is `E_SOURCE_AMBIGUOUS` on every APT version, and no pin is claimed to ensure origin safety (R-001, ADR-022 point 1).
- An activated name keeps its publisher when another source, including a distribution security update, later offers a higher version; Pakomichi shows a notice and the switch is an explicit user decision (ADR-022).
- An artifact whose `Provides` or `Replaces` names a member of the system namespace is held in admission (`E_SYSTEM_PACKAGE_CONFLICT`, ADR-022 point 2); APT itself accepts a third-party `Provides` of the C library (R-001 N-008/N-009).
- Do not rename or modify other parties' packages; do not change files of other APT repositories or the global policy. Never require `APT::Get::EnableUpgrade`.
- A binary SHA match of two *available files* may indicate content equivalence; an actually proven SHA is required, not just a name/version.
- Activation happens after reading the `dpkg` inventory and the repositories and after a verified `apt-get -s` transaction simulation, with an understanding of that simulation's limitations.
- If the preferred mode cannot be carried out, remain in `observing`/`held`. Do not change the package's original version for the sake of a pin.
- `apt-get update` exits 0 when a source is offline; source health comes from Pakomichi's own state, never from that exit status (ADR-022 point 6).
- `/var/lib/apt/lists` and `/var/cache/apt/archives` are never trusted input (ADR-025 point 7).

## Ordinary update command

`apt upgrade` and `apt full-upgrade` on Debian and Ubuntu; `apt-get dist-upgrade` on Astra Linux, which refuses `apt upgrade` and `apt-get upgrade` (R-001). The protection above must be shown under each listed command (ADR-022 point 4).

## Astra Linux

The supported level in 0.1 is `base(orel)` on Astra Linux 1.8.6 (ADR-026). The security level, the closed software environment, and integrity control are detected without root; while the closed environment is on, or cannot be ruled out, activation is refused and every artifact is held with `E_EXECUTION_POLICY` (ADR-025). The applier runs at integrity level 63 (a systemd service or the administrator's session); a failed apply from a lower level is reported as an integrity-level problem (`E_SECURITY_CONTEXT`).

## Tests

Only on builds admitted by ADR-026; the first APT targets are Debian 12 and Astra Linux 1.8.6 at `base(orel)`. Two `.deb` files with the same version and different sha, permutation of order and Pin-Priority, a selected package family (main/service), a higher version of an activated name from another source under each ordinary update command, the `Pin: release` match on one loopback host, a system dependency update, loss of the local server, Valid-Until, a replayed older generation.
