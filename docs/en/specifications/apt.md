# APT contract

**English** · [Русский](../../ru/specifications/apt.md)

## Adapter outputs

- For each active logical source: a Pakomichi-owned `.sources`/`.list` file (modern deb822 where possible), unique `Origin`, `Label`, `Suite` fields, and `Signed-By` set to *our* keyring; do not use the global `apt-key`/`trusted=yes`.
- A signed `InRelease` (and `Release.gpg` when needed), `Packages`/`Packages.gz`, correct checksums/architectures fields, `Acquire-By-Hash`, and time-bounded `Valid-Until` validity.
- An **initially low priority** for the Git source; for a deliberately selected package, targeted rules verified with `apt-cache policy`.

## Constraints

- `apt_preferences` selects a **version**, not an instance of the same version among several URLs. With identical NEVRA/versions and different bytes, it must not be claimed that a pin ensures origin safety. `R-001`.
- Do not rename or modify other parties' packages; do not change files of other APT repositories or the global policy.
- A binary SHA match of two *available files* may indicate content equivalence; an actually proven SHA is required, not just a name/version.
- Activation happens after reading the `dpkg` inventory and the repositories and after a verified `apt-get -s` transaction simulation, with an understanding of that simulation's limitations.
- If the preferred mode cannot be carried out, remain in `observing`/`held`. Do not change the package's original version for the sake of a pin.

## Tests

Debian 12/13, Ubuntu 24.04 (in the matrix only when an isolated environment actually exists). Two identical `.deb` files with the same version and different sha, permutation of order and Pin-Priority, a selected package family (main/service), a system dependency update, loss of the local server, Valid-Until.
