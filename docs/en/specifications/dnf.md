# RPM/DNF4/DNF5 contract

**English** · [Русский](../../ru/specifications/dnf.md)

- Each Git source has a unique repo ID; `baseurl` points to our loopback HTTP. The `repomd.xml` metadata and related files form a consistent Snapshot.
- `includepkgs` limits the visibility of admitted names only in our repo, but it does not replace **filtering before publication**: the user may change local settings or DNF options.
- `priority` is verified on a specific DNF version; a smaller number = a more preferred source. Do not consider the policy from our database sufficient.
- Two independent settings: `repo_gpgcheck` (metadata) and the per-package `gpgcheck`/`pkg_gpgcheck`. DNF4 and DNF5 differ in their settings; read the effective global policy.
- An RPM signed by the publisher: native signature verification, provided the other checks succeed.
- An unsigned but attested RPM: admissible **only** if an explicit administrator policy and the OS requirements allow it; never change the global `_pkgverify_level` for the sake of Pakomichi.
- A NetWatch package installed from COPR must not be switched automatically to a GitHub static RPM, even when the Git version is higher. `build_variant` may be unknown, and that is not evidence of equivalence.
- Determining the source of an installed RPM must rely on the package manager's real data; when it is unreliable, the status is unknown.

`R-001`: conflicts and priorities. `R-002`: signature checks. Run DNF4/DNF5 tests in isolation; do not install unsigned packages on production for the sake of a test.
