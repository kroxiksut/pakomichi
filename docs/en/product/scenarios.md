# Use cases and expected behavior

**English** · [Русский](../../ru/product/scenarios.md)

**UC-01, first package:** the user specifies a concrete Git URL; Pakomichi pins the ID, verifies the release/package and checks for name conflicts, then offers to activate the admitted package. After activation, ordinary `apt install` or `dnf install` is used.

**UC-02, several packages from one CI:** one Git repository publishes an application, a CLI, a service, and shared components; all of them may form an admitted package family. Native dependencies among them are resolved without connecting new Git projects.

**UC-03, the package already exists in the OS:** initially the native source is preferred; the user explicitly chooses Git when needed. There is no automatic switching from one publisher to another.

**UC-04, Git and the system repository provide the same version with different files:** APT pinning alone cannot reliably select the required bytes; Pakomichi does not activate a conflicting automatic update without a proven safe method.

**UC-05, incompatible system libraries are required:** do not search for the libraries in another Git project; reject the unsuitable version. OS system updates are managed by the system package manager.

**UC-06, repository transfer:** the ID is unchanged but the owner has changed — suspend updates until the transfer is explicitly confirmed. A new Git project with the old name does not inherit trust.

**UC-07, GitHub is unavailable:** the previous verified snapshot remains available only within the configured freshness period; a package without local bytes cannot be installed offline; other system sources are not modified.

**UC-08, disabling/removal:** remove only the source record and our rules; do not remove installed programs and do not rewrite other parties' files.

**UC-09, external state change:** if an administrator ran `dpkg -i`, disabled a repo, or configured DNF, detect the divergence and do not present the internal database as the single source of truth.

**UC-10, a fork or another repository of the author:** even version `999.0` of another project is never accepted as an update of an existing source.
