# RPM/DNF4/DNF5 contract

**English** · [Русский](../../ru/specifications/dnf.md)

## Repository configuration

- Each Git source has a unique repo ID; `baseurl` points to our loopback HTTP. The `repomd.xml` metadata and related files form a consistent Snapshot. Repository IDs and `name` values identify Pakomichi, the source, and the provenance level, so that `dnf repolist` and DNF's own error messages point at the Pakomichi repository (ADR-021, ADR-027).
- Every Pakomichi repository section sets `skip_if_unavailable=False` explicitly, on DNF4 and DNF5, regardless of the distribution default (ADR-021). While a Pakomichi repository is unavailable, DNF operations that load the metadata of all enabled repositories fail; this is a documented limitation. Pakomichi never switches its repositories to `True`, never disables them, and never edits third-party repository files to restore availability. `pchi doctor` reports the outage and the recovery command.
- `includepkgs` limits the visibility of admitted names only in our repo, but it does not replace **filtering before publication**: the user may change local settings or DNF options.
- `priority` is verified on a specific DNF build; a smaller number = a more preferred source. For activated names our repository has a priority better than the distribution repositories, and `includepkgs` lists only those names (ADR-022 point 3). `allow_vendor_change` is read and reported, never written (it is global) and never relied upon (absent in DNF 4.2). `excludepkgs` is never written into other repositories. Do not consider the policy from our database sufficient.
- `repodata` files have unique, digest-bearing names (never `--simple-md-filenames`); only `repomd.xml` and `repomd.xml.asc` are mutable and are served only from the current generation (ADR-024).

## Signatures (ADR-023)

- Two independent gates, each failing closed with its own diagnostic: `repo_gpgcheck=1` with signed `repomd.xml` (the local key), and package trust.
- DNF4 and DNF5 are separate adapters. DNF4 writes per-repository `gpgcheck` and `repo_gpgcheck` and treats `%_pkgverify_level` as the superior policy (DNF 4.14 has neither `pkg_gpgcheck` nor `gpgcheck_policy`); DNF5 writes `pkg_gpgcheck` and `repo_gpgcheck` explicitly and records `gpgcheck_policy`. An adapter never emits a setting its DNF does not support. After writing, the applier reads back the effective values; a mismatch is `E_ADMIN_APPLY_FAILED`. RPM 6 is a separate supported stack.
- **Native mode:** an RPM signed by the publisher, verified natively against the publisher key pinned for the source, with package checking on for its repository. Importing that key into the system RPM keyring needs explicit consent to its fingerprint and a warning that RPM then accepts it for packages from any source. The removal procedure for an imported key is fixed here before Native mode is implemented.
- **Attested exception (waits for R-003):** an unsigned RPM is published only after the production attestation verifier verified it, bound to its exact SHA-256, with explicit consent for the source, and only when the effective `%_pkgverify_level` is neither `signature` nor `all`. It is served from a separate logical repository of that source containing only such packages; package checking is disabled only for that Pakomichi repository. Otherwise it is held with `E_SIGNATURE_POLICY`.
- Never write a global `gpgcheck=0`, `pkg_gpgcheck=0`, `localpkg_gpgcheck` change, or `%_pkgverify_level` change; a requested global disable is refused before DNF is invoked.
- Repository metadata is generated only from the final verified RPM bytes; signing never rewrites an RPM.

## Freshness and generations (ADR-024)

- `repomd.xml` has no signed expiry and DNF accepts a replay of older signed metadata, so freshness and no-rollback are enforced on the server: generation IDs are monotonic and `current` never moves back.
- When the last confirmed synchronization of a source is older than the maximum freshness (7 days by default), Pakomichi publishes a new signed **empty generation** of that source's repository instead of answering 503 or serving stale data. Installed packages stay installed, DNF keeps working for the rest of the system, the source's packages are not offered until a successful `sync`, and `pchi doctor`/`pchi status` show `E_SOURCE_STALE`.
- RPM generations switch at most once per regular check interval (6 h), except on `sync --force` and for the empty generation, because `repomd.xml.asc` and `repomd.xml` are separate paths. A metadata-signature failure right after a switch is retryable, not corruption.

## Selection and installed state

- An equal version with different bytes is `E_SOURCE_AMBIGUOUS`; DNF priority is not a substitute (`distro-sync` and `reinstall` move to the currently preferred instance; on RED OS 7.3 and 8 `reinstall` takes the instance from the repository with the *worst* priority, R-001).
- An activated name keeps its publisher when another source, including a distribution security update, later offers a higher version; Pakomichi shows a notice (ADR-022).
- A NetWatch package installed from COPR must not be switched automatically to a GitHub static RPM, even when the Git version is higher. `build_variant` may be unknown, and that is not evidence of equivalence.
- Determining the source of an installed RPM must rely on the package manager's real data; when it is unreliable, the status is unknown.
- Uninstalling Pakomichi and removing a source delete the Pakomichi `.repo` files of that source (ADR-021).

## Ordinary update command and builds

`dnf upgrade`. Every rule is verified on every supported distribution build, not inferred from the DNF version: RED OS differs from upstream DNF 4.14/4.20 in `reinstall`, defaults, and options (ADR-022 point 5). For AlmaLinux and Fedora, support is claimed only after runs with SELinux enforcing (ADR-026).

`R-001`: conflicts and priorities. `R-002`: signature checks. `R-004`: delivery and generations. Run DNF4/DNF5 tests in isolation; do not install unsigned packages on production for the sake of a test.
