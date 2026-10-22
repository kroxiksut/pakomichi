# Trust and threat model

**English** · [Русский](../../ru/architecture/trust.md)

## What we trust

The user independently chooses a **specific** repository; we do not prove the publisher's honesty. Our goal is not to substitute the choice, not to accept bytes from another repo, and not to serve a corrupted artifact. We do not trust an arbitrary `owner/repo` string after an ownership change, an unsigned file name, `latest`, an RPM/DEB name, or HTTPS as evidence of the absence of malware.

## Strict

GitHub immutable release + cryptographically verified release attestation (with the required predicate type) + repository ID in the certificate/attestation + correspondence of release/assets + SHA-256 of the actual file. Verify the real fields/chain in R-003; the API `immutable=true` alone is insufficient to claim that the entire cryptographic procedure has been performed.

## Attested

The release may be mutable, but the specific file requires a cryptographically verified attestation with the expected source repository ID, workflow identity, predicate, and digest. After acceptance, `(release_id,asset_id,sha)` must not be overwritten with a new digest: a detected replacement must be blocked. The first observation does not prove the absence of changes before it.

## Pinned (ADR-027)

No cryptographic provenance: only repository-ID pinning and digest freezing protect it. Allowed in 0.1 only after the administrator's explicit consent for that source, which names the risk (a compromised publisher account, token, or CI can publish a malicious release that Pakomichi cannot detect), and only with manual approval of every release. The approval binds to the exact digests of the approved artifacts; until it is given the release is held with `E_RELEASE_APPROVAL_REQUIRED`, and a changed asset after approval is `E_ASSET_MUTATED`. Consent and approval are administrative actions, never available through the status API, the loopback HTTP endpoint, or `--yes`. A Pinned source works only in `supplemental` mode and never displaces a distribution package. The Signed level and a time-based quarantine for Pinned are deferred to 0.2.

## Invariants and the ratchet (ADR-027)

Independent of the level and never relaxed: repository-ID pinning; immutability of accepted bytes; family and system-namespace protection (ADR-022); CAS verification before serving; signed local indexes; the system RPM signature policy; no re-signing of third-party packages; no disabling of global signature checks; no automatic `yes` for a risky transition.

The level of a source is a floor (`pinned` < `attested` < `strict`). It rises automatically when a release carries stronger verified evidence. A release with weaker evidence than the floor is held with `E_EVIDENCE_DOWNGRADE` until the user decides; the floor never drops silently. Each level is served from its own logical repository with a distinct APT `Label`/`Origin` and DNF repository ID and `name`, so that `apt policy` and `dnf repolist` show it without `pchi`.

## RPM

Repository metadata signing is **not** an embedded RPM signature. Two independent gates fail closed with separate diagnostics: the signed `repomd.xml` of our repository (`repo_gpgcheck=1`, the local key) and package trust (R-002, ADR-023).

- **Native mode:** the embedded RPM signature verifies against the publisher key pinned for the source, with package checking on for its repository. Importing a publisher key into the system RPM keyring needs explicit consent to its fingerprint and a warning that RPM accepts it for packages from every source.
- **Attested exception (waits for R-003):** an unsigned RPM is published only after the production attestation verifier verified it, bound to its exact SHA-256, with explicit consent for the source, and only when the effective `%_pkgverify_level` is neither `signature` nor `all`. It is served from a separate logical repository that contains only such packages, with package checking disabled for that Pakomichi repository only. Otherwise `E_SIGNATURE_POLICY`. An attestation never turns an RPM into a natively signed one.
- Pakomichi never writes a global `gpgcheck=0`, `pkg_gpgcheck=0`, `localpkg_gpgcheck` change, or `%_pkgverify_level` change.

## Untrusted local package-manager data

`/var/lib/apt/lists` and `/var/cache/apt/archives` are never trusted input, on any distribution (ADR-025): on Astra Linux with integrity control a level-0 process can write them. Pakomichi relies on APT's own signature and hash verification and on its CAS digests.

## Local signing

We create a restricted local key for signing *our* APT/RPM indexes. We do not use it to re-sign third-party DEB/RPM files. A centralized key is a centralized point of trust: access permissions, recovery, and rotation are mandatory; `localhost` is not sufficient protection. Publisher keys and the local metadata key are separate and never interchangeable. Rotation is two-phase: the new key is trusted first (overlap), metadata is then signed with it, and the old key is removed afterwards. Loss of the key never silently creates a new trust root; recovery uses an authenticated backup or an explicit re-trust by the administrator (ADR-023, N-023).

## Acceptable risk

A compromise of the publisher, its CI, or its keys is possible in any system. Pakomichi must provide blocking of specific versions/sources but does not promise an impossible one-hundred-percent prevention. A signature confirms provenance, not the usefulness of the program.

## Protection against transfers and forks

Repo rename events (same repo ID + owner) and owner transfer events (same repo ID, different owner) have different behavior. On a transfer/ID mismatch → suspension; never search all repos by owner. A Git project deleted and recreated at the same URL has a different repo ID → reject.

## Artifact substitution

If upstream content has disappeared, substituting a neighboring asset / new digest / fork is prohibited. Verify the byte stream before passing the package to the native package manager. Verify the cache contents against the hashes and references of the current snapshot.
