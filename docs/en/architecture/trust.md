# Trust and threat model

**English** · [Русский](../../ru/architecture/trust.md)

## What we trust

The user independently chooses a **specific** repository; we do not prove the publisher's honesty. Our goal is not to substitute the choice, not to accept bytes from another repo, and not to serve a corrupted artifact. We do not trust an arbitrary `owner/repo` string after an ownership change, an unsigned file name, `latest`, an RPM/DEB name, or HTTPS as evidence of the absence of malware.

## Strict

GitHub immutable release + cryptographically verified release attestation (with the required predicate type) + repository ID in the certificate/attestation + correspondence of release/assets + SHA-256 of the actual file. Verify the real fields/chain in R-003; the API `immutable=true` alone is insufficient to claim that the entire cryptographic procedure has been performed.

## Attested

The release may be mutable, but the specific file requires a cryptographically verified attestation with the expected source repository ID, workflow identity, predicate, and digest. After acceptance, `(release_id,asset_id,sha)` must not be overwritten with a new digest: a detected replacement must be blocked. The first observation does not prove the absence of changes before it.

## Verification (ADR-030)

Strict and Attested are checked by `src/attest` with `sigstore-verify` 0.15.0 and Pakomichi's own `ring` provider, which is installed at process start. Strict and Attested use separate trusted roots and are never merged. Bundles are checked before any cryptography: at most 256 KiB each and 16 per digest, bundle media type v0.3, DSSE with one signature over an in-toto statement. The statement is interpreted only after its signature has been verified.

- **Strict** needs an immutable release and a release attestation from GitHub's authority: the SAN `https://dotcom.releases.github.com` and a verified RFC 3161 time, without a transparency log. Its predicate must name the pinned repository ID as `repositoryId` and `packageId`, a confirmed owner ID, this release's ID and tag, the object SHA of the tag reference as GitHub returns it (the commit for a lightweight tag, the tag object for an annotated one, never peeled), and the asset's name with its digest.
- **Attested** needs an SLSA provenance from public-good Sigstore with a verified SCT and transparency-log inclusion. Its Fulcio claims must carry the pinned repository and owner IDs, the pinned workflow of the repository itself (exact path, no prefix or pattern), the expected ref and the commit the release tag points to, and a GitHub-hosted runner.

Names never bind: a rename with unchanged IDs verifies, a new repository under an old name or a fork does not. After a confirmed transfer the earlier owner IDs stay accepted for attestations made before it. A failed check is `E_ATTESTATION_INVALID` with one sub-reason of ADR-030 point 7, carried as `subcode` in a version 2 reason event (ADR-031); missing evidence (no bundle, no release attestation, not immutable, no provenance) is `E_EVIDENCE_DOWNGRADE`.

The trusted roots come from TUF (ADR-030 point 8): each instance starts from a TUF root shipped with Pakomichi and pinned by SHA-256 (GitHub version 9, public-good version 15), walks the root chain, and verifies timestamp, snapshot, targets and `trusted_root.json` with `sigstore-tuf`. Only `tuf-repo.github.com` and `tuf-repo-cdn.sigstore.dev` are contacted, through the API client's rules: one resolution per request, every address must be public, TLS against the system CA store, no redirects, bounded sizes. Verified metadata is cached. When a repository cannot be reached, the cache is verified again from the pinned root and used only while it has not expired; expired metadata stops verification with a reason that names the instance. A verification failure of network data (a signature, a rollback, a target hash) is never replaced by the cache.

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
