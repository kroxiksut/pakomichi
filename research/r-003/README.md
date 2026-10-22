<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# R-003 research harness (read-only part)

This directory implements the parts of `docs/en/research/R-003-github-provenance.md`
that need no repository of our own: the external read-only check of
`matthart1983/netwatch` release `v0.35.4` and the negative cases that can be
produced locally from its published attestations. It is research tooling, not
production Pakomichi code, and it does not choose the production verifier.

GitHub CLI is used as the reference oracle (ADR-017 point 9). It is not a
runtime dependency.

## Rules

- Only anonymous, read-only GitHub requests. No token is read or sent; the
  scripts refuse to run when `GH_TOKEN`, `GITHUB_TOKEN`, or an enterprise token
  is set. The collection stage spends at most 20 counted API requests and stops
  when fewer than 12 anonymous requests remain.
- Nothing is created, forked, starred, commented on, or modified on GitHub.
- Downloaded packages are only hashed; they are never installed, unpacked, or
  executed.
- Raw API responses, downloads, bundles, the trusted root, and full verifier
  output stay in the ignored `.research-local/r-003/`. Only sanitized TSV
  files are kept in `results/`.

## Files

| File | Purpose |
| --- | --- |
| `wsl-import.ps1` | Imports (or with `-Remove` removes) a `pakomichi-r003-*` WSL distribution from the digest-pinned R-001 `fedora44` layer; refuses other names. |
| `bootstrap.sh` | Root, inside the distribution: base packages, the unprivileged `r003` user, GitHub CLI 2.95.0 pinned by SHA-256 (the same pin P0-004 verified against its `cli/cli` attestation). |
| `run.sh` | Root, inside the distribution: runs `r003.py` as `r003`, writes `results/*.tsv`, copies raw data to `.research-local/r-003/run-<UTC>/`. |
| `r003.py` | `collect`: anonymous API metadata, asset downloads, attestation bundles. `checks`: oracle cases, independent certificate/statement parsing, reconciliation by repository ID, owner ID, digest, ref, and commit. |
| `owner-repo/` | Templates for the owner's test repository (not used by this run). |

## Rerun

From Windows PowerShell 5.1 on the development host (check first that no heavy
WSL job of another project is running):

```powershell
powershell -NoProfile -File research/r-003/wsl-import.ps1 -Name pakomichi-r003-oracle
wsl.exe -d pakomichi-r003-oracle -u root --cd /tmp -- bash /mnt/d/Projects/pakomichi/research/r-003/bootstrap.sh
wsl.exe -d pakomichi-r003-oracle -u root --cd /tmp -- bash /mnt/d/Projects/pakomichi/research/r-003/run.sh all
# offline rerun of the oracle cases on the last collection, no API requests:
wsl.exe -d pakomichi-r003-oracle -u root --cd /tmp -- bash /mnt/d/Projects/pakomichi/research/r-003/run.sh checks
powershell -NoProfile -File research/r-003/wsl-import.ps1 -Name pakomichi-r003-oracle -Remove
```

## Results of the read-only run (2026-10-20)

Environment: `pakomichi-r003-oracle` from `library/fedora:44` (R-001 lock),
GitHub CLI 2.95.0 (SHA-256 `25d1e472…3d8c`), Python 3.14.8, no GitHub
authentication. 14 counted anonymous API requests (`results/api-requests.tsv`).
Raw data: `.research-local/r-003/run-20261020T104417Z/` (`$WORK` in the TSV
commands).

| File | Content |
| --- | --- |
| `results/release.tsv` | Repository ID, owner ID, release ID, `immutable`, tag object, tag commit, release-commit attestation lookup. |
| `results/assets.tsv` | Asset ID, API digest, downloaded SHA-256, attestation lookup status and repository IDs. |
| `results/attestations.tsv` | Independent parse of each bundle: predicate, subjects, Fulcio certificate extensions, release predicate IDs. |
| `results/checks.tsv` | 40 oracle cases: command, expectation, exit code, outcome, whether authentication was required. |
| `results/reconcile.tsv` | Oracle JSON matched against API facts by repository ID, owner ID, SHA-256, ref, commit, runner, issuer. |
| `results/environment.tsv` | Tool versions and DNS resolution inside the distribution. |

### External subject: `matthart1983/netwatch` v0.35.4

- Repository ID `1158138526`, owner ID `13101478`, release ID `415484031`,
  `immutable: false`; annotated tag resolves to commit `9c249f57…229b`.
- Four package assets (two `.deb`, two `.rpm`). Every downloaded SHA-256
  equals the API `digest`.
- Each asset digest returns the same single SLSA v1 provenance attestation
  (one DSSE statement with 10 subjects), signed by
  `matthart1983/netwatch/.github/workflows/release.yml@refs/tags/v0.35.4` on a
  GitHub-hosted runner. The certificate's `sourceRepositoryIdentifier` and
  owner identifier equal the API IDs; source ref and commit equal the tag.
- No release attestation: the tag-commit lookup returns 404, consistent with
  `immutable: false`. This release can qualify for Attested, not Strict.
- All 8 positive verifications (`--repo` only, and fully pinned signer
  workflow, ref, commit, issuer, predicate, hosted runner) passed offline;
  verification also passed inside a network namespace without network.

### Strict reference: `cli/cli` v2.95.0

Used because netwatch has no release attestation. `immutable: true`; the
release attestation (`https://in-toto.io/attestation/release/v0.2`) lists the
tag commit (`sha1`) and 22 asset digests, and its predicate carries
`repositoryId 212613049`, `ownerId 59704711`, `databaseId 341013769` (equal to
the API release ID), and the tag. It is signed with SAN
`https://dotcom.releases.github.com` by a GitHub-operated CA, with an RFC 3161
timestamp and no Rekor entry. The asset's separate SLSA provenance verified
offline with a pinned signer workflow.

### Negative cases (all failed as required, offline, no authentication)

One flipped asset byte; fork-like repository name; same name under another
owner; another `--owner`; wrong signer workflow; signer repository from
another repository; exact certificate identity with another ref; wrong OIDC
issuer; wrong source ref; wrong source commit; release predicate required for
the mutable release; artifact whose digest is not a release asset digest;
empty bundle (missing provenance); DSSE payload rewritten to the changed
digest; trusted root without certificate authorities; the same flipped-byte
and fork-name cases for the `cli/cli` asset.

### Findings for the R-003 decision

1. **Name binding only.** `gh attestation verify` has no repository-ID option;
   `--repo` matches the certificate URI by name and is case-insensitive
   (`O-name-case` passed with an upper-case name). Repository-ID and owner-ID
   binding must be done by Pakomichi from the verified certificate
   (`sourceRepositoryIdentifier`, `sourceRepositoryOwnerIdentifier`), as
   `reconcile.tsv` does (protocol step 7).
2. **Release attestations have no offline oracle path in gh 2.95.0.**
   `gh attestation verify` rejects them under the default policy (`S-release-default-policy`)
   and, with `--cert-identity https://dotcom.releases.github.com`, fails its
   own policy because the certificate has no `SourceRepositoryOwnerURI`
   (`S-release-cert-identity`). `gh release verify` and `verify-asset` have no
   `--bundle` option and are online-only. Strict verification therefore needs
   the authenticated oracle now and an independent verifier later.
3. **Authentication.** Every online gh command (`attestation verify` without
   `--bundle`, `release verify`, `release verify-asset`) exits 4 without a
   token before any request. Anonymous REST calls (repository, release, tag,
   attestations by digest) and `gh attestation trusted-root` (TUF) work
   without authentication, so offline verification of fetched bundles needs no
   token.
4. **Error detail.** gh reports signature, digest, and identity failures alike
   as `verifying with issuer "sigstore.dev"`; only some policy failures name
   the field. A production verifier must return typed reasons.
5. **Network.** Inside WSL, `release-assets.githubusercontent.com` resolved
   into `198.18.0.0/15` (as in R-005); `api.github.com` and the Sigstore TUF
   CDN resolved to public addresses. All downloads matched the API digests.

## Protocol status

| Step | Status |
| --- | --- |
| 1. Immutable release + release attestation | External read-only evidence only (`cli/cli`); predicate IDs reconciled offline; cryptographic check by `gh release verify*` needs authentication and was **not run**. Own repository required. |
| 2. Mutable release + build provenance | Done read-only on netwatch (signature, repo ID, workflow, ref, commit, SHA-256). Controlled repetition in the own repository remains. |
| 3. Asset replacement | Open: own repository. |
| 4. Rename / transfer | Open: own repository and a second owner. |
| 5. Foreign repository / fork | Name-substitution negatives done; a real fork with a higher version remains. |
| 6. Missing provenance, predicate, signer workflow, untrusted root, missing digest, no network | Done offline. |
| 7. Name vs repository ID | Done: gh binds by name only; ID reconciliation is required. |

## Plan for the owner's test repository (not executed)

Nothing below has been created or run. It needs the owner's decision and
GitHub accounts.

### Prerequisites

- A **public** test repository, e.g. `<owner>/pakomichi-r003-fixture`
  (artifact attestations in private repositories require GitHub Enterprise
  Cloud). A second account or organization owned by the owner for the
  transfer and fork steps.
- Copy `owner-repo/build-fixture.sh` to `scripts/` and the two workflow
  templates to `.github/workflows/`; replace every `<PIN: …>` with a reviewed
  full commit SHA. The fixture `.deb` has no maintainer scripts.
- For the online oracle commands, a fine-grained read-only token stored in
  `.research-local/r-003/secrets/github-token` (mode 0600) inside the research
  distribution and exported by a script from that file. Never on a command
  line or in a URL.

### Steps

1. **Strict.** Enable release immutability in the repository settings, run
   `r003-immutable-release` with version `0.1.0`. Then, in the research
   distribution: record the release with the anonymous API (`immutable`,
   release ID, asset ID, digest); `gh release verify v0.1.0 -R <repo> --format json`;
   `gh release verify-asset v0.1.0 <asset> -R <repo> --format json`; fetch the
   release attestation by `sha1:<tag commit>` and reconcile `repositoryId`,
   `ownerId`, `databaseId`, tag, commit, and asset digest. Negative: changed
   byte with `verify-asset`; try `gh release upload --clobber` on the immutable
   release and record the refusal.
2. **Attested.** Disable immutability, run `r003-mutable-attested` with
   `0.2.0`; repeat this harness's offline cases against the new asset with
   `--signer-workflow <owner>/pakomichi-r003-fixture/.github/workflows/mutable-attested.yml`
   and reconcile the repository ID.
3. **Replacement.** On the mutable `v0.2.0-mutable` release, replace the
   asset with a rebuilt one (`gh release delete-asset`, then `gh release upload`).
   Record the new asset ID and digest; the stored `(release ID, asset ID, SHA)`
   from step 2 must not be overwritten, and the replaced asset must have no
   attestation unless re-attested.
4. **Rename / transfer.** Rename the repository; record that the repository ID
   is unchanged, and run offline `gh attestation verify` on the step 2 bundle
   with the old and the new name (the certificate keeps the old URI). Create
   a new repository under the old name and record that its ID differs. Then
   transfer the repository to the second owner; the owner ID changes and the
   source must be suspended.
5. **Fork.** From the second account, fork the fixture, run the mutable
   workflow with a higher version (`0.3.0`) and the same asset name, and check
   that verification against the original repository and its ID rejects it.

Results go to `research/r-003/results/owner-*.tsv`, raw output to
`.research-local/r-003/`. The final R-003 report in `docs/` is written after
these steps.
