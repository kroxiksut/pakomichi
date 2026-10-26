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
| `bootstrap.sh` | Root, inside the distribution: base packages, the unprivileged `r003` user, GitHub CLI pinned by SHA-256, with the installed tarball's digest in `/opt/r003-gh/TARBALL-SHA256`. 2.103.0 since 2026-10-22; every run recorded below, before that date, used 2.95.0, the pin P0-004 verified against its `cli/cli` attestation. |
| `verify-gh-pin.sh` | Root, inside a bootstrapped distribution, anonymous: verifies a new `gh` tarball with the installed `gh` before it becomes the pin. Checks the API digest, `checksums.txt`, and the offline SLSA provenance, then compares the certificate exactly and case-sensitively, because `gh` ≤ 2.101.0 matches `--signer-workflow` as a prefix and `--source-ref` case-insensitively: repository and owner IDs, `deployment.yml@refs/heads/trunk`, the tag commit as the source digest, a GitHub-hosted runner. A changed byte must fail. It also records the release attestation's predicate. Output: `results/gh-pin-verify-<version>.tsv`. |
| `run.sh` | Root, inside the distribution: runs `r003.py` as `r003`, writes `results/*.tsv`, copies raw data to `.research-local/r-003/run-<UTC>/`. |
| `r003.py` | `collect`: anonymous API metadata, asset downloads, attestation bundles. `checks`: oracle cases, independent certificate/statement parsing, reconciliation by repository ID, owner ID, digest, ref, and commit. |
| `owner-repo/` | Templates for the owner's test repository (not used by this run). |
| `owner.py` | Owner-repository steps on `kroxiksut/pchi-test`. `step1`: anonymous collection through `r003.py`, offline and online oracle cases, release-predicate reconciliation, token-leak scan. `step2`: the mutable release, the full offline negative set of `r003.py`, and the step 1 release recorded again. `step3`: the replaced asset compared with the recorded step 2 run. `step4 --phase rename\|reuse\|transfer`: the same name, ID, and verification cases after each repository operation. `step5`: the fork release checked against the fork and the original. |
| `run-owner.sh` | Root, inside the distribution: hands `r003` the read-only token as a 0600 file (removed on exit), runs `owner.py`, writes `results/owner-*.tsv`, copies raw data to `.research-local/r-003/owner-<step>-<UTC>/`. |

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
| 1. Immutable release + release attestation | Done on the own repository `kroxiksut/pchi-test` (2026-10-22): `gh release verify*` with a read-only token, release predicate and build provenance reconciled by repository, owner, and release IDs; clobber refused. See "Owner repository: step 1". |
| 2. Mutable release + build provenance | Done read-only on netwatch and repeated on the own repository (2026-10-22): signature, repository and owner IDs, signer workflow, ref, commit, SHA-256; release lookup by commit is ambiguous. See "Owner repository: step 2". |
| 3. Asset replacement | Done on the own repository (2026-10-22): same release ID and name, new asset ID and digest, no attestation for the replacement; the removed asset's attestation still verifies online. See "Owner repository: step 3". |
| 4. Rename / transfer | Done on the own repository and `pchi-test-org` (2026-10-22): rename, reuse of the old name by a new repository, transfer. Names are not identity; after the transfer the attestations stay with the previous owner. See "Owner repository: step 4". |
| 5. Foreign repository / fork | Done (2026-10-22): a real fork released `0.3.0` with the same asset name and a valid attestation of its own; rejected against the original only by name or repository ID, not by owner ID. See "Owner repository: step 5". |
| 6. Missing provenance, predicate, signer workflow, untrusted root, missing digest, no network | Done offline. |
| 7. Name vs repository ID | Done: gh binds by name only; ID reconciliation is required. |

## Owner repository: step 1 (2026-10-22)

Setup: public repository `kroxiksut/pchi-test` (repository ID `1429109739`,
owner ID `2264172`), commit `6ee0f9f5…` with `owner-repo/` copied in and
pinned to `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1`
(v7.0.1) and `actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8`
(v4.2.2). Second owner for steps 4–5: organization `pchi-test-org` (owner ID
`346117935`). Release immutability enabled by the owner, then
`r003-immutable-release` run `39725497640` with version `0.1.0` on
`refs/heads/main`.

```powershell
powershell -NoProfile -File research/r-003/wsl-import.ps1 -Name pakomichi-r003-oracle
wsl.exe -d pakomichi-r003-oracle -u root --cd /tmp -- bash /mnt/d/Projects/pakomichi/research/r-003/bootstrap.sh
wsl.exe -d pakomichi-r003-oracle -u root --cd /tmp -- bash /mnt/d/Projects/pakomichi/research/r-003/run-owner.sh step1
```

Raw data: `.research-local/r-003/owner-step1-20261022T050816Z/`. 5 counted
anonymous API requests; 16 cases, none unexpected, no reconciliation
mismatch, token found in no file.

| File | Content |
| --- | --- |
| `results/owner-step1-release.tsv` | Release `420324447`, `immutable=True`, tag `v0.1.0` → commit `6ee0f9f5…` (lightweight tag), release attestation by `sha1:` commit found. |
| `results/owner-step1-assets.tsv` | Asset `664728438`, 772 bytes, API digest equals the downloaded SHA-256 `8fcda58d…`; two bundles, all from repository ID `1429109739`. |
| `results/owner-step1-attestations.tsv` | Release attestation (`release/v0.2`, SAN `https://dotcom.releases.github.com`, one RFC 3161 timestamp, no tlog entry): `repositoryId`, `ownerId`, `databaseId`, `tag`, asset digest, and commit match the API. Build provenance (`slsa/v1`): signer `immutable-release.yml@refs/heads/main`, repository and owner IDs, commit, `github-hosted`, `workflow_dispatch`. |
| `results/owner-step1-checks.tsv` | Oracle cases (below). |
| `results/owner-step1-reconcile.tsv` | Build provenance from the offline strict case and the online lookup, all fields matched. |
| `results/owner-step1-release-verify.tsv` | Statements from `gh release verify` and `verify-asset` reconciled with the API: all matched. |
| `results/owner-step1-write-negatives.tsv` | `gh release upload --clobber` with the owner's write login: `HTTP 422 Cannot delete asset from an immutable release`; asset ID and digest unchanged. |

Observations:

1. `gh release verify` and `verify-asset` need authentication even for a
   public repository (`O1-release-verify-anonymous`: exit 4). A fine-grained
   token with public read access and no permissions is enough.
2. `verify-asset` with one flipped byte fails (`attestation for v0.1.0 does
   not contain subject …`); `release verify` against the same name under the
   test organization fails (`release not found`).
3. Offline `gh attestation verify` still cannot check the release
   attestation: the default policy expects a workflow identity, and with
   `--cert-identity https://dotcom.releases.github.com` it requires a
   `SourceRepositoryOwnerURI` the certificate does not have (as with
   `cli/cli`). Strict therefore relies on `gh release verify*` or on a
   verifier with its own release-signer policy (P1-003c).
4. Build provenance binds the dispatching branch, not the release tag:
   `--source-ref refs/tags/v0.1.0` fails, `refs/heads/main` passes. A policy
   that pins the source ref must use the ref of the run.
5. Build provenance with the repository's other workflow
   (`mutable-attested.yml`) as signer and with the organization as owner is
   rejected offline.

## Owner repository: step 2 (2026-10-22)

Setup: the owner disabled release immutability and ran `r003-mutable-attested`
(run `39728227321`) with version `0.2.0` on `refs/heads/main`, commit
`6ee0f9f5…` (the same commit as step 1).

```powershell
wsl.exe -d pakomichi-r003-oracle -u root --cd /tmp -- bash /mnt/d/Projects/pakomichi/research/r-003/run-owner.sh step2
```

Raw data: `.research-local/r-003/owner-step2-20261022T053242Z/` (an earlier
run, `…053128Z`, differs only in `A2-attestation-online-netns`, which then ran
without the token and failed on authentication). 10 counted anonymous API
requests; 26 cases, none unexpected, no reconciliation mismatch, token found
in no file.

| File | Content |
| --- | --- |
| `results/owner-step2-release.tsv` | Release `420339762` `v0.2.0-mutable`, `immutable=False`, lightweight tag → `6ee0f9f5…`. Step 1 release `420324447` recorded again: still `immutable=True` with the same asset digest. The immutability setting is not readable anonymously (HTTP 401). |
| `results/owner-step2-assets.tsv` | Asset `664783235`, API digest equals the downloaded SHA-256 `93b4dc42…`; one bundle from repository ID `1429109739`. This `(release ID, asset ID, SHA-256)` triple is the step 3 baseline. |
| `results/owner-step2-attestations.tsv` | Build provenance: signer `mutable-attested.yml@refs/heads/main`, repository and owner IDs, commit, `github-hosted`. No release attestation for the asset. |
| `results/owner-step2-checks.tsv` | Oracle cases. |
| `results/owner-step2-reconcile.tsv` | Offline strict and online lookup, all fields matched. |

Observations:

1. Every offline negative of the read-only run is rejected on the own
   repository too: changed byte, fork-like name, the organization as owner or
   repository, the other workflow of the same repository, signer repository,
   certificate identity with another ref, issuer, source ref, source commit,
   release predicate, foreign digest, empty bundle, forged DSSE payload,
   trusted root without Fulcio CAs.
2. **Release lookup by commit is ambiguous.** `attestations/sha1:<tag commit>`
   for `v0.2.0-mutable` returns the release attestation of `v0.1.0`, because
   both tags point to the same commit (`match_release_id=NO`,
   `match_release_tag=NO`). Finding a release attestation for the tag commit
   does not make a release Strict: the predicate's `databaseId` and `tag` must
   equal the release being checked. `gh release verify` gets this right
   (`AN2-release-verify`: no attestations for `v0.2.0-mutable`).
3. Disabling immutability does not affect a release published while it was
   enabled: `v0.1.0` keeps `immutable=True` and still passes
   `gh release verify` (`A2-previous-release-verify`).
4. The `v0.2.0` asset checked against the `v0.1.0` release attestation fails
   (`AN2-verify-asset-cross-release`).
5. Online verification with a token but without network fails while building
   the Sigstore verifier (`A2-attestation-online-netns`); with a bundle and a
   trusted root it passes offline (`P2-offline-netns`).

## Owner repository: step 3 (2026-10-22)

Setup: the owner committed `owner-repo/replace-asset.yml` (pinned like the
other workflows) and the variant argument of `build-fixture.sh` as commit
`31c0b80f…`, then ran `r003-replace-asset` (run `39729393695`) with
`tag=v0.2.0-mutable`, `version=0.2.0`, `variant=replaced-1`. The job has only
`contents: write`, so it cannot attest. The variant was first built locally in
the DEB builder (`a59a5cfd…`, see Prerequisites).

```powershell
wsl.exe -d pakomichi-r003-oracle -u root --cd /tmp -- bash /mnt/d/Projects/pakomichi/research/r-003/run-owner.sh step3
```

Baseline: the recorded step 2 run (`R003_STEP2_RUN`, default
`owner-step2-20261022T053242Z`), whose asset file is re-hashed first. Raw data:
`.research-local/r-003/owner-step3-20261022T054617Z/`. 7 counted anonymous API
requests; 7 cases, none unexpected, token found in no file.

| File | Content |
| --- | --- |
| `results/owner-step3-replacement.tsv` | Step 2 against step 3: release ID `420339762`, `immutable=False`, tag commit, and asset name unchanged; asset ID `664783235` → `664806807`; SHA-256 `93b4dc42…` → `a59a5cfd…`, equal to the local rebuild; no attestation for the new digest; the old asset ID returns HTTP 404; the old digest still has its attestation (HTTP 200, one bundle). Uploader `github-actions[bot]`, as for the original. |
| `results/owner-step3-assets.tsv` | The replacement asset; API digest equals the download. |
| `results/owner-step3-checks.tsv` | Oracle cases. |

Observations:

1. A mutable release keeps its release ID, tag, tag commit, and asset name
   when the asset is replaced. Only the asset ID and the digest change, so a
   pin must hold `(release ID, asset ID, SHA-256)`; a name or a release ID
   alone does not detect the replacement.
2. The replacement has no attestation: online lookup returns HTTP 404
   (`AN3-new-online`), and the step 2 bundle rejects it offline
   (`N3-new-with-old-bundle`).
3. **An attestation outlives its asset.** The removed step 2 file still
   verifies online by digest (`O3-old-online`, signer
   `mutable-attested.yml`, repository ID `1429109739`) and offline with its
   bundle (`P3-old-with-old-bundle`). A valid attestation therefore does not
   prove that the file is a current asset of the release: Attested must also
   require that the digest equals the API digest of the current asset.
4. The uploader does not distinguish the replacement (both
   `github-actions[bot]`), and the replacement came from a later commit
   (`31c0b80f…`) while the tag still points to `6ee0f9f5…`.
5. A deterministic rebuild in the DEB builder predicted the CI digest of the
   replacement exactly.

## Owner repository: step 4 (2026-10-22)

With the owner's permission the agent ran the three operations with the
owner's `gh` login and checked after each one, reusing the step 1 asset and
its build provenance (`R003_STEP1_RUN`, re-hashed first):

1. `gh repo rename pchi-test-renamed -R kroxiksut/pchi-test --yes`
2. `gh repo create kroxiksut/pchi-test --public` (new, empty, ID `1429307950`)
3. `gh api -X POST repos/kroxiksut/pchi-test-renamed/transfer -f new_owner=pchi-test-org`

```powershell
wsl.exe -d pakomichi-r003-oracle -u root --cd /tmp -- bash /mnt/d/Projects/pakomichi/research/r-003/run-owner.sh step4 rename
wsl.exe -d pakomichi-r003-oracle -u root --cd /tmp -- bash /mnt/d/Projects/pakomichi/research/r-003/run-owner.sh step4 reuse
wsl.exe -d pakomichi-r003-oracle -u root --cd /tmp -- env R003_EXTRA_NAME=kroxiksut/pchi-test-renamed bash /mnt/d/Projects/pakomichi/research/r-003/run-owner.sh step4 transfer
```

Raw data: `.research-local/r-003/owner-step4-{rename-20261022T055547Z,reuse-20261022T055701Z,transfer-20261022T060838Z}/`.
All cases are observations; none unexpected, token found in no file.

| Phase | `kroxiksut/pchi-test` resolves to | Repository `1429109739` | Offline `--repo` old name | Offline `--repo` current name | Online lookup, current name | `gh release verify v0.1.0`, current name |
| --- | --- | --- | --- | --- | --- | --- |
| rename | `1429109739` (redirect) | `kroxiksut/pchi-test-renamed`, owner `2264172` | pass | fail | fail (certificate URI) | pass |
| reuse | `1429307950` (new repository, no redirect) | unchanged | **pass** | fail | fail | pass |
| transfer | `1429307950` | `pchi-test-org/pchi-test-renamed`, owner `346117935` | **pass** | fail | fail (HTTP 404) | **fail** (no attestations) |

Files: `results/owner-step4-<phase>-{names,checks,api-requests,environment}.tsv`;
`results/owner-step4-transfer-attestation-lookup.tsv` (read-only lookups with
the owner's login after the transfer).

Observations:

1. **Rename keeps the repository ID and breaks name binding.** The
   certificate keeps the old URI, so `--repo <new name>` fails offline and
   online, while the old name passes. `gh release verify` follows the
   repository and passes under both names.
2. **Reuse of the old name.** After a new repository takes the old name, the
   old artifacts still pass offline with `--repo kroxiksut/pchi-test`, a name
   that now belongs to another repository (ID `1429307950`). Only the
   repository ID tells them apart; a stored source must be resolved through
   `/repositories/{id}`, never through its name.
3. **Transfer keeps the repository ID and changes the owner ID**
   (`2264172` → `346117935`); the old name and the intermediate name redirect.
   The certificates still carry owner ID `2264172`, so the owner check fails:
   the source must be suspended for an owner decision, as planned.
4. **Attestations do not follow a transfer.** Right after the transfer,
   `attestations/…` returns HTTP 404 for the repository (by name and by ID)
   and for the organization, while `users/kroxiksut/attestations/…` still
   returns both bundles with repository ID `1429109739`. `gh release verify`
   for the immutable `v0.1.0` fails, although the release stays
   `immutable=True`. Online verification of releases published before a
   transfer is therefore not available; stored bundles still verify offline.
   Unchanged at read-only rechecks about 40 minutes, 4 hours and 19 hours
   after the transfer (2026-10-23, `gh` 2.103.0, raw data
   `.research-local/r-003/recheck2-20261023T005002Z/`), so it is treated as
   lasting behaviour; whether a transfer back restores the lookups is not
   tested.
5. **A transfer back is refused while the original owner has a fork.**
   `POST repos/pchi-test-org/pchi-test-renamed/transfer` with
   `new_owner=kroxiksut` (2026-10-23, owner's login, org admin) returned
   HTTP 422 `kroxiksut already has a repository in the
   pchi-test-org/pchi-test-renamed network`: the step 5 fork
   `kroxiksut/pchi-test-fork` is in the same fork network. The phase
   `run-owner.sh step4 transfer-back` exists but has not run.
6. **Re-attesting after the transfer does not restore the old provenance**
   (2026-10-25, after a community answer in GitHub discussion 211055
   suggested it). Three days after the transfer the lookups were unchanged
   (repository ID and organization 404, `users/kroxiksut` two attestations
   of `1429109739`). A workflow `.github/workflows/reattest.yml` added to
   `pchi-test-org/pchi-test-renamed` (commit `e2e658d1…`) downloaded the
   `v0.1.0` asset and ran `actions/attest-build-provenance` v4.2.2 over it
   (run `40195307476`). Afterwards `repositories/1429109739/attestations/…`
   and `orgs/pchi-test-org/attestations/…` return one attestation, the new
   one; the user endpoint still returns the two old ones. The new
   provenance names the workflow `reattest.yml@refs/heads/main`, the commit
   `e2e658d1…`, and the organization's owner ID `346117935` — not the
   confirmed signer workflow and not the commit `6ee0f9f5…` the `v0.1.0`
   tag points to. Dispatching the workflow at the tag is refused (HTTP 422
   "Workflow does not have 'workflow_dispatch' trigger", because the file
   does not exist at that commit). Under ADR-030/ADR-036 such a provenance
   is `workflow_mismatch` and a commit mismatch for the old release: it
   shows that a workflow of the repository saw the bytes later, not what
   they were built from. The lookup order of ADR-034 point 2 (earlier
   owners) and the stored bundles stay the way to keep old releases.
7. **A transfer back to the original owner makes the old attestations
   reachable again** (2026-10-25, after the owner deleted the fork). `POST
   repos/pchi-test-org/pchi-test-renamed/transfer -f new_owner=kroxiksut`
   succeeded; the repository is `kroxiksut/pchi-test-renamed` again, owner
   ID `2264172`. Right afterwards `repositories/1429109739/attestations/…`
   returns the two original attestations again, while the re-attestation of
   observation 6, made while the organization owned the repository, is no
   longer listed there and only `orgs/pchi-test-org/attestations/…` returns
   it. `run-owner.sh step4 transfer-back` (12 cases, none unexpected, token
   in no file; `results/owner-step4-transfer-back-*.tsv`, raw data
   `.research-local/r-003/owner-step4-transfer-back-20261025T142106Z/`):
   `gh release verify v0.1.0` passes again under the current name and
   through the organization's old name (redirect); `gh attestation verify
   --repo` passes offline with the original name `kroxiksut/pchi-test` and
   fails with the current name, because the certificate names the
   repository as it was at signing time. Attestations stay with the account
   that owned the repository when they were made, and every lookup is
   scoped to the current owner; verification has to bind the repository
   and owner IDs, never the current name.

### Name capture (2026-10-23)

The owner committed `.gitattributes`, `mutable-attested.yml` and
`build-fixture.sh` (pins as in the original) to the new `kroxiksut/pchi-test`
(ID `1429307950`, the repository that took the old name, commit `a12bcac0…`)
and ran `r003-mutable-attested` with `0.3.0` (run `39881198690`). The release
`v0.3.0-mutable` (ID `421346102`) has the asset
`pakomichi-r003-fixture_0.3.0_all.deb` (asset `667564280`, `d3c6baed…`) with
its own build provenance. The phase checks it against the pin of the
original: repository `1429109739`, owner `2264172`.

```powershell
wsl.exe -d pakomichi-r003-oracle -u root --cd /tmp -- bash /mnt/d/Projects/pakomichi/research/r-003/run-owner.sh step4 capture
```

Raw data: `.research-local/r-003/owner-step4-capture-20261023T010251Z/`.
7 cases, none unexpected, token found in no file. Files:
`results/owner-step4-capture-{release,assets,attestations,checks,reconcile,reconcile-vs-pin,api-requests,environment}.tsv`.

1. **A source pinned by name accepts another repository's release.**
   `--repo kroxiksut/pchi-test` passes offline and online, and so do the
   original's signer workflow path
   `kroxiksut/pchi-test/.github/workflows/mutable-attested.yml` and
   `--owner kroxiksut`. Against the holder's own IDs every field matches: the
   attestation is genuine, only it belongs to another repository.
2. **Only the repository ID rejects it.** Against the pin the owner ID,
   digest, ref, commit, hosted runner and issuer all match; only the
   repository ID differs (`1429307950` ≠ `1429109739`,
   `owner-step4-capture-reconcile-vs-pin.tsv`). With the original's current
   name the asset fails.
3. **The same bytes are attested by two repositories.** The fixture build is
   reproducible, so the digest equals the fork's `v0.3.0-mutable` asset from
   step 5. A digest alone does not identify the source either.

## Owner repository: step 5 (2026-10-22)

The agent forked `pchi-test-org/pchi-test-renamed` into
`kroxiksut/pchi-test-fork` (ID `1429309242`, `fork=true`, parent and source
`1429109739`), the owner enabled workflows in the fork in the web UI, and the
agent ran `r003-mutable-attested` there (run `39731324869`) with `0.3.0` on
the unchanged commit `31c0b80f…`. The fork published `v0.3.0-mutable` with
asset `pakomichi-r003-fixture_0.3.0_all.deb` (`d3c6baed…`), a higher version
under the same asset name, attested by the fork's own workflow run.

```powershell
wsl.exe -d pakomichi-r003-oracle -u root --cd /tmp -- bash /mnt/d/Projects/pakomichi/research/r-003/run-owner.sh step5
```

Raw data: `.research-local/r-003/owner-step5-20261022T060919Z/`. 10 cases,
none unexpected, token found in no file.

| File | Content |
| --- | --- |
| `results/owner-step5-release.tsv` | Fork and original IDs, fork release `420357583`, tag commit. |
| `results/owner-step5-assets.tsv`, `results/owner-step5-attestations.tsv` | Fork asset and its build provenance: repository ID `1429309242`, owner ID `2264172`, signer `kroxiksut/pchi-test-fork/.github/workflows/mutable-attested.yml`. |
| `results/owner-step5-checks.tsv` | Oracle cases. |
| `results/owner-step5-reconcile-vs-original.tsv` | The fork's verified result reconciled against the original: digest, ref, commit, runner, and issuer match; repository ID and owner ID do not (`all_match=NO`, as intended). |

Observations:

1. The fork's attestation is valid for the fork (`P5-fork-own-repo`), and is
   rejected against the original by its current name, its old name, its
   signer workflow, and its organization owner.
2. **Owner ID alone does not reject the fork.** The fork lives under the
   account that created the original, so its owner ID `2264172` equals the
   owner ID in the original's step 1–3 certificates, and `--owner kroxiksut`
   accepts the fork asset (`O5-fork-owner-only`). Only the repository ID
   (`1429309242` against `1429109739`) separates them.
3. Same commit, same workflow file name, same asset name, higher version:
   nothing in the release or the file name distinguishes the fork's package.
4. The online check against the original fails here with HTTP 404 because of
   step 4 observation 4, not because of the fork; the offline cases carry the
   evidence.

## Annotated tag reference (2026-10-22)

Every Strict case above uses a lightweight tag, so its tag reference is the
commit. An annotated tag was checked read-only, with anonymous API requests
and no harness run, on the public immutable release
`github/github-mcp-server` v2.0.2.

| File | Content |
| --- | --- |
| `results/annotated-tag-reference.tsv` | Repository ID `942771284`, owner ID `9919`, release `406753657` (`immutable=True`). `git/ref/tags/v2.0.2` gives an object of type `tag`, `503622d1…`, which peels to commit `eb47a99d…`. The release attestation's only `sha1` subject is the tag object, and the peeled commit is not a subject. A lookup by the tag object returns 1 attestation, a lookup by the peeled commit returns HTTP 404. The predicate IDs equal the API, and the asset `github-mcp-server_Linux_x86_64.tar.gz` is a subject with its API digest. |

Raw responses are in `.research-local/r-003/annotated-tag/`. The finding: the
expected `sha1` subject is the tag reference object as returned, never peeled.

## Oracle update to gh 2.103.0 (2026-10-22)

The runs above used `gh` 2.95.0. That version has three published flaws in
`attestation verify` matching, and each one makes a match looser:

- an unescaped regular expression for `--signer-repo` and `--signer-workflow`
  (GHSA-mm27-mwq9-fr5g, fixed in 2.97.0);
- `--signer-workflow` matched as a prefix (GHSA-wjmr-j3rp-mh2g, fixed in
  2.102.0);
- `--source-ref` compared case-insensitively (GHSA-4mq3-hpgx-9cx8, fixed in
  2.102.0).

No recorded result depends on them. Every negative case with these flags still
failed as required. The identities of the positive cases are reconciled
independently and exactly in `reconcile.tsv` and the owner `*-release-verify.tsv`
files.

`verify-gh-pin.sh 2.103.0` passed (`results/gh-pin-verify-2.103.0.tsv`):

- the tarball's SHA-256 `fdd768eb…d786` equals the API digest and
  `checksums.txt`;
- the SLSA provenance verified offline, with the certificate matching cli/cli
  `212613049`/`59704711` and `deployment.yml@refs/heads/trunk` at the tag
  commit, on a GitHub-hosted runner;
- a changed byte failed;
- the release attestation (`release/v0.2`, release `419735650`) names the tag
  commit and the tarball.

The cli/cli provenance names `refs/heads/trunk`, not the tag, because releases
are built by a manual run of the workflow on trunk. The tag commit is therefore
checked as the source digest. Then `bootstrap.sh` reinstalled `gh` 2.103.0 in
`pakomichi-r003-oracle`.

## Plan for the owner's test repository

Steps 1–5 are done (above). The final R-003 report in `docs/` remains.

### Prerequisites

- A **public** test repository, here `kroxiksut/pchi-test` (artifact
  attestations in private repositories require GitHub Enterprise Cloud). A
  second owner for the transfer and fork steps, here the organization
  `pchi-test-org`.
- Copy `owner-repo/build-fixture.sh` to `scripts/` and the three workflow
  templates to `.github/workflows/`; replace every `<PIN: …>` with a reviewed
  full commit SHA. The fixture `.deb` has no maintainer scripts. Without a
  variant the build is reproducible across dpkg versions: `0.2.0` rebuilt in
  the Debian 12 DEB builder (dpkg 1.21.23, xz 5.4.1) has the CI digest
  `93b4dc42…`; with the variant `replaced-1` it is `a59a5cfd…`.
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
   `--signer-workflow kroxiksut/pchi-test/.github/workflows/mutable-attested.yml`
   and reconcile the repository ID.
3. **Replacement.** On the mutable `v0.2.0-mutable` release, replace the
   asset with a rebuilt one (`gh release delete-asset`, then `gh release upload`)
   through `r003-replace-asset` with a variant, which has no attestation
   permissions.
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
