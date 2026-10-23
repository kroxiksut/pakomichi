# R-003 report — GitHub Strict/Attested and repository identity

**English** · [Русский](../../ru/research/R-003-report.md)

- **Date / performed by:** 2026-10-20 (read-only part) and 2026-10-22 (owner's test repository), read-only transfer recheck 2026-10-23, programming agent at the project owner's request; protocol: [R-003](R-003-github-provenance.md).
- **Outcome:** **PASS**. All seven protocol steps ran, and the actual JSON verification results and the exact matching rules are preserved. The production verifier was chosen separately in [ADR-030](../decisions/ADR-030.md). The observation after the transfer (step 4, finding 6) did not change at a read-only recheck about 19 hours later.
- **Main fact:** a repository name never identifies a GitHub source. After a rename, the old name verifies and the new one does not. After another repository takes the old name, artifacts of the original still pass `--repo` with that name. A fork in the same account has the original's owner ID. Only the repository ID separates all these cases, and Pakomichi must compare it itself, because `gh attestation verify` binds by name.

## Environment

All verification ran in the disposable WSL distribution `pakomichi-r003-oracle`, imported from the digest-pinned `library/fedora:44` layer of the R-001 lock, with Python 3.14.8 and GitHub CLI 2.95.0 as the reference oracle (tarball SHA-256 `25d1e472…3d8c`, the P0-004 pin). Collection and verification ran as the unprivileged user `r003`. Downloaded packages were only hashed: never installed, unpacked or executed.

- **Read-only part (2026-10-20):** external subjects `matthart1983/netwatch` v0.35.4 (mutable, build provenance) and `cli/cli` v2.95.0 (immutable, release attestation), anonymous API only, 14 counted requests.
- **Owner's test repository (2026-10-22):** public repository `kroxiksut/pchi-test` (repository ID `1429109739`, owner ID `2264172`) and the temporary organization `pchi-test-org` (owner ID `346117935`) as the second owner. Repository contents: an inert `.deb` fixture without maintainer scripts and three workflows pinned to full commit SHAs (`actions/checkout` v7.0.1 `3d3c42e5…`, `actions/attest-build-provenance` v4.2.2 `4d101475…`); templates in `research/r-003/owner-repo/`.
- **Credentials:** API collection stayed anonymous. A fine-grained token with public read access and no permissions was given only to online `gh` cases, through the environment from a 0600 file, never on a command line. A scan after every run found it in no log or result. Write operations on GitHub (enable immutability, dispatch workflows, rename, create, transfer, fork, the clobber attempt) were done by the owner or with the owner's login after the owner's explicit permission.
- **Network:** inside WSL `release-assets.githubusercontent.com` resolved into `198.18.0.0/15` (as in R-005). All downloads matched the API digests.

## Fixtures and commands

```powershell
powershell -NoProfile -File research/r-003/wsl-import.ps1 -Name pakomichi-r003-oracle
wsl.exe -d pakomichi-r003-oracle -u root --cd /tmp -- bash /mnt/d/Projects/pakomichi/research/r-003/bootstrap.sh
wsl.exe -d pakomichi-r003-oracle -u root --cd /tmp -- bash /mnt/d/Projects/pakomichi/research/r-003/run.sh all
wsl.exe -d pakomichi-r003-oracle -u root --cd /tmp -- bash /mnt/d/Projects/pakomichi/research/r-003/run-owner.sh step1
# step2, step3, step4 rename|reuse|transfer, step5 in the same way
```

`research/r-003/r003.py` is the read-only harness. `research/r-003/owner.py` reuses it for the owner steps, and `run-owner.sh` hands it the token. `research/r-003/README.md` gives the exact repository operation before each run. Sanitized results are in `research/r-003/results/` (`*.tsv` from the read-only run, `owner-step*-*.tsv` from the owner steps). Raw API responses, bundles, downloads and complete oracle output are in the ignored `.research-local/r-003/`.

## Results by protocol step

| Step | What ran | Result |
|---|---|---|
| 1. Immutable release + release attestation | `v0.1.0` published with immutability on (release `420324447`, asset `664728438`, SHA-256 `8fcda58d…`). | `gh release verify` and `verify-asset` pass with the token. The release predicate (`release/v0.2`) carries `repositoryId 1429109739`, `ownerId 2264172`, `databaseId 420324447`, tag `v0.1.0`, the tag commit as `sha1` subject and the asset as `sha256` subject; all equal the API. The asset also has build provenance, verified offline with a pinned workflow, ref, commit, issuer and hosted runner. `gh release upload --clobber` with the owner's write login: `HTTP 422 Cannot delete asset from an immutable release`, asset unchanged. |
| 2. Mutable release + build provenance | `v0.2.0-mutable` with immutability off (release `420339762`, asset `664783235`, `93b4dc42…`); netwatch read-only. | Signature, repository and owner IDs, signer workflow `mutable-attested.yml@refs/heads/main`, commit and SHA-256 reconciled. All 15 offline negatives rejected. `gh release verify` rejects the mutable release (no release attestation). `v0.1.0` stays `immutable=True` after immutability is turned off. |
| 3. Asset replacement | The step 2 asset replaced by a rebuild with a different payload (workflow without attestation permissions). | Release ID, tag, tag commit and asset name unchanged; asset ID `664783235` → `664806807`, SHA-256 → `a59a5cfd…` (predicted exactly by a local deterministic rebuild). The replacement has no attestation and fails against the step 2 bundle. The recorded step 2 triple is kept as evidence and is not overwritten. |
| 4. Rename / transfer | Rename to `pchi-test-renamed`; a new repository takes `kroxiksut/pchi-test` (ID `1429307950`); transfer to `pchi-test-org`. | Repository ID unchanged throughout; owner ID `2264172` → `346117935` after the transfer. See the table below. |
| 5. Fork | Fork `kroxiksut/pchi-test-fork` (ID `1429309242`, parent `1429109739`) released `v0.3.0-mutable` with the same asset name and its own build provenance (`d3c6baed…`). | Valid for the fork; rejected against the original by its current name, old name, signer workflow and organization owner. Reconciled against the original's IDs, the repository ID and owner ID differ (`all_match=NO`), everything else matches. |
| 6. Missing provenance, predicate, signer, root, digest, network | Read-only run and step 2. | Empty bundle, wrong predicate, other workflow or signer repository, wrong issuer, ref or commit, foreign digest, forged DSSE payload and a trusted root without Fulcio CAs are all rejected. Offline verification with a bundle and trusted root passes without network; online verification without network fails. |
| 7. Name vs repository ID | Read-only run and steps 4–5. | `gh attestation verify` binds by name only (case-insensitive). The repository and owner IDs are compared by the harness from the verified certificate. |

Step 4 in detail: the same step 1 asset and bundle checked after each operation.

| After | `kroxiksut/pchi-test` resolves to | Offline `--repo` old name | Offline `--repo` current name | `gh release verify v0.1.0`, current name |
|---|---|---|---|---|
| rename | `1429109739` (redirect) | pass | fail | pass |
| reuse of the old name | `1429307950` (another repository) | **pass** | fail | pass |
| transfer | `1429307950` | **pass** | fail | **fail** (no attestations) |

## Matching rules confirmed

- **Strict** needs a verified release attestation whose predicate `repositoryId` and `ownerId` equal the pinned IDs, `databaseId` equals the release ID being checked, `tag` equals its tag, the `sha1` subject equals the tag reference object, and a subject with the asset name has the asset's SHA-256. The API `immutable` flag is required but is not evidence by itself. The tag reference object is `object.sha` of `git/ref/tags/{tag}` as returned, never peeled. The R-003 tags are lightweight, so there it is the tag commit. A later read-only check of an annotated tag (`github/github-mcp-server` v2.0.2, `research/r-003/results/annotated-tag-reference.tsv`) showed that the `sha1` subject is the tag object, not the peeled commit, and that a lookup by the peeled commit returns HTTP 404.
- **Attested** needs verified build provenance whose certificate claims `.1.15` (repository ID) and `.1.17` (owner ID) equal the pinned IDs, with the exact signer workflow, ref, commit, issuer `https://token.actions.githubusercontent.com` and a GitHub-hosted runner. In addition, the artifact digest must equal the API digest of the asset currently in the release.
- **Pin:** `(release ID, asset ID, SHA-256)`. A name or a release ID alone does not detect a replaced asset.
- **Source resolution:** through `/repositories/{id}`, never through the stored name.

## Findings

1. **Release attestation lookup by commit is ambiguous.** For `v0.2.0-mutable`, `attestations/sha1:<tag commit>` returned the release attestation of `v0.1.0`, because both tags point to the same commit. Finding a release attestation for the tag commit does not make a release Strict; `databaseId` and `tag` must match the release being checked. `gh release verify` handles this correctly.
2. **An attestation outlives its asset.** After the replacement, the removed asset still verifies online by digest and offline with its bundle. A valid attestation does not prove that the file is a current asset of the release.
3. **Rename keeps the ID and breaks name binding.** Certificates keep the old repository URI. `--repo <new name>` fails and the old name passes; `gh release verify` follows the repository and passes under both names.
4. **Reuse of an old name.** Once another repository holds the old name, artifacts of the original still pass `--repo` with that name. Only the repository ID shows that the name now belongs to someone else.
5. **Transfer changes the owner ID**, so the certificates' owner ID no longer matches: the source must be suspended until the owner confirms it again (ADR-030 point 5). Attestations made before the transfer keep the old owner ID, so confirming the source again must add the new owner ID to the old one, not replace it; otherwise releases published before the transfer stop verifying (probe cases T1–T3 below).
6. **Attestations did not follow the transfer.** Within minutes of the transfer, and unchanged at read-only rechecks about 40 minutes, about 4 hours and about 19 hours later, `attestations/…` returned HTTP 404 for the repository (by name and by `/repositories/1429109739`) and for the organization, while `users/kroxiksut/attestations/…` still returned both bundles with repository ID `1429109739`. `gh release verify` for the immutable `v0.1.0` failed although the release stayed `immutable=True`. Bundles stored before a transfer still verify offline. Strict fetching must therefore not depend on fetching attestations after a transfer; it relies on bundles stored at admission.
7. **Owner ID alone does not reject a fork.** The fork lives in the account that created the original, so its owner ID equals the owner ID in the original's earlier certificates, and `--owner kroxiksut` accepts the fork's asset. Only the repository ID separates them.
8. **Oracle limits of `gh` 2.95.0.** `gh attestation verify` cannot check a release attestation offline: the default policy expects a workflow identity, and with `--cert-identity https://dotcom.releases.github.com` it requires a `SourceRepositoryOwnerURI` the certificate does not have. `gh release verify*` is online-only and needs authentication even for public repositories. Different failures are reported with the same `verifying with issuer "sigstore.dev"`.
9. **Provenance binds the dispatching ref.** A workflow dispatched on `main` records `refs/heads/main`, not the release tag. A policy that pins the source ref must use the ref of the run.
10. **Reproducibility.** The fixture build without a variant is byte-identical across dpkg 1.21.23 (Debian 12) and the CI runner, so a local rebuild predicted the CI digest of the replacement exactly.

## Production verifier

R-003 used `gh` only as the reference oracle (ADR-017 point 9). The production verifier is decided in [ADR-030](../decisions/ADR-030.md): `sigstore-verify` `=0.15.0` behind a Pakomichi interface. Strict uses GitHub's root, the SAN `https://dotcom.releases.github.com` and an RFC 3161 timestamp, and binds only by the predicate `repositoryId`/`packageId`/`ownerId`/`databaseId`/`tag`. Attested uses the public-good root and binds by Fulcio `.1.15`/`.1.17`. Its probe on the recorded R-003 evidence is `research/r-003/results/verifier-probe-cases.tsv` (60 of 60 as expected), and `research/r-003/results/verifier-probe-oracle.tsv` (`gh` 2.103.0 agrees in 26 of 26 comparable Attested cases; for a renamed repository `gh` rejects by name, while ADR-030 passes by ID with a notice). The cross-check of that verifier on the step 4 and 5 bundles (P1-003c, `research/r-003/verifier-probe-owner.sh`, results `research/r-003/results/verifier-probe-owner.tsv`) gave 10 of 10 as expected:

| Case | Input and pin | ADR-030 probe | `gh` 2.103.0 offline |
|---|---|---|---|
| R1, R2 | after rename; pinned IDs `1429109739`/`2264172`, expected name `kroxiksut/pchi-test-renamed` | Strict and Attested PASS with a `name_changed` notice | rejects (binds the old name in the certificate) |
| U1, U2 | the new `kroxiksut/pchi-test` (ID `1429307950`, same owner `2264172`) offered the original's `v0.1.0` bundle | `RepositoryIdMismatch` (Strict and Attested) | **accepts** with `--repo kroxiksut/pchi-test` |
| T1, T2 | after transfer, owner ID re-pinned to the organization `346117935` | `OwnerIdMismatch` | rejects with the new name |
| T3 | after transfer, owner ID of the release time `2264172` kept | PASS with `name_changed` | — |
| F1 | fork bundle (`1429309242`, owner `2264172`) against the original's pin | `RepositoryIdMismatch` | rejects |
| F2 | fork bundle against the fork's own pin | PASS | accepts |
| F3 | the fork's mutable release under Strict | DOWNGRADE `ReleaseAttestationMissing` | — |

U2 is the case this protocol exists for: a repository that took the old name is accepted by name-based verification and rejected only by repository ID.

## Not covered

- Finding 6 held for about 19 hours after the transfer (`results/owner-step4-transfer-attestation-lookup.tsv`) and is treated as lasting behaviour; GitHub does not document it, and whether a transfer back restores the lookups was not tested.
- A release published from a new repository that took an old name was not created; finding 4 rests on the original's artifacts.
- Private repositories, GitHub Enterprise, reusable signer workflows from another repository, and the TUF client (P2-003) are outside this protocol.

## Conclusion

Proven: Strict and Attested can be decided offline from stored bundles with exact ID binding; the immutable flag, a name, an owner ID or a release ID alone are each insufficient, as shown by real counterexamples. Finding 6 held unchanged for about 19 hours and is treated as lasting, which Strict already tolerates by relying on bundles stored at admission; that it is permanent is not proven.

**ADRs affected:** ADR-005 and ADR-027 (trust levels and Pinned), ADR-017 point 9 (oracle only), ADR-030 (production verifier, consistent with these results).

**Fallback:** unchanged from the protocol. If a mode cannot be verified on a given host or project, that mode is disabled and the source stays observing.

**Required follow-up:** the Pinned and ratchet implementation (P2-011a) stores `(release ID, asset ID, SHA-256)` and requires the digest of the current asset; the Strict and Attested implementation checks `databaseId`/`tag` against the release and resolves sources only by repository ID; after a transfer the source is suspended, confirming it again adds the new owner ID to the pinned set, and verification uses bundles stored at admission.
