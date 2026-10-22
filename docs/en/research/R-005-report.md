# R-005 report — provenance evidence published with GitHub Release packages

**English** · [Русский](../../ru/research/R-005-report.md)

- **Date / performed by:** 2026-10-20, programming agent at the project owner's request; protocol: [R-005](R-005-provenance-survey.md).
- **Outcome:** **PASS for the research protocol**, not for product readiness. Phase A contains 100 eligible repositories from two sources and 291 release rows; Phase B completely classified a deterministic subset of 20 repositories and 30 package assets.
- **Decision boundary:** this report is evidence for the proposed ADR-018. It does not amend accepted ADR-005, approve Pinned mode, or test Pakomichi's future quarantine behavior.

## Environment and isolation

All network collection and verification ran as the unprivileged user `r005` in the dedicated WSL2 distribution `pakomichi-r005-survey`. It was imported from `fedora:44`, pinned to manifest `sha256:be9d65e2…` and layer `sha256:59259e16…`. The environment used Python 3.14.8, GitHub CLI 2.97.0, GnuPG 2.4.9, minisign 0.12, and RPM 6.0.2; exact values are in `research/r-005/results/environment.tsv`.

The owner's Ubuntu distribution, Windows package sources, VirtualBox, and third-party repositories were not modified. The study made only read-only GitHub requests. It did not create issues, pull requests, forks, stars, comments, or repository changes. Packages were downloaded into uniquely named `/tmp/pakomichi-r005-*` directories, never installed or unpacked, and removed on exit. Raw API responses and verifier logs remain ignored under `.research-local/r-005/`.

WSL maps GitHub release hosts into the benchmarking-only `198.18.0.0/15` range. Phase B used the documented narrow opt-in for that range; loopback, private, link-local, URL credentials, non-HTTPS URLs, and non-443 ports remained rejected.

## Sample and reproducibility

The sample was frozen at `2026-10-20T07:45:32Z`:

- `deb-get` was used only as a list of GitHub repository names: commit `8fa6a694e2733f73ff4ec9cba8c12b0632b48ff8`, tarball SHA-256 `c1172a9e62c5ae5be254be8e30cb5f667804aa61b39e54f99ac30e4d2303f7f6`;
- GitHub Search used the fixed topics `linux`, `cli`, and `desktop`, each with `stars:>=100 archived:false fork:false`;
- the accepted set has 80 deb-get-only repositories, 4 search-only repositories, and 16 present in both sources;
- 31 candidates were excluded with a recorded reason: 25 had no `.deb`/`.rpm` in 30 recent releases, 3 were archived, 2 were forks, and 1 was not found;
- 94 repositories supplied three eligible stable releases, 3 supplied two, and 3 supplied one.

This is not a prevalence survey of all GitHub software. deb-get favors popular desktop applications, while search favors starred projects and the selected topics. The candidate list is a research artifact, not a discovery feature; the collector never enumerated all repositories of an owner.

Reproduction commands:

```bash
bash research/r-005/run-phase-a.sh
python3 -I research/r-005/phase_b.py prepare \
  --sample research/r-005/results/phase-b-sample.tsv \
  --output research/r-005/results/phase-b-plan.tsv
# Review and resolve every plan row before execution.
bash research/r-005/run-phase-b.sh
python3 -I research/r-005/aggregate.py \
  --phase-a research/r-005/results/phase-a.tsv \
  --phase-b research/r-005/results/phase-b.tsv \
  --repositories research/r-005/results/repositories.tsv \
  --regressions research/r-005/results/regressions.tsv \
  --summary research/r-005/results/aggregate.json
```

## Phase A: claimed evidence

Phase A records names and GitHub API observations; it does not prove a signature merely because an asset is named `.sig`.

| Latest-release classification | Repositories | Share |
|---|---:|---:|
| Strict-claimed | 6 | 6% |
| Attested-claimed | 1 | 1% |
| Signed-claimed | 7 | 7% |
| Checksums-only | 8 | 8% |
| Nothing-observed | 55 | 55% |
| Unknown-attestation | 23 | 23% |

`Unknown-attestation` means the GitHub asset did not expose a digest, so Phase A could not issue the digest-addressed attestation request. It is not evidence that an attestation is absent.

The resulting claimed 0.1 coverage is:

| Admitted levels | Repositories | Share |
|---|---:|---:|
| Strict + Attested | 7 | 7% |
| Strict + Attested + Signed | 14 | 14% |
| Plus Pinned | 100 | 100% theoretical eligibility only |

The Pinned row does not measure quarantine, mutation response, explicit consent, or safety. It must not be presented as verified product coverage.

## Phase B: verified subset

Twenty repositories were selected independently of their claimed evidence by a deterministic hash of selection date, repository ID, and repository name. For each selected format, the plan preferred a native x86-64 package. Thirty assets totaling approximately 0.94 GiB were downloaded and classified.

| Highest verified level | Repositories | Share of Phase B only |
|---|---:|---:|
| Strict | 3 | 15% |
| Attested | 1 | 5% |
| Signed | 0 | 0% |
| Checksums-only | 1 | 5% |
| Nothing-observed | 15 | 75% |

Strict + Attested therefore covers 4/20 (20%) in Phase B; adding Signed changes nothing. This percentage describes only the deterministic verification subset and is not an estimate for all 100 repositories.

Important verification details:

- GitHub release and asset attestations verified Strict for `GyulyVGC/sniffnet`, `anchore/grype`, and `olalie/tapmap`; artifact attestation verified Attested for `sharkdp/fd`.
- Four sampled `Unknown-attestation` repositories were downloaded and queried by their computed SHA-256. All returned an exact attestation-endpoint 404 and were classified `Nothing-observed`; transport errors are not treated as absence.
- `muesli/duf` published an OpenPGP signature over checksums and `fail2ban/fail2ban` published a detached OpenPGP package signature. The signatures were structurally inspected and the checksum file bound the selected duf assets, but exact-fingerprint searches and release notes exposed no key identity published by the project. Both therefore remained `Nothing-observed`, not Signed.
- The checksums for `nextpad-plus-plus/nextpad-plus-plus-linux` bound both selected package bytes, but were unsigned, so the level remained Checksums-only.
- `rpmkeys --checksig --verbose` ran in an empty inspection rpmdb for all 10 selected RPMs. None contained an embedded RPM signature. GitHub Strict/Attested evidence and native RPM signatures are independent properties; the R-002 mandatory-policy fallback still applies.

The per-repository table is `repositories.tsv`; exact package rows, digests, methods, RPM state, and sanitized verdicts are in `phase-b.tsv`. Detailed verifier output remains ignored.

## Evidence stability across releases

The 191 comparable adjacent-release transitions contain:

| Transition | Count |
|---|---:|
| Stable | 121 |
| Improvement | 6 |
| Regression | 0 |
| Unknown | 64 |

The six observed improvements introduced checksums, Strict release evidence, or an artifact attestation. No regression was observed, but 64 transitions are unknown because at least one release lacked the API digest needed for Phase A attestation lookup. This sample therefore does not prove that evidence levels never regress; ADR-018's proposed ratchet still requires direct negative testing.

## Conclusions and decision input

1. The context assumption behind ADR-005 is not supported by this sample: only 7% of latest releases claimed Strict or Attested evidence. Because of the known sample biases, this is decision input rather than a GitHub-wide prevalence estimate.
2. Adding all `Signed-claimed` rows would raise claimed coverage only to 14%, and Phase B confirmed no Signed repository in its deterministic subset. A signature filename cannot count without cryptographic verification against a project-published identity.
3. Pinned would make every sampled repository theoretically eligible, but R-005 did not test quarantine or mutation handling. The 100% number is not evidence that Pinned is safe or ready for 0.1.
4. Missing GitHub API asset digests materially limit metadata-only classification: 23% of latest releases were `Unknown-attestation`. Downloading and hashing in Phase B resolved the four sampled cases to no observed attestation.
5. Provenance and native package signatures are orthogonal. None of the 10 selected RPMs had an embedded signature, including RPMs with verified Strict GitHub release evidence.

For the project owner: the result supports continuing the ADR-018 discussion because ADR-005 alone would leave most of this sample in `observing`. It does not by itself choose Signed or Pinned, supersede ADR-005, or satisfy the required R-003 and quarantine negative tests.

## Deviations and implementation observations

- The first Phase A attempt ended after more than 200 cached responses when `http.client.RemoteDisconnected` was not covered by the retry boundary. The client now retries `HTTPException` with bounded backoff; a unit test reproduces disconnect then success. The final authenticated run completed with ample API quota.
- `cosign` was not installed because no selected plan row required it. GitHub attestations used the ADR-017 reference oracle, GitHub CLI 2.97.0.
- No deliberately selected rare-signature example was added to the denominator. The Phase B subset remained deterministic and independent of claimed level.

## Proposed index entries

- `docs/en/process/decisions-and-evidence.md`: `R-005 — PASS for the protocol: 100 repositories from deb-get and GitHub Search; latest-release claimed coverage was 7% Strict+Attested and 14% with Signed-claimed; deterministic Phase B verified 20 repositories, with 3 Strict, 1 Attested, 0 Signed, 1 checksums-only, and 15 nothing observed. Pinned coverage is theoretical only; ADR-018 remains an owner decision.`
- `docs/en/research/INDEX.md`: `R-005 report: [provenance evidence published with GitHub Release packages](R-005-report.md) — protocol PASS; 100 repositories and a 20-repository verified subset.`
