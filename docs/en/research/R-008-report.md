# R-008 report — package sources (phase A)

**English** · [Русский](../../ru/research/R-008-report.md)

**Status: phase A complete; the protocol is not yet PASS.**

- **Done:** every source in scope has a row, and every design point of question 7 has a decision or an experiment that will decide it.
- **Proposed ADR:** [ADR-032](../decisions/ADR-032.md) is drafted; the owner agreed with the approach in principle on 2026-10-22.
- **Missing:** the acceptance of ADR-032 and the phase B experiments.

Protocol: [R-008](R-008-package-sources.md). Date: 2026-10-22.

## Method and limits

- Phase A only: documents plus anonymous, read-only requests from the development host.
  - Only metadata was read: API objects, `InRelease`, `repomd.xml`, catalog manifests. No package was downloaded or installed.
  - No account was created, and nothing was written to any service.
  - Raw responses and headers are in `.research-local/r-008/{forges,repos,catalogs}/`, and the matrix is in `research/r-008/sources-matrix.tsv`.
- Claims marked "unconfirmed" in the matrix come from a single secondary source or were not observed.
- I rechecked these from the saved files:
  - none of the 17 `InRelease` files has `Valid-Until`;
  - COPR and RED OS `repomd.xml.asc` return 404, and the COPR `.repo` has `repo_gpgcheck=0`;
  - GitLab release links have no size or digest field;
  - an anonymous GitLab 304 still decremented the rate limit (497 → 496).
- **Environmental limits:**
  - flathub.org was unreachable from the host, so the Flathub answers come from its documentation sources;
  - `apt.grafana.com` and `rpm.grafana.com` answered 403 to every request;
  - GitFlic and GitVerse require a token for every API call, so they were not read.

## Main findings

1. **Only GitHub offers Strict.** Attested is realistic on one other service, gitlab.com. Fulcio accepts it as an issuer with the same repository-ID and owner-ID claims (`.15`/`.17`). GitLab's attestations API is an experiment, and a self-managed instance has no public issuer.

   The other forges, the hosted repositories, and the catalogs offer only digests, publisher OpenPGP signatures by convention, or keys held by the service. That means Native (ADR-023) and Pinned (ADR-027) at most, plus the deferred "Signed" level for publisher OpenPGP keys (Launchpad, Forgejo).
2. **Numeric or UUID identities exist almost everywhere, but they are scoped to an instance.**
   - Numeric: GitLab project and namespace, Gitea/Forgejo/GitVerse repository and owner.
   - UUID or GUID: Bitbucket, GitFlic, Azure DevOps.
   - Name only: Launchpad and the hosted APT/DNF repositories. Their identity is a host, a path, and a key.
   - Gitea and Forgejo need a token to read a repository by ID, so "reconcile by ID, never by name" requires credentials there.
3. **The release object differs by source:**
   - GitLab's REST API has no release ID, and its asset links can be edited and carry no digest; the digests live in the generic package registry.
   - Bitbucket and SourceForge have no release object at all.
   - Generic packages in GitLab append files to an existing version by default.

   A replaced file is therefore not the only kind of mutation: a new file in a pinned release is one too.
4. **Download hosts differ from API hosts:**
   - presigned S3 (Bitbucket, COPR);
   - Cloudflare R2 (gitea.com);
   - CloudFront (packagecloud);
   - third-party mirrors (SourceForge);
   - a separate file host (Launchpad);
   - redirects between `repo1` and `repo2`/`repo3` (RED OS);
   - any host a GitLab release link names.

   One allowed host per client does not generalise.
5. **Conditional requests and rate-limit headers differ by source.**
   - No validators at all: Gitea, Forgejo, SourceForge, Azure DevOps, Tailscale, Chocolatey, the Snap info API.
   - Five header dialects:
     - GitHub `x-ratelimit-*`;
     - GitLab `RateLimit-*`;
     - Bitbucket `X-RateLimit-*` with `w=3600`;
     - the IETF draft `ratelimit-policy` (Codeberg);
     - `GitVerse-RateLimit-*`.
6. **Pointer catalogs add a second party's hash claim, not bytes.** WinGet, Scoop, Homebrew casks and formula sources, AppImageHub, and cargo-binstall all point at the vendor's own URL.
   - For jq 1.8.2, the WinGet `InstallerSha256` and the Scoop `hash` equal the GitHub asset digest, and Homebrew's source checksum equals another asset's digest. All of this was checked without downloading anything.
   - A WinGet manifest changed under the same version (jq 1.8.2 gained an arm64 installer), and that is visible only in Git history.
   - The community catalog lags: `Microsoft.OpenSSH.Preview` is 10.0.0.0 (2025-10-27) in WinGet, against 10.4.0.0p1-Preview (2026-10-20) in GitHub Releases (R-007, `.research-local/r-007/`).
   - A matching name proves nothing: the `jq` snap belongs to a third party and is still at 1.5.
7. **Store and packager signatures are not author signatures.**
   - Snap assertions, the Flathub repository key, and npm registry signatures belong to the store or registry.
   - Homebrew bottle attestations name Homebrew's own workflow, and one attestation covers 104 bottles.
   - None of them can count as Native or Attested for the upstream project.
8. **Hosted APT/DNF repositories offer nothing beyond the key APT/DNF already checks, and that key usually identifies the service, not the project.**
   - Microsoft uses one key per service, and Launchpad one key per owner. packagecloud, Cloudsmith, Gemfury, and COPR hold the private key.
   - Freshness gives the consumer nothing to rely on: no `Valid-Until` anywhere, and COPR and RED OS do not sign `repomd.xml` at all.
   - Bytes under the same version do change legitimately: HashiCorp re-signed packages under the same NEVRA after its 2026-09-10 key rotation, and COPR rebuilds the same version.
9. **The Russian targets:**
   - **Astra.** The documented route for third-party software is a vendor repository tested under "Ready for Astra", with ELF signatures by the Astra chain for the closed software environment. `extended` is explicitly not certified.
   - **RED OS.** The certified edition forbids pointing automatic update services at external third-party repositories. RED SOFT hosts selected third-party software in its own `3rdparty` tree.
   - Whether Pakomichi's local repository counts as such an external repository is an owner decision, needed before any claim about certified RED OS.

## Design points (question 7)

| Design point | Decision | Basis |
|---|---|---|
| Trust levels Strict, Attested, Native, Pinned | **Stay.** Strict stays GitHub-only. Attested becomes "an issuer plus its claim template", needed for gitlab.com. "Signed" (a publisher OpenPGP key) stays deferred and is the main upgrade path for Launchpad, Forgejo, SourceForge | findings 1, 7 |
| `forge_repository` (`repository_id`, `owner_id` as TEXT) | **Needs a general form:** add a source kind and an instance origin (IDs collide across instances); TEXT already holds int, UUID, GUID, and ObjectId. A name-only identity (Launchpad, hosted repositories) is a separate class that can never reach Attested | finding 2 |
| Owner confirmations (migration 0002) | **Stay**; they map to the GitLab namespace, Bitbucket workspace, and Gitea owner. For key-identified repositories the analogue is a confirmation of a key change | findings 2, 8 |
| `release_record.forge_release_id` | **Needs a general form:** nullable or composite (GitLab: tag plus the release ID from release evidence; Bitbucket and SourceForge: no release object) | finding 3 |
| Asset ID of `artifact` and the asset pin | **Needs a general form:** an opaque source artifact key plus a digest with its algorithm (sha256, sha512, sha3-384, md5 as a weak hint only). `E_ASSET_MUTATED` also covers a file added to a pinned release | findings 3, 6 |
| `trust_evidence` types | **Need new values**, none of which raises a level by itself: `catalog_digest_claim`, `store_assertion`, `api_digest`. Possible Windows evidence (R-007): `authenticode`, `msix_publisher` | findings 6, 7 |
| `github::PinnedRepository` | **Needs a general form:** one pin per source kind; the GitHub one stays as it is | finding 2 |
| ETag cache | **Stays ETag-only**, plus a path for sources without validators (time to live from `Cache-Control`, a poll budget). Rate limiting needs a parser per header dialect. On GitLab, as on GitHub, 304 costs quota | finding 5 |
| Pagination | **Needs a validated paginator per source** (GitLab adds extra query parameters, Bitbucket puts `next` in the body, Launchpad uses `memo`, GitFlic uses 0-based pages) | finding 5 |
| Single allowed host and the no-redirect rule | **Needs a general form:** per source, an API host plus declared download hosts, DNS vetting on every hop, and integrity only from the pinned digest. GitLab links outside the instance are refused or limited to its package registry | finding 4 |
| Optional token | **Needs a general form:** credentials per source instance (GitFlic and GitVerse cannot be read without one) | finding 2 |
| 16 MiB response cap | **Stays.** Azure DevOps returned a 24 MB unpaged list, which must be refused, not raised | — |
| Hosted APT/DNF repositories as a source kind | **Decided by the owner on 2026-10-22: a source kind** (vendor and organization repositories too). The value is control, not stronger cryptography: admitted packages, key-change confirmation, rollback detection, snapshots, recorded origin. Behaviour is configurable, with balanced defaults ([ADR-032](../decisions/ADR-032.md), proposed draft). The phase A recommendation "not a source kind" is withdrawn | finding 8 |
| Pointer catalogs (WinGet, Scoop, casks) | **Decided by the owner on 2026-10-22: sources are not restricted, so catalogs are sources too**, with honest levels (a catalog hash claim never raises a level) and a cross-check against forge digests where available ([ADR-032](../decisions/ADR-032.md)). The phase A recommendation "cross-check only" is withdrawn | finding 6 |
| Certified RED OS | **Open: owner decision** on whether a Pakomichi repository on loopback is an "external third-party repository" | finding 9 |

## Input for the proposed ADR on the source model

1. A source has a kind, for example `github`, `gitlab`, `forgejo`, `bitbucket`, or `sourceforge`. It has an instance origin, a stable identity of that kind, and the set of confirmed owners (migration 0002).
2. An artifact is identified by `(source, release key or null, source artifact key, digest algorithm, digest)`. The pin is never rebound, and both a replaced file and an added file are mutations.
3. Levels:
   - Strict is GitHub-only;
   - Attested comes from an issuer with a claim template (GitHub; gitlab.com);
   - Native and Pinned work for any source;
   - Signed stays deferred.

   Store, packager, and catalog claims are evidence that never raises a level.
4. Network: per source, an allowlist of API and download hosts, a paginator, a rate-limit dialect, and an optional validator.
5. Withdrawn after the owner's decision of 2026-10-22: hosted APT/DNF repositories and catalogs are source kinds. The draft is [ADR-032](../decisions/ADR-032.md). Still out of scope: Azure DevOps, Bitbucket Data Center, GitHub Packages (credentials required), and Snap, Flatpak, AppImage as formats.

## Phase B results so far (2026-10-22)

**Cross-channel hash census.** Read-only, with no binaries downloaded (`research/r-008/census.ps1`, `research/r-008/census.tsv`, raw files in `.research-local/r-008/census/`).
- Coverage:
  - 18 popular CLI tools (ripgrep, fd, bat, fzf, jq, yq, gh, lazygit, delta, starship, zoxide, eza, hyperfine, k9s, age, sops, croc, just);
  - 126 catalog claims;
  - every latest GitHub release had a `digest` on every asset (518 assets).
- **No mismatch anywhere.**
- Per channel:
  - WinGet: 39 match, 6 lag. In both lagging cases (yq 4.53.6 against 4.54.1, lazygit 0.66.1 against 0.66.2) the hash equals the digest of the older GitHub release.
  - Scoop: 42 of 42 match, all at the latest version, every URL a GitHub release asset.
  - Homebrew formulae: only jq is comparable, and it matches. The other 17 use auto-generated `/archive/` tarballs or a Git URL, and their bottles are built by Homebrew.
- **AUR:**
  - None of the guessed `<tool>-bin` packages exists in the AUR RPC.
  - The cgit `.SRCINFO` URL still serves stale branches of deleted packages, so a `.SRCINFO` is not evidence that a package is live.
  - The only live `delta-bin` packages a different project, `zed-industries/delta-nix`: a second case where a matching name is a different publisher.

**APT without `Valid-Until`.** A disposable Debian 12.15 distribution, apt 2.6.1, a TEST ONLY key, and a local repository (`research/r-008/apt-freshness.sh`, `research/r-008/apt-freshness.tsv`, logs in `.research-local/r-008/lab-apt/`). The distribution was removed afterwards.
- **Rollback is refused silently, and only by a client that already has newer data.**
  - After `InRelease` A, an older signed `InRelease` B was fetched (HTTP 200) and ignored. The exit code was 0, with no warning, and A's package list was kept.
  - A client without lists would accept B.
- **Without `Valid-Until`, nothing expires by default.** Metadata 10 days old is accepted. `Acquire::Max-ValidTime` and the `.sources` field `Valid-Until-Max` both turn `Date` plus the maximum into an expiry ("Release file … is expired", exit 100), so they work as freeze protection for repositories that publish no `Valid-Until`.
- **APT parses the OBS non-RFC date** (`Mon Sep 14 16:13:08 2026`) and applies `Max-ValidTime` to it.
- **A `Date` in the future is refused by default** ("not valid yet"). `Date-Max-Future`, `Acquire::Max-FutureTime`, or `Acquire::Check-Date=false` accept it.

For Pakomichi, the consequences are:
- a native-repository source can get freeze protection from a per-source `Valid-Until-Max`;
- rollback is visible only if Pakomichi itself compares `Date` with what it has seen, because APT gives no signal.

**Authenticode stability (R-007 question 3, partial).** Two Win32-OpenSSH MSIs were analysed (10.4.0.0p1 and 10.0.0.0p2): `research/r-007/authenticode-stability.tsv`, raw files in `.research-local/r-007/authenticode/`.

| Field | Stable between the two releases? |
|---|---|
| Subject (`CN=Microsoft Corporation`, …) | yes |
| Root (Microsoft Root Certificate Authority 2011) | yes |
| Timestamp authority | yes |
| Signature shape (one SHA-256 signature) | yes |
| Intermediate CA | **no**: PCA 2011 → PCA 2024 |
| Leaf thumbprint | **no**: about one-year leaves, reissued roughly every 10 months |
| Signing time | none is recorded; only the timestamp countersignature carries a time |

So neither the leaf thumbprint nor one intermediate can be pinned. The candidate pin is the subject plus a known root, on a valid chain with a timestamp. Older releases (9.8, 9.5, 8.9) are still needed before this becomes a finding. The WinGet `InstallerSha256` for 10.0.0.0 equals the GitHub digest; the script's automatic WinGet comparison still has a bug.

## Phase B: Gitea on gitea.com (2026-10-23)

Disposable fixtures created by an agent on the owner's instructions and labelled as such: organizations `pchi-test-gitea-a` (ID 259409) and `pchi-test-gitea-b` (ID 259410), repositories 148572 and 148573. Server version `29.0.0+dev-160-g55186ca39b`. Harness `research/r-008/gitea.py`, results `research/r-008/gitea-results.tsv`, raw responses in `.research-local/r-008/gitea-20261023T000000Z/`; the token was read only inside the harness and found in no file. The facts below were checked again with anonymous reads.

1. **Reading a repository by ID needs a token.** `GET /api/v1/repositories/{id}` answers HTTP 401 `token is required` anonymously and 200 with a token; reading by name works anonymously. Reconciling by ID, never by name, therefore needs credentials on Gitea (confirms phase A).
2. **Rename keeps the ID and redirects.** After `pchi-test` → `pchi-test-renamed` the ID stayed 148572; the old name answers 301 on the API, the web URL, and the Git URL.
3. **Reuse of the old name removes the redirect.** A new repository under the old name (ID 148573) answers 200 there with no redirect; a lookup by name now silently reaches another repository, as on GitHub (R-003). Only the ID tells them apart.
4. **Transfer** to another organization answered 202 and completed at once (both organizations had the same owner, so an acceptance step for a foreign owner was not tested). The ID stayed, the owner ID changed from 259409 to 259410, and the old path answers 301.
5. **Release attachments carry no digest.** The attachment JSON has only `id`, `uuid`, `name`, `size`, `download_count`, `created_at`, `browser_download_url`; the download (`/attachments/{uuid}`) is a 303 to a presigned object-storage URL valid for 300 s, and neither response carries a digest header. The SHA-256 is known only after downloading.
6. **Two attachments with the same name are accepted in one release** (201 for the second upload). An asset name does not identify a file on Gitea; two files of one name are `E_SOURCE_AMBIGUOUS`, as in `specifications/github.md` point 4.
7. **A replaced attachment leaves no trace on the release.** Delete and upload under the same name gives a new `id` and `uuid`, so the URL changes and the old one answers 404; `published_at` and `created_at` stay, there is no `updated_at`, and neither the activity feed nor `releases.atom` records the change. There is no immutable-release setting. A pin of `(release ID, attachment ID, SHA-256 of the downloaded bytes)` detects the replacement; nothing on the server does.
8. **No HTTP validators.** No `ETag` or `Last-Modified` on the API responses tested (`Cache-Control: max-age=0, private, must-revalidate`), so conditional requests are not available; no rate-limit headers were seen.
9. **No package registry on gitea.com.** Every `/api/packages/…` path answers 404 from the front proxy, and the repositories report `has_packages=false`. The Debian/RPM registry questions (service-held key, `Valid-Until`, the same version with new bytes) need a self-hosted Gitea or Forgejo instance and stay open.
10. **Actions are enabled** (`has_actions=true`, an empty run list); Gitea has no artifact attestations, so a Gitea source can reach Native or Pinned at most (phase A, finding 1).

## Phase B: package registry on a self-hosted Forgejo (2026-10-23)

gitea.com serves no package registry, so the registry questions ran on Forgejo 17.0.0 (`17.0.0+gitea-1.22.0`) in a disposable WSL distribution `pakomichi-r008-forgejo` from the pinned Debian 12 image, removed afterwards. The binary was verified by SHA-256 (`5a3b07e1…`) and by its OpenPGP signature against the release key `EB114F5E…C5923710` published on forgejo.org (`research/r-008/forgejo.lock.json`). Harness `research/r-008/forgejo-*.sh`, `forgejo-registry.py`; results `research/r-008/forgejo-registry.tsv`; raw files (Release, InRelease, Packages at every step, keys, repomd, apt logs) in `.research-local/r-008/forgejo-20261023T044146Z/`. Fixtures: the inert R-003 test `.deb` files and two R-001 builds of `sampleapp-1.0-1.noarch` with different bytes. Lab secrets were deleted after the run and found in no file.

1. **The service holds the key, one per owner and format.** It is generated on the first publication of an owner: RSA-2048, no expiry. Owners `lab` and `other` got different keys, and the RPM key of `lab` differs from its Debian key. The key stayed the same through every later step.
2. **No freshness bound.** The Debian `Release` has `Acquire-By-Hash: yes`, MD5/SHA1/SHA256/SHA512 sections and a `Date` equal to the time of the last package change, but no `Valid-Until`; the RPM `repomd.xml` has no revision and no expiry. A frozen copy of such a repository stays valid indefinitely (as in the APT freshness result above).
3. **The same version can silently get new bytes.** Uploading another `0.2.0` with the same name and architecture is refused (HTTP 409 `package file already exists`), but `DELETE` of the version (204) followed by the upload (201) publishes the new bytes under the same version: `Packages` changes from `93b4dc42…` to `a59a5cfd…`, `Date` moves on, and `InRelease` and `Release.gpg` verify with the same key. The only trace is a new internal version ID (5 → 6); no history or audit entry remains. RPM behaves the same (`8b594f76…` → `470e92cb…`, `repomd.xml.asc` valid).
4. **APT notices only a stale index, never the change.** With the cached index, `apt-get download` of 0.2.0 failed with `File has unexpected size (800 != 772). Mirror sync in progress?`; after `apt-get update` it fetched the new bytes without any warning.

So a valid signature of a hosted registry proves that the service published the index, not that a version kept its bytes. A source of this kind reaches Native at most (ADR-032), and Pakomichi must pin what it admitted by name, version and SHA-256 and treat new bytes under an admitted version as a replacement (`E_ASSET_MUTATED`), exactly as for release assets.

## Phase B (each item needs the owner's approval)

- **Forges** (test projects created by the owner):
  - GitLab: rename, transfer, reuse of the old path, link swap, duplicate upload, CI attestation and its certificate claims;
  - Gitea on gitea.com: done on 2026-10-23 (section above); the package registry on a self-hosted Forgejo: done on 2026-10-23 (section above); still open: Codeberg;
  - Bitbucket, only with a paid workspace: since 2025-05-29 free workspaces cannot upload or download files (Downloads) and have 1 GB of storage in total ([Atlassian, "Important changes coming to Bitbucket Cloud's Free plan"](https://www.atlassian.com/blog/bitbucket/important-changes-coming-to-bitbucket-clouds-free-plan), read 2026-10-23). Not tested: the project does not take a paid plan for this; a contribution with a reproducible test on a paid workspace is welcome;
  - GitFlic and GitVerse: read-only with the owner's token.
- **Hosted repositories** (R-001 and R-004 labs):
  - APT freeze without `Valid-Until`, with and without `Valid-Until-Max`;
  - APT with the OBS `Date` format;
  - DNF rollback with unsigned metadata;
  - RPM subkey rotation;
  - same NEVRA with new bytes;
  - a read-only RED OS configuration on `redos80`.
- **Windows** (R-007, a Windows 11 test VM):
  - a REST source on loopback, and the minimal trust change it needs;
  - a pre-indexed signed source;
  - client hash enforcement;
  - Authenticode pin stability across releases.
- **Read-only:** a cross-channel hash census of about 20 projects that publish only on GitHub; the Flathub API from another network.
