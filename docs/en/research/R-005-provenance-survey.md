# R-005 — Provenance evidence published by real repositories

**English** · [Русский](../../ru/research/R-005-provenance-survey.md)

This protocol measures which provenance evidence is actually published by repositories that ship `.deb`/`.rpm` files in GitHub Releases. Its result is decision input for the proposed ADR-018; it does not test Pakomichi behavior and does not change ADR-005 by itself.

## Questions

1. For the latest stable release that contains `.deb` or `.rpm` assets, what share of repositories provides: (a) Strict evidence (immutable release with a release attestation); (b) an artifact attestation (Attested); (c) a publisher signature with a verifiable identity (cosign signature or bundle over checksums, OpenPGP or minisign signature over checksums, signed RPM); (d) only unsigned checksums; (e) nothing?
2. Is the level stable across the last three stable releases, or does it regress?
3. Which share of the sample would 0.1 cover with Strict + Attested, with Signed added, and with Pinned added?

## Sample

- At least 100 repositories from at least two independent sources, each recorded with its selection date: (1) the GitHub-hosted entries of the `deb-get` catalog, used only as a list of names; (2) a GitHub repository search (for example, by the topics `linux`, `cli`, or `desktop` with at least 100 stars), filtered to repositories whose recent releases contain `.deb` or `.rpm` files. The read-only examples from `docs/en/product/scenarios.md` may be added.
- Exclude forks and archived repositories and record every exclusion. The candidate list is a research artifact only: do not follow forks or other repositories of the same owner, and do not turn the list into a discovery feature.
- Record the known biases: the `deb-get` catalog favors popular desktop applications; search favors starred projects.

## Method

Run in an isolated environment according to `docs/en/process/test-environments.md`. A GitHub token, if used, comes only from an environment variable or a local file with minimal permissions, never from a command argument or a log.

1. **Phase A, metadata only (GitHub REST API).** For each repository record the repository ID, the fork and archived flags, and the last three non-prerelease releases with `immutable`, asset names, sizes, and the asset `digest` field when present. For each `.deb`/`.rpm` digest query `GET /repos/{owner}/{repo}/attestations/sha256:{digest}`. Record signature and checksum assets by name: `*.sig`, `*.pem`, `*.bundle`, `*.sigstore.json`, `*.asc`, `*.minisig`, `SHA256SUMS*`, `checksums*.txt`. Phase A records claimed evidence only.
2. **Phase B, verification of a subset (at least 20 repositories, in a VM or container).** Download the assets and verify: attestations with `gh attestation verify` (the reference oracle of ADR-017); cosign, OpenPGP, and minisign signatures against the identity or key published by the project; RPM signatures with `rpm -K`. Do not install packages, unpack maintainer scripts, or run them. A file named `.sig` is not evidence until it verifies.
3. Classify each repository by the highest level confirmed in phase B, or claimed in phase A, and report claimed and verified levels separately.

## Output and PASS

- A table per repository: repository, ID, selection source, releases checked, level per release, and notes; aggregates per level, separately for claimed and verified; level regressions between releases.
- The script and the candidate list are saved as reproducible commands; raw JSON stays in `.research-local/`.
- Report neutrally: missing attestations is an observation about the evidence, not a judgment of a project.
- **PASS** (of the protocol, not of the product): at least 100 repositories from at least two sources, a reproducible list and commands, and a phase B subset of at least 20 repositories. **INCONCLUSIVE** if the sample is smaller or API limits prevent completion.

## Constraints and fallback

Do not open issues or pull requests in external repositories, fork them, or modify them as part of this research. If the result is INCONCLUSIVE, ADR-018 stays proposed and ADR-005 stays in force.
