# R-008 — Package sources: where developers publish, and what that means for the architecture

**English** · [Русский](../../ru/research/R-008-package-sources.md)

This protocol surveys the places where developers publish installable software that Pakomichi could take packages from. GitHub Releases is the first and only source of 0.1 (ADR-014). The survey checks which assumptions of the current design hold beyond GitHub, so that the source model can be fixed before more code depends on it. It is input for ADRs on the source model. It does not change the 0.1 scope and does not decide which sources will be implemented, or when.

## Questions

1. **Identity.** What stable identifier does a project and its owner have: a numeric ID, a UUID, or only a path? What happens on rename, transfer, deletion, and reuse of a name? Can a name be resolved to the stable identifier before first use, and do redirects follow a move?
2. **Release model.** Which object does the source publish? A release with a tag and assets, a versioned package, a pointer manifest (a vendor URL and a hash), or signed repository metadata (an APT or RPM repository)? Which fields exist (IDs, digest, size, times)? Can the content under the same version or name change, and does anything record it?
3. **Evidence.** Which evidence can a consumer verify?
   - attestations: issuer and identity claims;
   - detached signatures: OpenPGP, minisign, cosign;
   - repository metadata keys;
   - platform signatures: Authenticode, store assertions;
   - checksums only.

   How does each map to the trust levels Strict and Attested (ADR-005), Pinned (ADR-027) and Native (ADR-023)?
4. **Formats.** Which artifact formats does the source carry (`.deb`, `.rpm`, MSI, MSIX, AppImage, Flatpak, archives), and which of them reach APT or DNF without conversion (AGENTS.md forbids converting `.tar.gz` into `.deb`)?
5. **API.** Authentication requirements, anonymous limits, conditional requests, pagination, redirects across hosts, and size limits, measured against the client rules of `specifications/github.md` points 7–8 and ADR-019.
6. **Discovery boundary.** Can the source be used without scanning neighbouring projects, forks, or same-named projects (AGENTS.md)?
7. **Architecture impact.** Which parts of the current design are specific to GitHub and would need a general form? Candidates:
   - `forge_repository` (`repository_id`, `owner_id`, `canonical_url`) and the owner confirmations of migration 0002;
   - `release_record.forge_release_id` and the asset ID of `artifact`;
   - the evidence types of `trust_evidence`;
   - `github::PinnedRepository` and the asset pin;
   - the ETag cache and the network host allowlist;
   - the trust levels themselves.

## Sources in scope

| Group | Sources |
|---|---|
| Forges with releases | GitHub; GitLab (gitlab.com and self-managed); Bitbucket Cloud and Data Center; Gitea and Forgejo (Codeberg); Azure DevOps; SourceForge, including SVN-hosted projects; Launchpad (code hosting); GitFlic and GitVerse (Russian forges) |
| Developer-run package repositories | Vendor APT and YUM/DNF repositories; Launchpad PPA; Fedora COPR; openSUSE Build Service; hosted repositories (packagecloud, Cloudsmith, Gemfury); public Artifactory and Nexus instances |
| Application bundles and stores | Flathub; Snap Store; AppImage published in releases and catalogs |
| Windows and macOS catalogs | WinGet community repository and REST sources; Chocolatey; Scoop; Microsoft Store; Homebrew formulae, bottles, casks, and taps |
| Registries | GitHub Packages; GitLab Package Registry; OCI registries carrying non-container artifacts; language registries (crates.io, PyPI, npm) for contrast, including tools that install release binaries from them |
| Russian distributions | Repositories of Astra Linux and RED OS, and the vendor programmes for third-party software on them, as targets that consume the sources above |

The list may grow during the survey. Every added source is recorded with the reason it was added.

## Method

Run according to `docs/en/process/test-environments.md`. The survey is read-only throughout: no accounts are created, nothing is published, and no request writes to any service.

1. **Phase A, documents and anonymous reads.**
   - For every source, record the documented answers to questions 1–6, citing a URL and the date read. Mark claims from a single secondary source as unconfirmed.
   - Where the source has a public API, read the metadata of at least one real public project anonymously and save the response in `.research-local/r-008/`.
   - Do not download or install packages on the development host.
2. **Phase B, experiments, which need owner approval per platform.**
   - The questions left open by phase A become experiments in disposable test projects or local labs.
   - A test project on a public service is created by the owner from his own account, as for R-003.
   - Windows experiments follow R-007 and run in a VM.
   - Each experiment has its own commands, logs, and result table.
3. **Synthesis.** A matrix of sources against questions 1–6, then a list of the design points from question 7 with the change each would need.

## Output and PASS

- A report with the matrix and the architecture list, both EN and RU. A sanitized TSV of the matrix goes in `research/r-008/`; raw responses stay in `.research-local/r-008/`.
- **PASS** (of the protocol, not of any product capability), when all of the following hold:
  - every source in scope has a row with sourced answers to questions 1–6 or an explicit "unknown" with a planned experiment;
  - every design point of question 7 has a decision: it stays, it needs a general form (described), or it is still open (with the experiment that decides it);
  - at least one proposed ADR for the source model is drafted, or the report states why none is needed.
- **INCONCLUSIVE** if a group of sources has no row, or if the architecture list cannot be completed.

## Constraints and fallback

No issues, pull requests, comments, or package submissions in external projects. No repository files of the host, and no third-party sources of a lab system, are changed outside a disposable environment. Nothing here is a support claim. If the survey is inconclusive, the GitHub-specific design of 0.1 stays as it is, and each later source starts with its own research task.
