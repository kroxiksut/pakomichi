<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# R-005 research harness

This directory implements the read-only collection and verification protocol in
`docs/en/research/R-005-provenance-survey.md`. It is research tooling, not a
repository discovery feature and not production Pakomichi code.

Raw API responses, downloaded packages, keys, and verifier output belong under
`.research-local/r-005/`. Only sanitized TSV/JSON results belong in
`research/r-005/results/`.

## Isolation

Create a dedicated WSL2 distribution from a digest-pinned R-001 image. The
importer refuses names outside the R-005 namespace.

```powershell
powershell -NoProfile -File research/r-005/wsl-import.ps1 `
  -Name pakomichi-r005-survey -Image fedora44
```

Do not use the owner's `Ubuntu-24.04` distribution. Do not pass a token on the
command line. Put a read-only token in
`.research-local/r-005/secrets/github-token` with owner-only permissions inside
the WSL environment, or set `PAKOMICHI_GITHUB_TOKEN` there.

## Phase A

The collector freezes the `deb-get` commit, records its tarball SHA-256, uses
fixed GitHub Search queries, excludes forks and archived repositories, inspects
the latest three stable releases that actually contain `.deb`/`.rpm` assets,
and saves raw GitHub JSON outside Git. A missing asset digest is recorded as
unknown rather than as evidence that no attestation exists.

```bash
python3 -I research/r-005/survey.py collect \
  --raw-dir .research-local/r-005/raw \
  --token-file .research-local/r-005/secrets/github-token \
  --candidates research/r-005/results/candidates.tsv \
  --results research/r-005/results/phase-a.tsv \
  --exclusions research/r-005/results/exclusions.tsv \
  --phase-b-sample research/r-005/results/phase-b-sample.tsv \
  --summary research/r-005/results/summary.json
```

The Phase B sample is selected independently of the claimed evidence level by
a deterministic hash of the repository ID and selection date. Purposefully
selected examples of rare signature forms must be reported separately and must
not be used as an unbiased coverage denominator.

## Phase B

Generate a plan without overwriting an existing, manually reviewed plan:

```bash
python3 -I research/r-005/phase_b.py prepare \
  --sample research/r-005/results/phase-b-sample.tsv \
  --output research/r-005/results/phase-b-plan.tsv
```

For each selected asset, replace `unresolved` with one supported method and
record the exact evidence URLs and pinned identity. `key_source_url` records
where the project itself publishes the identity; a key found only next to an
asset is not sufficient. A signed-checksum method verifies both the signature
and the binding from the checksum file to the downloaded package bytes.

Run verification as the unprivileged research user. Packages are downloaded
but never installed or unpacked:

```bash
bash research/r-005/run-phase-b.sh
```

The runner uses a uniquely named `/tmp/pakomichi-r005-phase-b.*` download
directory and removes it on exit. Pass `dry-run` to use the ignored dry-run
plan and result paths.

Some WSL networking modes map public destinations into the benchmarking-only
`198.18.0.0/15` range. After confirming that behavior in the disposable WSL
distribution, set `PAKOMICHI_WSL_SYNTHETIC_DNS=1` for Phase B. This narrow
opt-in permits only that synthetic range; loopback, private, link-local, URL
credentials, non-HTTPS schemes, and non-443 ports remain rejected. Leave it
unset on networks that return public DNS addresses.

Aggregate claimed and verified results separately. The generated Pinned number
is labelled as theoretical eligibility; this protocol does not observe the
proposed quarantine behavior:

```bash
python3 -I research/r-005/aggregate.py \
  --phase-a research/r-005/results/phase-a.tsv \
  --phase-b research/r-005/results/phase-b.tsv \
  --repositories research/r-005/results/repositories.tsv \
  --regressions research/r-005/results/regressions.tsv \
  --summary research/r-005/results/aggregate.json
```

## Local checks

```bash
python3 -I -m unittest discover -s research/r-005 -p 'test_*.py' -v
python3 -I -m py_compile research/r-005/survey.py research/r-005/phase_b.py research/r-005/aggregate.py research/r-005/test_survey.py
python3 -I research/r-005/validate-results.py research/r-005/results
```

Phase B records GitHub evidence and native RPM signatures independently. Every
selected RPM is inspected with `rpmkeys --checksig --verbose` in an empty
inspection database even when its primary provenance method is a GitHub release
attestation. An OpenPGP signature without a key identity published by the
project is inspected but remains `Nothing-observed`, never `Signed`.
