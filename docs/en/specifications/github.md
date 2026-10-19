# GitHub Releases adapter contract

**English** · [Русский](../../ru/specifications/github.md)

1. On `source add`, obtain the repo canonical URL, the numerical repository ID, and the owner ID from the API. Reconcile them on every synchronization. A Git rename with unchanged IDs is allowed; owner transfer -> suspend.
2. Request only the Releases of the selected repo ID. No Search API for neighboring repos, forks, or alternative owners. Do not use HTML scraping.
3. Release ID/tag/target_commitish are different fields. A verified link to the commit and the release is required wherever the trust mode claims it; `target_commitish` is not a sufficient cryptographic SHA check.
4. First examine the list of assets (name, size, digest, ID) and filter by format/architecture; when necessary, download *only* the candidates and inspect the native metadata.
5. Reconcile the digest of the received content; do not treat the API `digest` as an independent signature. Verify the cryptographic attestation, predicate, verified source repo ID, workflow, and exact digest.
6. Stable/beta/alpha channels are an explicit policy and the native version; the `prerelease` flag is mutable and is not the sole criterion.
7. Record ETag/Last-Modified, use conditional requests, back off according to `Retry-After` and limits; on error, do not substitute the reliable date of the last successful synchronization.
8. HTTP redirect validation on every hop; do not access private IPs/metadata endpoints based on parameters of an untrusted source; limit the sizes/number of assets.
9. No attestation/repo ID problem/file changed → `held`/`rejected`, a log event, no publication.

References: `docs/en/references.md`. Required research task: `R-003`.
