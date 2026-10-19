# R-003 — Confirming GitHub Strict/Attested and identity

**English** · [Русский](../../ru/research/R-003-github-provenance.md)

The result of this protocol is required before claiming support for the GitHub Strict or Attested modes.

## Goals

Check: (a) Strict immutable release + a correct release attestation; (b) mutable release + signed artifact build provenance; (c) binding to the permanent repo ID in the attestation; (d) rejection of a new repo/fork under an old name; (e) immutability of admitted digests.

## Examples

Use your own **test** repository with available controlled releases and small files. As a read-only external check, use `matthart1983/netwatch`, whose v0.35.4 release has `immutable:false` and published build attestations. Do not mutate or fork the external project for the sake of a test.

## Steps

1. Create a release draft, attach files, publish an immutable release; request the release attestation, parse the predicate, and check the signer/source ID.
2. Create a mutable release with `actions/attest-build-provenance` for a file; check the signature, source repo ID, workflow identity, and SHA256; use `gh attestation verify -R owner/repo --format json` as an experimental reference, but check the CLI's limitations.
3. Change an existing *test* mutable asset and check that the stored `(release ID, asset ID, SHA)` is not automatically overwritten; republishing a new version is a separate release.
4. Simulate rename/transfer; check the repository ID and owner ID, as well as the behavior of `gh attestation verify` with the old and new names. For transfer → suspend.
5. Try an attestation from another repository/fork with the same artifact name and a higher version; it is not accepted.
6. Check the cases of missing provenance, an incorrect predicate, signer workflow, an untrusted root chain, a missing asset digest, and no network.
7. Check whether GitHub CLI yields only a name binding instead of the repo ID for an offline bundle; separately reconcile the embedded `sourceRepositoryIdentifier`.

## PASS and fallback

PASS when the report preserves the actual JSON verification results and exact matching rules for repo ID, asset SHA, and release/commit. Relying only on the file name and the `immutable` flag is not allowed.

**Fallback:** disable the specific unconfirmed mode (Strict or Attested) on the given host/project until a verified verification tool becomes available; the source is observing, not "trust on SHA alone".
