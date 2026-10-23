# Machine-readable reason and error codes

**English** · [Русский](../../ru/specifications/errors.md)

| Code | Meaning | Behavior |
|---|---|---|
| `E_REPO_ID_CHANGED` | The URL resolves to a different persistent repo ID | Suspend, do not follow |
| `E_OWNER_TRANSFER` | The owner has changed | Suspend until confirmation |
| `E_ASSET_MUTATED` | An already accepted artifact has changed | Reject the new copy, do not rebind the digest |
| `E_ATTESTATION_INVALID` | Verification of the provenance evidence failed | Reject |
| `E_SIGNATURE_POLICY` | The system policy requires an RPM signature that is unavailable, or an unsigned RPM does not meet every condition of the Attested exception (ADR-023) | Hold |
| `E_FAMILY_UNAPPROVED` | A new package name outside the admitted package family | Hold |
| `E_SYSTEM_PACKAGE_CONFLICT` | An attempt to displace a system package/critical `Provides` | Hold |
| `E_SOURCE_AMBIGUOUS` | The same version from sources with different bytes | Observing/hold |
| `E_DEPENDENCY_UNSATISFIABLE` | Required dependencies are missing | Hold |
| `E_PLATFORM_UNSUPPORTED` | The format/arch/ABI is clearly unsuitable, or the system SQLite is older than 3.34.1 (ADR-020) | Hold; for SQLite the state owner does not start |
| `E_SNAPSHOT_INCONSISTENT` | The snapshot's index/reference/signature diverges, including a failed check of our own signed `InRelease`/`repomd.xml` (the metadata gate, ADR-023) | Do not publish; a signature failure right after an RPM generation switch is retried first (ADR-024) |
| `E_CACHE_DIGEST_MISMATCH` | Cache bytes do not match the accepted SHA | Do not serve |
| `E_SOURCE_STALE` | The data has exceeded the permissible freshness | Error of our source. On DNF, a signed empty generation replaces the stale one (ADR-024); on APT, `Valid-Until` expires |
| `E_FORGE_UNAVAILABLE` | Git is unavailable | Verified cache according to policy |
| `E_ADMIN_APPLY_FAILED` | Incomplete write of the local configuration, or the effective values read back after writing differ from the written ones | Rollback/reconcile |
| `E_DISK_EXHAUSTED` | The snapshot/download cannot be completed | Refuse the new publication, do not change the old snapshot |
| `E_ARTIFACT_MALFORMED` | A package from the source fails structural inspection: a truncated or corrupted archive, malformed headers or metadata, a format version or member compression that no current `dpkg`/`rpm` accepts, a member over the inspection limits, or not a DEB/RPM at all | Reject these bytes; the user reports the broken asset to the publisher. A well-formed package that only this system's native tool cannot read is `E_PLATFORM_UNSUPPORTED` |
| `E_EVIDENCE_DOWNGRADE` | A release carries weaker provenance evidence than the source's trust floor, for example no attestation after attested releases | Hold the release until the user decides; the floor is never lowered automatically. The user asks the publisher to restore the evidence or, where the source has Pinned consent, approves the release explicitly |
| `E_RELEASE_APPROVAL_REQUIRED` | A release admitted only at the Pinned level (explicit per-source consent, no cryptographic provenance) waits for the user's manual approval of that release | Hold until the user approves the release; the approval covers only the digests that were reviewed |
| `E_EXECUTION_POLICY` | An OS execution-control policy would refuse to run the package's executables, for example a closed software environment that runs only executables signed through the OS vendor's key chain (found on Astra Linux, R-006); also when such a policy is configured but not yet running, or its state cannot be read | Hold every artifact and refuse activation; never sign, re-sign, or modify files, add keys, or change the policy. A program that crashes under such a policy is reported as a probable refusal, not as a package defect |
| `E_SECURITY_CONTEXT` | The operation runs in a security context that cannot perform it, for example an integrity level or a mandatory access label below what writing the package-manager configuration needs (found on Astra Linux, R-006) | Refuse or roll back the apply; report the context and how to rerun from the right one (a systemd service or the administrator's session); not a package error |
| `E_CHANNEL_UNCLEAR` | A release flagged stable by the provider names a pre-release in its tag or in a native version (for example the tag `10.4.0.0p1-Preview` with `prerelease: false`) | Not offered on the stable channel and never treated as stable automatically; the user waits for a stable release or chooses to follow pre-releases for this source |
| `E_SYSTEM_NAMESPACE_UNKNOWN` | The system namespace cannot be computed: the native metadata of an enabled distribution source is missing or unreadable (before the first `apt update` or `dnf makecache`, after `dnf clean all`, damaged lists) | Hold new admissions; the published generation stays as it is; `pchi doctor` names the source and the command that refreshes its metadata. Pakomichi never refreshes the native metadata itself |

`Reason` contains a human-readable reason and the corresponding source/package/release ID; sensitive information from the network and keys must not be logged.

## Wire contract v1

Each reason is transmitted as an event with an explicit schema version:

```json
{
  "schema_version": 1,
  "event": "reason",
  "reason": {
    "code": "E_REPO_ID_CHANGED",
    "object": {
      "kind": "source",
      "id": "source-1234"
    },
    "message": "repository identity changed"
  }
}
```

Version `1` allows `object.kind`: `source`, `package`, `release`, `artifact`,
`snapshot`, `operation`, `cache`, `platform`. An unknown version, an unknown
field, or an unknown enum value is rejected. `object.id` is a bounded
identifier, not a URL. The human-readable `message` is created only through a
validated type: control characters and common forms of credentials are
rejected before serialization and during deserialization. The forms are
recognized by structure, not by an individual word: assignments and headers
(`token=`, `password:`, `Authorization:`), armor lines (`-----BEGIN …`),
prefixed tokens of realistic length (`ghp_…`, `github_pat_…`, `xox…`, `AKIA…`),
and any userinfo part of a URL (`https://user@host`). Therefore names such as
`slovakia-maps` and phrases about a signing key are admissible.

The CLI displays the same reason without a separate model:

```text
[E_REPO_ID_CHANGED] source source-1234: repository identity changed
```

The prohibition of sensitive-data signatures complements sanitization at the
boundary of the network and cryptographic adapters, but does not replace it:
an arbitrary input error must not be turned directly into a `message`.

## Wire contract v2: attestation sub-reasons

Version `2` (ADR-030 point 7, ADR-031) is version 1 plus `reason.subcode`. It is
written only for `E_ATTESTATION_INVALID` with a sub-reason; every other event,
including `E_ATTESTATION_INVALID` without one, stays version 1, so a version 1
reader keeps reading them and rejects only the version 2 events. Readers of
this contract accept both versions. A version 2 event without `subcode`, a
version 1 event with one, a `subcode` with another code, and an unknown
`subcode` are rejected.

```json
{
  "schema_version": 2,
  "event": "reason",
  "reason": {
    "code": "E_ATTESTATION_INVALID",
    "object": {
      "kind": "artifact",
      "id": "artifact-1234"
    },
    "message": "attestation rejected: owner id mismatch",
    "subcode": "owner_id_mismatch"
  }
}
```

The `message` of an attestation failure is fixed text for its sub-reason;
values from the bundle or the certificate never enter it. The sub-reasons:

| Subcode | Meaning |
|---|---|
| `bundle_too_large` | A bundle is over 256 KiB |
| `too_many_bundles` | More than 16 bundles for one digest |
| `bundle_malformed` | A bundle does not parse, or its DSSE envelope does not have exactly one signature |
| `bundle_unsupported` | Not a v0.3 bundle, not DSSE, not an in-toto payload, or the library's structural rules refuse it |
| `signature_invalid` | The DSSE signature over the statement does not verify |
| `artifact_digest_mismatch` | The bytes are not a subject of the signed statement |
| `certificate_untrusted` | The certificate does not chain to the trusted root or breaks the certificate profile |
| `certificate_time` | No authority or certificate is valid at the verified time |
| `sct_invalid` | The certificate's SCT does not verify |
| `tlog_inclusion` | The transparency-log inclusion proof does not verify, or log verification is incomplete |
| `tlog_checkpoint` | The signed checkpoint does not verify |
| `tlog_promise` | The inclusion promise or the integrated time does not verify |
| `tlog_entry` | The log entry does not describe this bundle, is malformed, or comes from an unknown log |
| `timestamp_invalid` | An RFC 3161 timestamp does not verify |
| `no_verified_time` | No signing time verified at all |
| `identity_mismatch` | The certificate SAN or OIDC issuer is not the required one |
| `repository_id_mismatch` | The attested repository ID is not the pinned one |
| `owner_id_mismatch` | The attested owner ID is not a confirmed owner |
| `release_mismatch` | Another release ID, package ID, tag, or tag reference object |
| `subject_mismatch` | The asset's name is missing or carries another digest |
| `workflow_mismatch` | The signer is not the pinned workflow of the source repository |
| `ref_mismatch` | The source ref is not the expected one |
| `commit_mismatch` | The source commit is not the commit the release tag points to |
| `runner_not_hosted` | Not built on a GitHub-hosted runner |
| `statement_invalid` | The verified statement is not an in-toto Statement v1 or lacks a required field |
| `trust_root_invalid` | The trusted root itself is defective, for example without CT log keys |
