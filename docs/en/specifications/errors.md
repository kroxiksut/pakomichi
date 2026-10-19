# Machine-readable reason and error codes

**English** · [Русский](../../ru/specifications/errors.md)

| Code | Meaning | Behavior |
|---|---|---|
| `E_REPO_ID_CHANGED` | The URL resolves to a different persistent repo ID | Suspend, do not follow |
| `E_OWNER_TRANSFER` | The owner has changed | Suspend until confirmation |
| `E_ASSET_MUTATED` | An already accepted artifact has changed | Reject the new copy, do not rebind the digest |
| `E_ATTESTATION_INVALID` | Verification of the provenance evidence failed | Reject |
| `E_SIGNATURE_POLICY` | The system policy requires an RPM signature that is unavailable | Hold |
| `E_FAMILY_UNAPPROVED` | A new package name outside the admitted package family | Hold |
| `E_SYSTEM_PACKAGE_CONFLICT` | An attempt to displace a system package/critical `Provides` | Hold |
| `E_SOURCE_AMBIGUOUS` | The same version from sources with different bytes | Observing/hold |
| `E_DEPENDENCY_UNSATISFIABLE` | Required dependencies are missing | Hold |
| `E_PLATFORM_UNSUPPORTED` | The format/arch/ABI is clearly unsuitable | Hold |
| `E_SNAPSHOT_INCONSISTENT` | The snapshot's index/reference/signature diverges | Do not publish |
| `E_CACHE_DIGEST_MISMATCH` | Cache bytes do not match the accepted SHA | Do not serve |
| `E_SOURCE_STALE` | The data has exceeded the permissible freshness | Error of our source |
| `E_FORGE_UNAVAILABLE` | Git is unavailable | Verified cache according to policy |
| `E_ADMIN_APPLY_FAILED` | Incomplete write of the local configuration | Rollback/reconcile |
| `E_DISK_EXHAUSTED` | The snapshot/download cannot be completed | Refuse the new publication, do not change the old snapshot |

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
