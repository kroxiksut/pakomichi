# OS security boundaries

**English** · [Русский](../../ru/architecture/privileges.md)

| Component | Privileges | Restriction |
|---|---|---|
| Forge network client | user/unprivileged | Only outgoing requests to the selected platform and to verified asset URLs |
| Package inspector | sandbox/unprivileged | Do not execute `postinst` or rpm scripts; file/resource limits |
| Attestation verification | unprivileged | Cryptography and pinned IDs |
| Blob store | separate system user | Prevent file substitution by another user; content hash check |
| Local HTTP | unprivileged, loopback | Only GET/HEAD, no administrative requests |
| Signer | minimal access rights to the private key | Sign only an approved Snapshot |
| Admin applier | root/restricted helper | Modify **only our** repo/prefs/keyring files; change log |
| Read-only API | local socket | No `apt install` commands, no key or source changes |

Protect against path traversal, SSRF, symlink races, zip bombs, and disk/memory exhaustion; do not trust a `source`/`asset` name as a filesystem path. The audit log contains no tokens, keys, or bearer headers.

Global control of APT/DNF transactions is absent in 0.1. Running in a VM is mandatory for trials that install conflicting/dangerous packages. A root compromise of the entire OS is outside Pakomichi's guarantees.
