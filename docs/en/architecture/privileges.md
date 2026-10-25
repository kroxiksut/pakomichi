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
| Admin applier | root/restricted helper | Modify **only our** repo/prefs/keyring files; change log; on Astra Linux with integrity control, integrity level 63 (a systemd service or the administrator's session) |
| Read-only API | local socket | No `apt install` commands, no key or source changes, no Pinned consent or release approval, no socket recovery |

Protect against path traversal, SSRF, symlink races, zip bombs, and disk/memory exhaustion; do not trust a `source`/`asset` name as a filesystem path. The audit log contains no tokens, keys, or bearer headers.

Administrative actions — activation, migration, Pinned consent and the approval of a Pinned release (ADR-027), socket recovery by `pchi doctor --repair` (ADR-021), importing a publisher key — need administrator privileges and an explicit interactive confirmation; they are never reachable through the status API or the loopback HTTP endpoint, and never through `--yes`.

On Astra Linux with mandatory integrity control, systemd starts Pakomichi's services at level 63, so ADR-009 privilege separation remains the boundary. An apply started from a lower integrity level fails to write `/etc/apt` and `/var/lib/dpkg`; it is reported as an integrity-level problem (`E_SECURITY_CONTEXT`), not as a package error (ADR-025, R-006). The APT lists and cache are writable from level 0 and are never trusted input.

The loopback port is free while the socket is down (for example after a crash loop). Binding it on a privileged port through systemd is to be tested before the port is chosen (ADR-024 point 6); until then the health check of `pchi doctor` is the only mitigation.

Global control of APT/DNF transactions is absent in 0.1. Running in a VM is mandatory for trials that install conflicting/dangerous packages. A root compromise of the entire OS is outside Pakomichi's guarantees.

## Local IPC

The IPC library (`src/ipc`, P2-013) implements ADR-029:

- **Frames:** 4-byte big-endian length plus UTF-8 JSON; an empty frame, a length over 1 MiB (request) or 8 MiB (response), a truncated frame, or invalid UTF-8 closes the connection before anything is parsed.
- **Messages:** `schema_version` 1 and `type`; every wire type rejects unknown fields, and `confirmed` has no default. An unknown version is answered with the supported versions; any other refusal says that nothing was applied. The exact JSON of every request and response variant is pinned by a test.
- **Channels:** `StatusRequest` (ping, status, operation) and `AdminRequest` (adds plan and confirm) are separate types, so a plan or a confirmation on `status.sock` does not parse. `SO_PEERCRED` is read with `nix` (`std`'s `peer_cred` is unstable and the workspace denies unsafe code) and checked against the channel's peer rule before the first frame; a refusal closes the connection without a response.
- **Limits:** first frame within 5 s, idle connections closed after 30 s, at most 8 connections per uid and 64 in total on the status channel, 4 on the administrative one; over the limit the connection is closed at once.
- **Work:** `ping` and status are answered by the connection's own thread; a confirmed action runs as an operation on one worker thread, and its 128-bit identifier from `/dev/urandom` is bound to the caller's uid (an unknown and a foreign identifier get the same answer). A confirmation must repeat the digest of the plan the server returned and is refused when the server's current plan differs.
- **Closing:** the response is flushed, the write side is shut down, then the socket is closed.

Not yet implemented: the `status.sock` and `admin.sock` channels of the state owner (with P4-001a). The sockets come from systemd, the signer, inspector, and applier run as `Accept=yes` instances (ADR-035, P4-003a), and every process checks its privileges at start.

## Package inspector boundary (DEB)

The inspector (`src/inspect/`) reads native metadata from an untrusted package and never installs it, unpacks its payload, or runs a maintainer script. It runs only on Linux, in the disposable unprivileged inspector process of ADR-017, and refuses effective UID 0; the override exists for tests only.

What runs:

1. In-process, from a file opened with `O_NOFOLLOW` that must be a regular file: the size limit, then the outer `ar` container — member order, the `debian-binary` major version `2`, the control and data member names (and so their compression), the compressed control member size, and the end of every member within the file. A truncated or reordered archive, another format version, or an oversized control member is rejected before any decompression.
2. A child process, without a shell: `prlimit --cpu --as --fsize=0 --core=0 --nofile -- dpkg-deb --ctrl-tarfile /proc/self/fd/0`. Both tools come from `/usr/bin` or `/bin` only. The package is the child's standard input, so `dpkg-deb` reads the file that step 1 checked. The environment contains only `PATH=/usr/bin:/bin` and `LC_ALL=C`; the working directory is `/`. The parent enforces a wall-clock timeout and caps for the decompressed stream and for diagnostics, and kills the child when one is exceeded. Without `prlimit` the inspector refuses to run unless the configuration explicitly allows it.
3. In memory: a minimal tar reader lists the control archive and copies out `control`; a strict deb822 parser reads the paragraph (UTF-8 only, no control characters, no duplicate fields, size and count limits). Duplicate or non-regular `control` entries, absolute names, and `..` components are rejected rather than resolved.

What never runs: `dpkg`, `dpkg-deb --extract`/`--install`/`--control`, `tar -x`, a maintainer script (`preinst`, `postinst`, `prerm`, `postrm`, `config`; only their presence is reported), or anything that writes to the dpkg database. The inspector writes nothing to disk, and `RLIMIT_FSIZE=0` keeps the child from writing file data.

Every rejection of package bytes maps to `E_ARTIFACT_MALFORMED` (ADR-028); the one exception is a `dpkg-deb` refusal of a member compression that this system's `dpkg` does not support (a well-formed package only this native tool cannot read), which maps to `E_PLATFORM_UNSUPPORTED`. Root, a missing tool, a timeout, a signal, and local I/O errors have no reason code and admit nothing. Process-level isolation beyond these limits (a dedicated user, a systemd sandbox, seccomp) is a deployment concern of the inspector unit.

## Package inspector boundary (RPM)

The RPM side of the inspector has the same deployment and the same guards: Linux only, the disposable unprivileged inspector process, refusal of effective UID 0 (the override is for tests only), a file opened with `O_NOFOLLOW` that must be a regular file, and the package size limit. It runs no native tool: the headers are parsed in-process with the `rpm` crate (`=0.30.2`, default features disabled, so no payload, decompression, or signature code is linked; ADR-017).

What runs, in order, reading the file sequentially and stopping at the payload:

1. The 96-byte lead: the RPM magic (otherwise the file is not an RPM, which covers an empty file and a DEB), major version 3 or 4, and signature type 5 (header signature).
2. The signature header, its 8-byte alignment padding, and the main header. For each header the 16-byte intro is checked first: the header magic and version, at least one index entry, and the declared entry count and data size against the configured limits, which are themselves capped at librpm's bounds (signature header: 32 entries, 64 MiB; main header: 65535 entries, 256 MiB; the default main-header data limit is 64 MiB). The declared size must also fit in the rest of the file, so nothing is allocated for bytes the file does not hold.
3. Every index entry, before the crate sees it: a known data type, a non-negative offset inside the data store, natural alignment for integers, data that ends inside the store, a count of one for a string, NUL-terminated strings, and no repeated tag. The crate indexes the store without bounds checks; this step is what keeps malformed input from making it panic or exhaust memory.
4. The crate parses the checked bytes. The reader then requires `Name`, `Version`, `Release`, and `Arch` (rpmbuild character sets without macro characters, no `-` in version or release, at most 256 bytes), accepts an optional single `Epoch`, and checks that the name, flag, and version arrays of each relationship kind have equal lengths. `RPMSIGTAG_LONGSIZE`/`RPMSIGTAG_SIZE`, when present, must equal the size of the main header plus the payload, which rejects a truncated or extended file without reading the payload.

What it reports: name, epoch, version, release, architecture, source or binary package, `RPMTAG_RPMFORMAT`, installed size; `Requires`, `Provides`, `Conflicts`, `Obsoletes`, and the weak `Recommends`, `Suggests`, `Supplements`, `Enhances` as raw name, `RPMSENSE_*` flags, and version (resolving them belongs to the family model); the presence of `%pre`, `%post`, `%preun`, `%postun`, `%pretrans`, `%posttrans`, `%preuntrans`, `%postuntrans`, `%verifyscript`, triggers, file triggers, and transaction file triggers (a script tag or an interpreter-only tag counts); the payload format, compressor, and flags tags as written (librpm reads an absent compressor tag as gzip); and which signature tags (`DSA`, `RSA`, `OPENPGP`, legacy `PGP`/`GPG`/`PGP5`) and digest tags are present.

What never runs: a scriptlet or trigger, payload reading or decompression, `rpm`, `rpmkeys`, `rpm2cpio`, or any access to an rpmdb. Signatures and digests are reported, not verified: verification belongs to native RPM/DNF policy (R-002), so a present signature tag is not evidence that a package is trusted. The reader writes nothing to disk.

Rejections of package bytes (not an RPM, a malformed or truncated lead or header, a header over the limits, a missing or invalid identity tag, mismatched relationship arrays, an unsupported lead) map to `E_ARTIFACT_MALFORMED`, as on the DEB side; root and local I/O errors have no reason code and admit nothing. A panic in the third-party parser would end the disposable inspector process, which also admits nothing.

## Process layout (ADR-035)

- **Processes and users:** `pakomichi-state` (user `pakomichi`: state database, CAS writer, GitHub network), `pakomichi-reader` (user `pakomichi-reader`, read-only, group `pakomichi`), `pakomichi-signer` (user `pakomichi-signer`, the only reader of the metadata key in `/var/lib/pakomichi-signer`, mode 0700), `pakomichi-inspector` (`DynamicUser=yes`, no network, read-only file system, group `pakomichi` to read CAS objects). Each refuses to run as root before it reads anything else; the signer also refuses a key directory that is not its own or that group or others can enter.
- **Channels:** `sign.sock` and `inspect.sock` (0600, `pakomichi`) start one `Accept=yes` instance per connection, whose standard input and output are the connection; `fetch.sock` (0600, `pakomichi-reader`) is served by the state owner. Every server admits only the uid that owns its socket file, checked from `SO_PEERCRED` before the first frame; root gets no answer. One request per connection (`ipc::oneshot`).
- **Root applier:** `pakomichi-applier` (P4-003a) is one `Accept=yes` instance of `apply.sock` (0600, the state owner's user) per apply. It refuses to run unless it is root, admits only the uid that owns the socket file and refuses a socket owned by root, and takes an exclusive lock so two instances never write the same files. Its unit gives root no capabilities, no network, and a read-only file system except `/etc/apt/sources.list.d`, `/etc/apt/preferences.d`, `/etc/apt/keyrings`, and `/run/pakomichi` (those directories must exist before the unit starts). It renders the files from the desired configuration itself and refuses a recorded path that is not one of Pakomichi's (`delivery-recovery.md`).
- **Answers are read back:** the state owner re-validates an inspection with the parser's own rules (the control paragraph is rendered and parsed again; the maintainer scripts must follow from the control members), and checks a signature with `gpgv` as before.
- **Verified on Debian 12 with the real units** (`research/p2-013b/`, `results/debian12.tsv`). The root applier behind `apply.sock`: Debian 12, Debian 13, and Ubuntu 24.04, 15 of 15 scenarios each (`research/p4-003a/`, `results/*.tsv`), with a `systemd-analyze security` exposure of 2.7; Astra Linux 1.8.6 `smolensk` with integrity control on (`results/astra186-smolensk-mic.tsv`): the unit at level 63 applies, and the applier started at level 0 answers `E_SECURITY_CONTEXT` with `/etc/apt` unchanged (N-036). The status and administrative channels of the state owner are not part of this yet.