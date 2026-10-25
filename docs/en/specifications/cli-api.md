# Proposed CLI and read-only API

**English** · [Русский](../../ru/specifications/cli-api.md)

**Command names approved by the project owner:** the primary short command is `pchi`, the full command is `pakomichi`. Both entry points provide the same CLI, set of arguments, exit codes, and output semantics. Documentation and interactive examples use `pchi` by default. The conflicting name `gitbridge` must not be used.

```text
pchi source add <https-git-url> [--observe] [--workflow <path> --ref tag|refs/heads/<name>]
pchi source list
pchi source inspect <id>
pchi source activate <id> --packages <comma-list> [--policy supplemental|preferred]
pchi source suspend <id>
pchi source remove <id>  # does not remove programs
pchi sync [<id>] [--force]
pchi source allow-pinned <id>  # Pinned consent for one source (ADR-027)
pchi release approve <source-id> <release-id>  # Pinned: approve one release
pchi status [--json]
pchi doctor [--json] [--repair]
pchi cache status
```

The full form replaces only the entry-point name: `pakomichi source list` is equivalent to `pchi source list`. The way the two entry points are delivered (for example, an alias, a symlink, or a separate launcher) is chosen when the package is implemented, but it must not create two diverging CLI implementations.

`add` by itself does not activate a package. Do not use `--yes` to confirm a repo owner transfer, a publisher change, an ambiguity, Pinned consent, or the approval of a Pinned release. Activation requires administrator privileges and prints the original and resulting plan of files/sources.

**Attested signer** (ADR-036 point 1): `source add` looks for the workflow that signs the provenance of the latest release and shows it in the plan; the confirmation stores it with the source. `--workflow` and `--ref` (`tag` for the release tag, or `refs/heads/<name>`) set it explicitly and must agree with what discovery finds. Two different signers refuse the plan. A source without a signer works at Strict and Pinned.

**Family** (ADR-036 point 3): the plan of `source activate` shows the family revision, every name and architecture the source offers, and the names to activate; the confirmation approves the listed names into the next revision. A name the source never offered is refused; a source that was never synchronized is refused with a message to run `pchi sync <id>` first.

**`pchi doctor`** (ADR-021, ADR-022, ADR-024, ADR-025) diagnoses without changing anything: the health of the socket and service units (a socket in `failed` or `service-start-limit-hit` is reported as an outage of the Pakomichi repositories, with the recovery command), the last confirmed synchronization and the age of the served generation per source (`E_SOURCE_STALE`), updates of an activated name offered by another source, the Astra Linux security level, and the name of every failing Pakomichi repository. The exit status of `apt-get update` is never used as a health signal. `--repair` performs only the documented socket recovery (`systemctl reset-failed` for the units, then starting the socket); it requires administrator privileges and an explicit interactive confirmation, does not accept `--yes`, and is never offered through the status API or the loopback HTTP endpoint.

**Pinned level** (ADR-027): `source allow-pinned` names the risk (a compromised publisher account, token, or CI can publish a malicious release that Pakomichi cannot detect) and records consent for that source only; `release approve` shows the release and the exact digests of its artifacts and approves only those digests. Both are administrative, interactive, and refuse `--yes`. A Pinned source can be activated only with `--policy supplemental`. The command names were approved by the project owner on 2026-10-21.

**Status API (read-only):** list of sources, identity, mode, provenance level and trust floor, last_successful_sync, trusted snapshot age, list of installed/admissible versions, held reasons (including `E_EVIDENCE_DOWNGRADE` and `E_RELEASE_APPROVAL_REQUIRED`), updates of activated names offered by another source, build variant/confidence, app/package statuses. The JSON response contains `schema_version`, machine-readable `state`, `reason_code`. The status API never accepts consent, approval, or recovery.

The API must not provide `install`, `upgrade`, `change source`, `add repo`, `import key` commands. Applications may show the user an available update, but installation is performed by the native package manager.

**Errors:** for details see `errors.md`. Output contains no secrets/tokens. Do not introduce a false "package is protected" message if only a SHA match has been verified.

## Implementation (P4-001a)

One implementation serves both entry points: `src/cli`, called by the `pchi` and `pakomichi` binaries. Read-only commands (`status`, `source list`, `source inspect`) use `status.sock`; administrative ones (`source add`, `source activate`, `sync`, `doctor --repair`) use `admin.sock` and therefore need root.

- **Confirmation:** the CLI asks the server for the plan, prints its summary and every change (kind, target, digest before and after, and the reason codes of the risks), and applies it only after the administrator types `yes` at a terminal. Without a terminal it changes nothing. No command accepts `--yes` or any other way to confirm from its arguments; the plan digest binds the action and its arguments (ADR-029 point 8, ADR-033 point 5).
- **Exit status:** `0` done; `1` refused by the server, or the operation failed; `2` a usage error; `3` not confirmed, or no terminal to confirm at (nothing was changed); `4` the service did not answer.
- **Defaults:** `source activate` without `--policy` asks for `supplemental`, never `preferred`.
- `PAKOMICHI_RUNTIME_DIR` points the CLI at another socket directory for a test bed; packages never set it.
- **Signer discovery:** `source add` asks GitHub for the latest release, the commit of its tag, and the attestations of at most 20 uploaded assets that carry an API digest, each by the pinned repository ID. An asset without a digest is skipped, because its attestations cannot be looked up without downloading it. The state owner verifies with trusted roots refreshed through TUF at start (`pakomichi-state --tuf-cache DIR`); without them the plan says that nothing was checked and the source gets no signer unless one is named.
- **Synchronization** (`sync`, and every activation): identity by repository ID; every listed release, oldest first, so the trust floor rises as the releases did; assets for the target fetched into the CAS and inspected by the isolated inspector; Strict or Attested evidence of the exact bytes; the family (proposed on the first synchronization, a name outside it recorded as seen and held with `E_FAMILY_UNAPPROVED`); system namespace, compatibility, and the decision core, each decision logged; a signed generation per level for the activated names; then the APT configuration of every source through the root applier. The activation journal follows only a verified apply, and so does the source state: `active` while the verified configuration pins at least one of its names, back to `registered` when none is left; an observed or suspended source keeps its state. An error talking to GitHub, the inspector, or the publisher stops that source's pass and fails the operation; what was published before stays, and the other sources still run.
- `source activate` and `sync` need `pakomichi-state` started with the pipeline arguments (`--publish-root`, `--sign-socket`, `--inspect-socket`, `--apply-socket`, `--keyring`, `--key-fingerprint`, and `--loopback-port`); without them they are refused. `doctor --repair` is refused in this build.
