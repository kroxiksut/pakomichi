# Proposed CLI and read-only API

**English** · [Русский](../../ru/specifications/cli-api.md)

**Command names approved by the project owner:** the primary short command is `pchi`, the full command is `pakomichi`. Both entry points provide the same CLI, set of arguments, exit codes, and output semantics. Documentation and interactive examples use `pchi` by default. The conflicting name `gitbridge` must not be used.

```text
pchi source add <https-git-url> [--observe]
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

**`pchi doctor`** (ADR-021, ADR-022, ADR-024, ADR-025) diagnoses without changing anything: the health of the socket and service units (a socket in `failed` or `service-start-limit-hit` is reported as an outage of the Pakomichi repositories, with the recovery command), the last confirmed synchronization and the age of the served generation per source (`E_SOURCE_STALE`), updates of an activated name offered by another source, the Astra Linux security level, and the name of every failing Pakomichi repository. The exit status of `apt-get update` is never used as a health signal. `--repair` performs only the documented socket recovery (`systemctl reset-failed` for the units, then starting the socket); it requires administrator privileges and an explicit interactive confirmation, does not accept `--yes`, and is never offered through the status API or the loopback HTTP endpoint.

**Pinned level** (ADR-027): `source allow-pinned` names the risk (a compromised publisher account, token, or CI can publish a malicious release that Pakomichi cannot detect) and records consent for that source only; `release approve` shows the release and the exact digests of its artifacts and approves only those digests. Both are administrative, interactive, and refuse `--yes`. A Pinned source can be activated only with `--policy supplemental`. The command names were approved by the project owner on 2026-10-21.

**Status API (read-only):** list of sources, identity, mode, provenance level and trust floor, last_successful_sync, trusted snapshot age, list of installed/admissible versions, held reasons (including `E_EVIDENCE_DOWNGRADE` and `E_RELEASE_APPROVAL_REQUIRED`), updates of activated names offered by another source, build variant/confidence, app/package statuses. The JSON response contains `schema_version`, machine-readable `state`, `reason_code`. The status API never accepts consent, approval, or recovery.

The API must not provide `install`, `upgrade`, `change source`, `add repo`, `import key` commands. Applications may show the user an available update, but installation is performed by the native package manager.

**Errors:** for details see `errors.md`. Output contains no secrets/tokens. Do not introduce a false "package is protected" message if only a SHA match has been verified.
