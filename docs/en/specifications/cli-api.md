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
pchi status [--json]
pchi diagnose [--json]
pchi cache status
```

The full form replaces only the entry-point name: `pakomichi source list` is equivalent to `pchi source list`. The way the two entry points are delivered (for example, an alias, a symlink, or a separate launcher) is chosen when the package is implemented, but it must not create two diverging CLI implementations.

`add` by itself does not activate a package. Do not use `--yes` to confirm a repo owner transfer, a publisher change, or an ambiguity. Activation requires administrator privileges and prints the original and resulting plan of files/sources.

**Status API (read-only):** list of sources, identity, mode, last_successful_sync, trusted snapshot age, list of installed/admissible versions, held reasons, build variant/confidence, app/package statuses. The JSON response contains `schema_version`, machine-readable `state`, `reason_code`.

The API must not provide `install`, `upgrade`, `change source`, `add repo`, `import key` commands. Applications may show the user an available update, but installation is performed by the native package manager.

**Errors:** for details see `errors.md`. Output contains no secrets/tokens. Do not introduce a false "package is protected" message if only a SHA match has been verified.
