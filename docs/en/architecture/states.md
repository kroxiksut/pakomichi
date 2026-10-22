# State and transition model

**English** · [Русский](../../ru/architecture/states.md)

## Source

`discovered` → `registered` → `observing` → `active` → `suspended` / `disabled`; from `suspended` to `active` only after the cause has been eliminated and re-verification has passed. `disabled` does not delete the `ForgeRepository` until an explicit deletion operation is performed.

| Event | Before | After | Rule |
|---|---|---|---|
| `source add` | absent | discovered/registered | Pin the repository ID and owner |
| detection of a conflicting system package | registered | observing | Do not change the vendor |
| explicit consent + successful simulation | observing | active | Apply only our policy files |
| a different repo ID at the old URL | any active | suspended | No automatic relink |
| owner change with the same ID | active | suspended | Explicit confirmation is required |
| invalid attestation | active | suspended or exclusion of the specific release | Depending on the scope of the violation; do not erase confirmed history |
| selected package is no longer available | active | observing/suspended package | Do not switch to a fork |
| network temporarily unavailable | active | active + stale status | Use the last trusted snapshot only according to the freshness policy |
| maximum freshness reached (DNF) | active | active + `E_SOURCE_STALE` | Publish a signed empty generation; installed packages stay; a successful `sync` restores the offer (ADR-024) |
| explicit Pinned consent | registered/observing | observing | Only `supplemental` may follow; every release still needs approval (ADR-027) |
| closed software environment on (Astra Linux) | any | observing (activation refused) | Hold every artifact with `E_EXECUTION_POLICY` (ADR-025) |
| user removed the source | any | disabled/deleted | Applications remain installed; the source's repository files are deleted |

## Version / artifact

`discovered → candidate → verified → eligible → published → retired`. Branches: `held` (conflict/compatibility, evidence below the trust floor `E_EVIDENCE_DOWNGRADE`, a Pinned release awaiting approval `E_RELEASE_APPROVAL_REQUIRED`), `rejected` (trust/substitution), `revoked` (explicit block). `verified` ≠ `eligible`: the source file is genuine but may be incompatible. For a Pinned source, `verified` means that the administrator approved the exact digest, not that a cryptographic check passed.

The trust floor of a source (`pinned` < `attested` < `strict`) only rises; lowering it is refused (ADR-027).

## Snapshots

`building → signed → verified → staged → published → retired → collected`. `failed` from any state before published; a published snapshot is **not modified**. Generation IDs are monotonic and never reused, and `current` never moves back to an older generation. A retired generation stays reachable at least for the maximum freshness (DNF) or its `Valid-Until` (APT) plus a safety margin; collection is by reachability plus this window, never by generation count alone (ADR-024). RPM generations switch at most once per regular check interval, except on `sync --force` and for the empty generation after maximum freshness.

## Installed state

Pakomichi **observes** APT/dpkg or DNF/rpm; it is not the only registry of installed packages. Discrepancies set `external_change_detected` and do not lead to an autonomous reinstallation.

## Errors

The machine-readable codes listed in `docs/en/specifications/errors.md` are mandatory, together with a human-readable reason: what happened, which file/package is affected, whether it is possible to continue, and whether an administrator's choice is required.
