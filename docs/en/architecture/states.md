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
| user removed the source | any | disabled/deleted | Applications remain installed |

## Version / artifact

`discovered → candidate → verified → eligible → published → retired`. Branches: `held` (conflict/compatibility), `rejected` (trust/substitution), `revoked` (explicit block). `verified` ≠ `eligible`: the source file is genuine but may be incompatible.

## Snapshots

`building → signed → verified → staged → published → retired → collected`. `failed` from any state before published; a published snapshot is **not modified**. We keep old snapshots while requests exist or until the period of safe reference availability has expired.

## Installed state

Pakomichi **observes** APT/dpkg or DNF/rpm; it is not the only registry of installed packages. Discrepancies set `external_change_detected` and do not lead to an autonomous reinstallation.

## Errors

The machine-readable codes listed in `docs/en/specifications/errors.md` are mandatory, together with a human-readable reason: what happened, which file/package is affected, whether it is possible to continue, and whether an administrator's choice is required.
