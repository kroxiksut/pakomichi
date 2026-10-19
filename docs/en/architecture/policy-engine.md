# Admission and source selection policy

**English** · [Русский](../../ru/architecture/policy-engine.md)

## Decision priority

1. **Identity:** the source repo ID/owner ID match the pinned ones; on an owner transfer, suspend.
2. **Provenance:** verifiable attestation/immutable policy and exact bytes; a contradiction → reject.
3. **Composition:** the name+artifact belong to the allowed family; an attempt to capture a system package → hold.
4. **Suitable release:** selected channel, native version, architecture, dependencies, compatibility.
5. **Conflicts:** analysis of the installed state and the available OS sources (not only a comparison of version numbers).
6. **Feasibility in the native package manager:** if the selected policy cannot be expressed → observing/hold, without a false `preferred`.
7. **Publication:** only allow → signed snapshot.

## Base source modes

- `observing`: information only; we publish nothing.
- `supplemental`: system sources are preferred; the Git package is used when the policy and native resolution allow it.
- `preferred`: explicit user consent and a confirmed native policy, only for allowed names; no change of any other vendor by default.
- `suspended`: conflict/error; do not publish new untrusted material.

## Main conflict

APT selects a version by priorities **but does not guarantee the selection of a specific instance of the same version** from two sources. Therefore, the same version with different bytes is `E_SOURCE_AMBIGUOUS`; an ordinary pin does not solve the problem. DNF also requires independent trials (`R-001`).

## Must not

- Pretend that the local preference DB affects a standalone `apt upgrade`.
- Change third-party repositories/the order of their files to silently win on priority.
- Add `glibc`, `openssl`, `python3` from Git and hide this operation inside an allowed family.
- Automatically roll back to a lower version or switch stable → prerelease.

## Decision vs transaction

`eligible` means that a correct candidate version has been published according to the current inventory snapshot. It is **not the same as** a guarantee that any future `apt upgrade` is safe. Evidence of the selection/plan is provided in the adapter tests; the limitations remain visible.
