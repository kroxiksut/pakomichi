# Admission and source selection policy

**English** · [Русский](../../ru/architecture/policy-engine.md)

## Decision priority

1. **Identity:** the source repo ID/owner ID match the pinned ones; on an owner transfer, suspend.
2. **Provenance:** verifiable attestation/immutable policy and exact bytes; a contradiction → reject. A release with weaker evidence than the source's trust floor → hold with `E_EVIDENCE_DOWNGRADE`; a Pinned release without the administrator's approval of its exact digests → hold with `E_RELEASE_APPROVAL_REQUIRED` (ADR-027).
3. **Composition:** the name+artifact belong to the allowed family; an attempt to capture a system package → hold. An artifact is held with `E_SYSTEM_PACKAGE_CONFLICT` when any of its `Provides`, or any `Obsoletes`/`Replaces` whatever its version constraint, names a member of the system namespace (ADR-022 point 2). The native managers do not perform this check, so admission does.
4. **Suitable release:** selected channel, native version, architecture, dependencies, compatibility.
5. **Conflicts:** analysis of the installed state and the available OS sources (not only a comparison of version numbers).
6. **Feasibility in the native package manager:** if the selected policy cannot be expressed → observing/hold, without a false `preferred`.
7. **Publication:** only allow → signed snapshot.

## Base source modes

- `observing`: information only; we publish nothing.
- `supplemental`: system sources are preferred; the Git package is used when the policy and native resolution allow it. A name installed from, or available in, another enabled source is not activated in this mode.
- `preferred`: explicit user consent and a confirmed native policy, only for allowed names; no change of any other vendor by default. Taking over a name from another source is an explicit migration (ADR-012, E2E-04). A Pinned source never uses this mode (ADR-027).
- `suspended`: conflict/error; do not publish new untrusted material.

## Main conflict

APT selects a version by priorities **but does not guarantee the selection of a specific instance of the same version** from two sources. Therefore, the same version with different bytes is `E_SOURCE_AMBIGUOUS` on every platform; neither APT 2.8+ pins nor DNF priority are accepted as a substitute (R-001, ADR-022 point 1).

## No implicit publisher change (ADR-022)

R-001 showed that an ordinary upgrade on every tested manager changes the publisher when another enabled source offers a higher version of the same name. For every activated name, including every member of the activated family:

- **APT:** `Pin-Priority: 990` for the activated names, matched by `Pin: release o=…,l=…` of the source's logical repository; never `Pin: origin` (one loopback host serves all repositories) and never 1000 or higher (that allows downgrades).
- **DNF:** a repository priority better than the distribution repositories, with `includepkgs` limited to the activated names. `allow_vendor_change` is read and reported, never written or relied upon; `excludepkgs` is never written into other repositories.
- **Later updates from another source**, including distribution security updates, do not change the publisher. `pchi status`, `pchi doctor`, and the status API show a prominent notice naming the other source and version; switching remains an explicit user decision.

The protection is shown under the ordinary update command of each distribution: `apt upgrade`/`apt full-upgrade` on Debian and Ubuntu, `apt-get dist-upgrade` on Astra Linux, `dnf upgrade` on DNF platforms. Every rule is verified on every supported distribution build, not inferred from the manager's version: RED OS differs from upstream DNF in `reinstall`, defaults, and options.

## Astra Linux closed software environment (ADR-025)

While the closed software environment is on (or cannot be ruled out), Pakomichi refuses to activate sources and holds every artifact with `E_EXECUTION_POLICY` instead of offering it as an update; the hold does not depend on the artifact's content.

## Must not

- Pretend that the local preference DB affects a standalone `apt upgrade`.
- Change third-party repositories/the order of their files to silently win on priority.
- Add `glibc`, `openssl`, `python3` from Git and hide this operation inside an allowed family.
- Automatically roll back to a lower version or switch stable → prerelease.
- Require `APT::Get::EnableUpgrade` or any other change of the distribution's APT or DNF policy.
- Judge source health by the exit status of `apt-get update` (it exits 0 when a source is offline); use Pakomichi's own state instead (ADR-022 point 6).

## Decision vs transaction

`eligible` means that a correct candidate version has been published according to the current inventory snapshot. It is **not the same as** a guarantee that any future `apt upgrade` is safe. Evidence of the selection/plan is provided in the adapter tests; the limitations remain visible.
