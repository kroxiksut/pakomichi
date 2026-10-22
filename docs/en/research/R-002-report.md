# R-002 report — RPM signatures, signed repodata, and Attested

**English** · [Русский](../../ru/research/R-002-report.md)

- **Date / performed by:** 2026-10-20, programming agent at the project owner's request; protocol: [R-002](R-002-rpm-signatures.md).
- **Outcome:** **PASS** against the R-002 criterion on the tested DNF4 and DNF5 versions. An unsigned RPM was accepted only in the explicit modeled-Attested cell, after exact-byte verification and with package checking disabled for that test repository. The same bytes were rejected when native policy required an embedded RPM signature.
- **Not proven:** other distribution builds, production GitHub attestations, production key custody, or recovery on an installed system. The attestation verifier and all keys are laboratory fixtures. These results constrain ADR-006 and P1-005; they do not implement them.

## Environments and isolation

Every target was a fresh WSL2 import of the digest-pinned image already cached by R-001. The Windows host, its repositories, the owner's Ubuntu distribution, and other research distributions were not modified.

| Platform | Pinned image | Package stack | Baseline effective policy |
|---|---|---|---|
| AlmaLinux 9.8 | `almalinux:9`, manifest `sha256:dc973f4d…`, layer `sha256:b4183c2…` | DNF 4.14.0, RPM 4.16.1.3 | `gpgcheck=1`, `repo_gpgcheck=0`, `localpkg_gpgcheck=0`, `%_pkgverify_level=digest`; `pkg_gpgcheck` and `gpgcheck_policy` unsupported |
| Fedora 44 | `fedora:44`, manifest `sha256:be9d65e2…`, layer `sha256:59259e16…` | DNF5 5.4.3.0, RPM 6.0.2 | `gpgcheck=1`, `pkg_gpgcheck=1`, `repo_gpgcheck=0`, `localpkg_gpgcheck=0`, `gpgcheck_policy=legacy`, `%_pkgverify_level=digest` |

Both targets used the WSL2 `6.18.40.1-microsoft-standard-WSL2` kernel. Repository metadata was served on target loopback only. Distribution repositories were used solely to install test tools; every matrix operation used an isolated `reposdir` containing only R-002. Raw commands and output remain in ignored `.research-local/r-002/runs/`; sanitized results are in `research/r-002/results/`.

**Limitation:** the targets share the host kernel and network namespace. This is sufficient for package-manager verification decisions, but not evidence for boot, systemd, SELinux, protected-mode, or power-loss behavior.

## Fixtures

The AlmaLinux 9 R-001 builder produced all fixtures from one specification:

- `signed.rpm` and `unsigned.rpm` have the same payload digest (`7c210c52…`) but different full-file hashes; the first has an RSA/SHA-256 RPM v4 header signature and the second has none;
- `corrupted.rpm` differs in a signature byte and is reported `BAD` after the public key is imported;
- `attested.rpm` is byte-identical to `unsigned.rpm`; its modeled attestation binds exact SHA-256 `fe920655…`;
- `unconfirmed.rpm` has different bytes and payload, so it cannot accidentally reuse that attestation;
- no fixture has scriptlets.

The repository builder generated valid and invalid detached signatures for `repomd.xml`, a repository whose RPM was replaced after metadata generation, and metadata-key A/B rotation repositories. `metadata-signer-invariance.tsv` proves that signing or re-signing metadata did not modify the RPM: all four repository copies equal `signed.rpm` at SHA-256 `dc7fa40b…`.

## Reproduction

```powershell
powershell -NoProfile -File research/r-002/run-build.ps1
powershell -NoProfile -File research/r-002/run-target.ps1 -Platform alma9
powershell -NoProfile -File research/r-002/run-target.ps1 -Platform fedora44
python -I research/r-002/validate-results.py research/r-002/results --platform alma9 --platform fedora44
```

The builder and targets are stopped or unregistered in `finally` blocks. Test private keys, packages, repository trees, and raw logs stay under ignored `.research-local/r-002/`.

## Results

Both platforms produced the same verdicts in all 12 cells:

| Cell | DNF4 | DNF5 | Confirmed property |
|---|---:|---:|---|
| Valid RPM signature + valid signed metadata, required policy | allow | allow | A trusted embedded signature is installable. |
| Unsigned RPM + valid signed metadata, required policy | block | block | Signed metadata does not replace the package signature. |
| Modeled-Attested unsigned RPM, explicit permitted mode | allow | allow | An exact-byte, per-source exception can be represented where OS policy permits it. |
| Same Attested RPM, required policy | block | block | Attestation does not weaken mandatory native signature policy. |
| Different, unconfirmed unsigned RPM | block before DNF | block before DNF | The adapter creates no exception after attestation mismatch. |
| Corrupted embedded signature | block | block | Signature corruption fails closed. |
| Invalid `repomd.xml.asc` | block | block | Metadata authentication is independent and required. |
| RPM replaced after metadata generation | block | block | Repository hashes bind package bytes. |
| Request for global `gpgcheck=0` | refused, exit 64 | refused, exit 64 | DNF is not invoked for a global-disable request. |
| Metadata key A trusted | allow metadata | allow metadata | Baseline key works. |
| Metadata key B before trust | block | block | Rotation does not silently trust a new key. |
| Metadata key B after explicit trust | allow metadata | allow metadata | Explicit rotation restores availability. |

The complete command/exit/verdict records are `alma9.tsv` and `fedora44.tsv`. `rpmkeys` independently reports the signed fixture as valid, unsigned fixtures as digest-only, and the corrupted fixture as invalid on both RPM versions.

### Policy syntax is version-specific

- **DNF4:** repository package checking is `gpgcheck=1`; DNF 4.14 exposes neither `pkg_gpgcheck` nor `gpgcheck_policy`. For the mandatory-policy experiment, `%_pkgverify_level=signature` is the RPM transaction backstop and still rejects unsigned bytes even when one test repository requests `gpgcheck=0`.
- **DNF5:** `pkg_gpgcheck` is the unambiguous package setting. The baseline `gpgcheck_policy=legacy` means `gpgcheck=1` expands only to `pkg_gpgcheck=1`; it does not imply `repo_gpgcheck` or `localpkg_gpgcheck`. The harness writes `pkg_gpgcheck` explicitly and keeps `repo_gpgcheck=1` independent. This matches the upstream [DNF5 configuration reference](https://dnf5.readthedocs.io/en/latest/dnf5.conf.5.html#gpgcheck-label).
- **RPM 6:** RPM 6 defaults to enforced transaction verification and supports RPM v4 packages, but DNF5 remains the owner of repository-package checking. The RPM 6 transition must be treated as a distinct supported stack; see the upstream [RPM 6.0 release notes](https://rpm.org/releases/6.0.0).

The baseline values are observations, not safe defaults for generated repositories. Pakomichi must write the package and metadata settings it relies on and then read back the effective configuration.

## Metadata key rotation and recovery

Rotation is two-phase: key B metadata is rejected while only A is configured, and accepted only after B is explicitly trusted. Loss of the metadata private key does not invalidate an already signed snapshot (`exit 0`), prevents a new signature (`exit 2`), and permits a new verifiable signature only after the laboratory backup is restored (`exit 0`). This checks the mechanism; it does not approve a production custody design.

## Conclusions

1. The hypothesis is confirmed on DNF 4.14/RPM 4.16 and DNF5 5.4/RPM 6.0: repository metadata authentication and embedded RPM authentication are separate controls.
2. A GitHub attestation can authorize an explicit exception only when effective OS policy permits unsigned packages. It never turns the RPM into a natively signed RPM or overrides a mandatory signature requirement.
3. `repo_gpgcheck=1` is required independently. A valid package signature cannot rescue invalid metadata, and valid metadata cannot rescue an unsigned or corrupted package under mandatory policy.
4. Global verification must never be disabled. Any permitted exception is scoped to one verified source and one exact package digest, after explicit consent.
5. Metadata signing is byte-preserving for RPMs. Repository hashes detect a package changed after metadata generation.

## Required decision changes (input for ADR-006 and P1-005)

- Define independent gates for signed `repomd.xml` and package-level trust. Both fail closed with separate diagnostics.
- In `Native` mode require the embedded RPM signature. In `Attested` mode allow an unsigned RPM only after production attestation verification, exact digest binding, explicit user consent, and confirmation that effective OS policy permits the exception; otherwise Hold.
- Never write global `gpgcheck=0`. DNF4 exceptions, if allowed, are per repository and subordinate to `%_pkgverify_level`. DNF5 uses explicit `pkg_gpgcheck` and `repo_gpgcheck`, while recording `gpgcheck_policy` and effective values.
- Treat DNF4 and DNF5 as separate adapters. Do not emit unsupported settings, and test each supported distribution build rather than infer behavior from a major version.
- Keep package-publisher keys separate from repository-metadata keys. Rotation explicitly overlaps trust or stages the new key; loss recovery requires an authenticated backup.
- Generate metadata only from final verified RPM bytes and re-check the digest before publication. Metadata signing must never rewrite an RPM.

## Negative cases and deviations

All required negative cases passed: unsigned under mandatory policy, attestation mismatch, corrupted RPM signature, invalid metadata signature, package replacement after metadata, untrusted rotation key, and global-disable request. No global DNF configuration or host repository was changed. No interactive confirmation was automated. Scope covers the two listed upstream distribution images, not RED OS, protected Astra modes, or production attestation infrastructure.

## Proposed index entries

- `docs/en/process/decisions-and-evidence.md`: `R-002 — PASS (DNF 4.14/RPM 4.16 and DNF5 5.4/RPM 6.0): signed repodata and embedded RPM signatures are independent; Attested unsigned is permitted only as an explicit exact-digest exception where effective OS policy allows it; global verification is never disabled.`
- `docs/en/research/INDEX.md`: `R-002 report: [RPM signatures, signed repodata, and Attested](R-002-report.md) — PASS on AlmaLinux 9 and Fedora 44.`
