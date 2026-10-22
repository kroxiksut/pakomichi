# R-006 — Astra Linux protected security levels

**English** · [Русский](../../ru/research/R-006-astra-protected-modes.md)

This protocol must report before any support claim for Astra Linux beyond the base security level, and before Pakomichi's APT path is enabled on such a system. R-001 covered Astra Linux 1.7.6 and 1.8.6 only at the base level (`base(orel)`), with fixtures that contain no executables.

## Hypothesis

Astra Linux is Debian-compatible, and the protected levels do not change APT's version and instance selection. They do change what an installed package may do:

- With the closed software environment on, the kernel refuses to execute an ELF file or load a library that is not signed by a key the system trusts. Release binaries from GitHub carry no such signature, so a package can be delivered and installed but its programs do not run.
- With mandatory integrity control on, installing packages requires a session at a high integrity level, which affects how Pakomichi's service and the administrator's applier run.
- Additional locks (interpreters, setting the executable bit) can break maintainer scripts.

Pakomichi must detect these modes without root, hold an artifact that cannot run on the system and say why, and never sign, patch, or repackage third-party files to get around the check.

## Environment

A dedicated VM `pakomichi-astra18-*` cloned from an installed Astra Linux 1.8.6 system at the base level, or, with the owner's approval, that system inside a dedicated snapshot that is restored and deleted afterwards. Existing snapshots are never changed. Network: NAT only, SSH through a port forward. Before changing a security level, take a snapshot of the clone. Record the exact Astra version, kernel, `parsec`/`digsig` package versions, and the effective settings at each level.

## Fixtures

Built outside the target, TEST ONLY, never published:

- `sampleapp-elf`: a DEB with an unsigned ELF executable and no maintainer scripts.
- The same package with its ELF signed by a laboratory key that is installed into the clone's trusted ELF keys. This only confirms the mechanism. Pakomichi never signs files.
- `sampleapp-script`: a DEB with a trivial `postinst`.
- The R-001 `sampleapp` set, to confirm that APT decisions do not change.

## Matrix

| Level | Closed environment | Integrity control | Access control |
|---|---|---|---|
| base (control) | off | off | off |
| closed environment only | on | off | off |
| advanced (`voronezh`) | on | on | off |
| maximum (`smolensk`) | on | on | on |

At each level, record:

1. `apt-get install` and `dpkg -i`: exit status and whether dpkg or APT itself checks signatures.
2. Running the installed program: success or refusal, the exact error, and the audit log entry.
3. `postinst` behavior.
4. Installation from a low and from a high integrity session.
5. `apt-get dist-upgrade` with the R-001 upgrade layout, compared with the base level.
6. Which indicators an unprivileged process can read to detect the level: `astra-modeswitch get`, `/etc/digsig/digsig_initramfs.conf`, `/proc/cmdline`, `pdp-id`. Record which ones need root.

## Negative cases

- An unsigned ELF must never be reported as runnable when the closed environment is on.
- No change to the source VM, its snapshots, its trusted keys, or its security level.
- No signing or modification of third-party files, and no instruction to the user to disable the closed environment as Pakomichi's default advice.

## Result

PASS: a documented matrix with a detection method that works without root, and the observed behavior for unsigned executables at every level. **Fallback:** if the level cannot be detected reliably, or the behavior cannot be reproduced, the Astra Linux protected levels stay outside the 0.1 support matrix and Pakomichi holds artifacts with executables on Astra Linux whose level it cannot confirm as base.
