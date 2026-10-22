# R-006 report — Astra Linux protected security levels

**English** · [Русский](../../ru/research/R-006-report.md)

- **Date / performed by:** 2026-10-19 and 2026-10-20, programming agent at the project owner's request; protocol: [R-006](R-006-astra-protected-modes.md).
- **Outcome:** **PASS** for Astra Linux 1.8.6: every level of the protocol matrix, installation from a low and a high integrity level, the R-001 APT matrix at `maximum(smolensk)`, and level detection without root. Astra Linux 1.7, the `external_sig` and xattr signature modes, and the interpreter and `chmod +x` locks are not covered (see "Not covered").
- **Main fact:** with the closed software environment on, APT and dpkg install a package with an unsigned ELF without any error, but the program does not start. A self-made key cannot be trusted on Astra Linux 1.8: an additional key is accepted only when it is signed by the Astra Linux root key.

## Environment

Astra Linux 1.8.6, kernel 6.12.77-1-generic, `digsig_verif` and `parsec` 6.12.77-1.astra1+ci11, gnupg 2.2.40-1.1.astra7b1, bsign 1.5.11. The work ran on an existing installed VM in a dedicated VirtualBox snapshot taken before the experiment (approved by the project owner instead of a clone). Afterwards the VM was restored to that snapshot, and the snapshot was deleted; the VM's other snapshots were not touched. The second session (2026-10-20) repeated this with a new snapshot; `strace` 6.1 was installed from the Astra Linux repository inside that snapshot only, and `apt-get update` refreshed the VM's own package lists there; both were discarded with the snapshot. SSH access only; addresses and credentials are not recorded here.

## Fixtures and commands

`research/r-006/build-deb.sh` builds two TEST ONLY packages in the R-001 Debian 12 builder: `sampleapp-elf` (a static ELF from a few lines of assembly that prints one line, not signed for Astra Linux) and `sampleapp-script` (no executable, a `postinst` that writes a marker). `research/r-006/run-level.sh LABEL` copies `level-check.sh` and the packages to the target and runs it through sudo; it records the level as an unprivileged user and as root, installs with `dpkg -i` and `apt-get install ./…`, runs the ELF as the user and as root, checks the `postinst` marker, and purges both packages. `research/r-006/low-ilev-check.sh` collects the commands of the low-integrity cell; the cell itself was run on 2026-10-20 as an equivalent ad hoc root snippet, and the script file was written from it afterwards and has not been run as a file. The R-001 APT matrix ran unchanged with `research/r-001/run-remote.sh astra186-smolensk apt` (isolated mode, see the [R-001 report](R-001-report.md)). Raw logs: `.research-local/r-006/` and `.research-local/r-001/runs/astra186-smolensk/`; the matrix cells are in `research/r-006/results/astra186-smolensk-apt.tsv`.

Levels were changed with `astra-modeswitch set`, `astra-digsig-control enable`, `astra-mic-control enable`, and `astra-mac-control enable`, each followed by a reboot.

## Results

| Cell | Level / settings | `dpkg -i` / `apt-get install` | Unsigned ELF run (user, root) | `postinst` |
|---|---|---|---|---|
| 1 | `base(orel)`, all off | exit 0 | runs, exit 0 | ran |
| 2 | `advanced(voronezh)`, closed environment on | exit 0, status `install ok installed` | **`Segmentation fault`, exit 139**; kernel `DIGSIG:[ERROR] type=NOT_SIGNED` | ran |
| 3 | `advanced(voronezh)`, closed environment + integrity control | exit 0 | exit 139, `NOT_SIGNED` | ran |
| 4 | `maximum(smolensk)`, closed environment + integrity control + access control | exit 0 | exit 139, `NOT_SIGNED` | ran |
| 5 | `advanced(voronezh)`, closed environment + integrity control; the command runs at integrity level 0 | **refused**: `dpkg -i` exit 2, `apt-get install` exit 100, nothing installed | — | did not run |
| 6 | `maximum(smolensk)`, all three on; R-001 APT matrix, 26 cells | same decisions as `base(orel)` in every cell | — | — |

Cell 6 compared with the R-001 run on the same system at `base(orel)`: the candidate, the downloaded instance, the installed variant, and the fetched URLs match in all 26 cells, including equal versions, pins, `dist-upgrade`, the removed and unreachable source, the missing dependency, and the negative cases N-008 and N-009. The only difference is the order of two parallel downloads in one cell. APT 2.6.1.astra3, dpkg 1.21.22.astra.se7, parsec-base 3.11+ci183.

Further observations:

- At `base(orel)`, `astra-digsig-control enable` refuses: `This function can't be enabled in current astra mode`. Switching the level alone enables nothing; each protection is enabled separately and takes effect after a reboot.
- The refusal is not a clean error: the process is killed with `SIGSEGV` (exit 139), and the reason is only in the kernel log.
- An ELF signed with `bsign` and a laboratory RSA-4096 key: `BAD_SIGNATURE`, `Unknown algo type 0`. Signed with a laboratory GOST R 34.10-2012 key placed in `/etc/digsig/keys` (initramfs regenerated, rebooted): the kernel refused to load the key (`verify_key_signature: ERROR, Key signature was not found`, `LOADKEY ... res=fail`), and the program got `BAD_SIGNATURE`, `signer key was not found`. The Astra Linux keys in `/etc/digsig/` are GOST R 34.10-2012 (OpenPGP algorithm 35).
- The administrator's SSH session runs at `ILevel=63(High)` once integrity control is on, so `dpkg` and APT work as before. systemd services, including a service with `DynamicUser=yes`, also start at `ILevel=63`.
- Installation from a low integrity level (cell 5, `advanced(voronezh)` with the closed environment and integrity control on; 2026-10-20). A process started as root with `pdp-exec -l 0:0` runs at `ILevel=0(Low)`. From that level `dpkg -i` fails with `dpkg: error: required read/write access to the dpkg database directory /var/lib/dpkg` (exit 2), and `apt-get install ./…` resolves the transaction and then fails with `E: Sub-process /usr/bin/dpkg returned an error code (2)` (exit 100); nothing is installed. Writing to `/etc/apt/sources.list.d/` and `/var/lib/` is refused with `Permission denied`. `apt-get update` succeeds, and writing to `/var/cache/apt/archives/` succeeds, because `/var/lib/apt/lists`, `/var/cache/apt/archives`, `/var/log`, and `/tmp` carry the `Low` integrity label, while `/etc`, `/etc/apt`, `/usr/bin`, and `/var/lib/dpkg` carry `High`. The same `dpkg -i` from the administrator's session at level 63 succeeds.
- `sumic` is not a tool for this test: it always runs the command through `/usr/bin/fly-xephyr.sh` and `xinit` in an isolated Xephyr display, so without a graphical session it exits with status 1, and its error output does not reach the caller. This was the cause of the inconclusive first attempt on 2026-10-19 (traced with `strace` from the Astra Linux repository, installed only inside the experiment snapshot). On the base level `sumic` refuses with a message that it works only at the advanced and maximum levels.
- Detection without root: `astra-modeswitch get`/`getname`, `/etc/digsig/digsig_initramfs.conf` (`DIGSIG_ELF_MODE`), `/proc/cmdline` (`parsec.max_ilev`, `parsec.mac`), `pdp-id`, and `/sys/module/parsec/parameters/max_ilev` are readable. The `digsig` file shows the configured state for the next boot, not necessarily the running state. `astra-*-control is-enabled|status` and `/sys/module/digsig_verif/parameters/*` need root.

## Not covered

- Astra Linux 1.7, excluded from R-006 by the project owner's decision on 2026-10-20. Its protected levels may behave differently and must not be assumed from 1.8.6; Astra Linux 1.7 at a protected level is therefore not part of any support claim.
- The `external_sig` and xattr signature modes. They change where a signature is stored, not who may sign, so they are not expected to remove the root-key requirement; this is not shown.
- The interpreter, `chmod +x`, and `bash` locks, which can break maintainer scripts. They were off in every cell.
- The R-001 APT matrix at `advanced(voronezh)`; it ran only at `maximum(smolensk)`, which includes every protection that `voronezh` has.

## Conclusions and required decision changes

1. On Astra Linux with the closed software environment on, a package from a GitHub release with executables can be delivered and installed without any error and still never run. Pakomichi must detect the closed environment and hold such artifacts with a clear reason instead of offering them as ordinary updates.
2. Pakomichi cannot fix this and must not try: trusting an extra key requires a key signed by the Astra Linux root key, and signing or modifying third-party files is prohibited by `AGENTS.md`.
3. Pakomichi's own executables will not run on such a system unless they are signed through the Astra Linux key chain. Until that is arranged, the protected levels with the closed environment are outside the 0.1 support matrix.
4. Detection must use unprivileged indicators: the level from `astra-modeswitch`, the closed environment from `/etc/digsig/digsig_initramfs.conf`, and integrity control from `/sys/module/parsec/parameters/max_ilev`. Because the `digsig` file may differ from the running state until a reboot, a mismatch must be treated as "closed environment on".
5. A crash with `SIGSEGV` after installation must not be diagnosed as a defect of the package when the closed environment is on.
6. With integrity control on, only a process at a high integrity level can install packages. Pakomichi's administrative applier must run as a systemd service or from the administrator's session (both run at level 63), and must report a failed installation from a lower level as an integrity-level problem, not as a package error. A low-integrity component, such as the network downloader, cannot install packages or change APT sources, which matches the privilege separation of ADR-009.
7. At integrity level 0 a process can still write to `/var/lib/apt/lists` and `/var/cache/apt/archives`. Pakomichi must not treat the APT lists or cache as trusted input on Astra Linux, and must rely on APT's signature and hash verification and on its own CAS digests.
8. The protected levels do not change APT's choice of version or instance. The R-001 conclusions and the ADR-004 hold apply to Astra Linux 1.8.6 at every level unchanged.
