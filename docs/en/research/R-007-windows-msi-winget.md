# R-007 — Windows: MSI packages from GitHub Releases through a local WinGet source

**English** · [Русский](../../ru/research/R-007-windows-msi-winget.md)

This protocol does not block 0.1. ADR-014 keeps WinGet outside the alpha and requires that it be investigated in parallel; this document is the input for that investigation and for a future ADR. Nothing here is a support claim or an implemented capability.

## Motivating example

A common way to install OpenSSH for Windows on Windows 10 today, as suggested by an assistant to the project owner on 2026-10-21:

```powershell
Invoke-WebRequest https://github.com/PowerShell/Win32-OpenSSH/releases/download/10.4.0.0p1-Preview/OpenSSH-Win64-v10.4.0.0.msi -OutFile C:\temp\OpenSSH-Win64.msi -UseBasicParsing
Start-Process msiexec -ArgumentList '/i C:\temp\OpenSSH-Win64.msi /qn' -Wait
```

Read-only GitHub API facts for that release, observed on 2026-10-21:

| Fact | Value | Consequence for the recipe |
|---|---|---|
| Repository ID / owner ID | `42125787` / `11524380` | The recipe uses a name in a URL; a renamed, transferred, or re-created repository is not detected |
| Release `10.4.0.0p1-Preview` | published 2026-10-20, `immutable=false`, `prerelease=false` | The assets can be replaced; the tag says "Preview" while the release flag says stable, so a channel cannot be judged from the flag alone |
| Asset digest | `sha256:788d8643…6ac9` for `OpenSSH-Win64-v10.4.0.0.msi` | Published by GitHub, but the recipe never compares it |
| Attestations for that digest | none (`404`) | Neither Strict nor Attested evidence exists (ADR-005) |
| Other assets | `OpenSSH-{ARM,ARM64,Win32,Win64}.zip` and `*_Symbols.zip` | The architecture and the format are chosen by hand |

Further problems of the recipe: no Authenticode check of the MSI; `msiexec /qn` runs the package's custom actions silently and with administrator rights; the version, architecture, and path are written into the command, so the next release needs a new hand-written URL and nothing records where the installed program came from; and Windows 10 already ships OpenSSH as an optional capability (`OpenSSH.Client`, `OpenSSH.Server` in `System32`), so the MSI installs a second copy next to it, with two `ssh` on `PATH` and a possible conflict of the `sshd` service.

The same task with Pakomichi, as it could look if this research succeeds (hypothetical; no such command exists):

```text
pchi source add https://github.com/PowerShell/Win32-OpenSSH
  → pinned: repository ID 42125787, owner ID 11524380
pchi source inspect <id>
  → MSI for x64, x86, ARM64 (zip and symbol archives ignored)
  → no attestations, release not immutable: Strict and Attested unavailable
  → Authenticode signature: <signer, status>         (analogue of Native mode, ADR-023)
  → custom actions: <list from the MSI tables>       (shown, not executed)
  → conflict: Windows capability OpenSSH.Client is installed → observing
pchi source activate <id> --packages openssh          (explicit decision about the built-in capability)
winget upgrade                                        (later releases arrive through the native manager)
```

What it would simplify: no hand-written URL, version, or architecture; the asset digest and the publisher signature are checked before anything runs; a replaced asset (`E_ASSET_MUTATED`), a changed repository ID, or an owner transfer is blocked; the custom actions and the conflict with a system component are visible before the decision; later releases arrive through the ordinary update command; and the installed program keeps a recorded origin.

If the publisher's package already exists in the community WinGet repository, the right answer is to use it, as with PPA or COPR on Linux. Pakomichi is for projects that publish only in Releases.

## Hypothesis

Pakomichi's model carries over to Windows with the following mapping, each part of which needs evidence:

| Linux (0.1) | Windows (hypothesis) |
|---|---|
| Local signed APT/DNF repository on loopback | A local WinGet source served by Pakomichi |
| Native manager: `apt upgrade`, `dnf upgrade` | `winget upgrade` |
| Embedded RPM signature, Native mode (ADR-023) | Authenticode signature of the MSI, verified against a publisher identity pinned for the source |
| Maintainer scripts, inspected without execution (ADR-028) | MSI custom actions, read from the MSI tables without installing |
| System namespace (ADR-022) | Windows optional capabilities and packages installed from other WinGet sources |
| Execution-control policy (`E_EXECUTION_POLICY`) | Smart App Control, WDAC/AppLocker policies |

## Questions

1. Which WinGet source types can a local service provide: the REST source (does it require HTTPS, and with which certificate trust on loopback), or a pre-indexed source (does it require a signed `source.msix`, and with which key)? Can `winget source add` register it without weakening WinGet's own checks, and does it need administrator rights?
2. Does `winget upgrade` keep the source of an installed package, or can a higher version from another source (the community repository, the Microsoft Store) take it over, as R-001 showed for APT and DNF?
3. Authenticode: which fields identify the publisher reliably enough to pin (subject, issuer chain, certificate thumbprint across renewals), how timestamping and revocation behave offline, and what signing the Win32-OpenSSH MSI actually carries.
4. Can the MSI tables (`Property`, `CustomAction`, `InstallExecuteSequence`, `File`) be read without installing and without executing anything, by a bounded parser in an unprivileged process?
5. How to detect, without administrator rights, that a Windows capability or a package from another source provides the same program.
6. How MSIX and portable zip assets fit, or whether they stay out of scope.

## Environment

A dedicated VM `pakomichi-win-*` in `V:\VMs\pakomichi-*`, with a snapshot before each experiment. Alternatively, with the owner's approval (given on 2026-10-22), a shared Windows test VM, used on these conditions:

- experiments run in their own directory;
- every change is listed and reverted at the end, and the revert is checked: WinGet sources and settings, installed packages, certificates, files;
- snapshots of a shared VM are never created, restored, or deleted.

Either way: the VM lease rules apply, NAT only, and the WinGet and Windows versions are recorded. Only test-only signing certificates are used, and never added to the host. No experiment runs on the development host.

## Fixtures

Built outside the target, TEST ONLY, never published: an MSI signed by a laboratory certificate, the same MSI unsigned, one with a modified byte after signing, one with a custom action, and a higher version of the same product from a second test source. Third-party MSIs (such as Win32-OpenSSH) are inspected read-only and installed only in the VM.

## Negative cases

- An MSI whose digest differs from the accepted one is never offered.
- An unsigned or wrongly signed MSI is not offered as Native.
- No custom action runs during inspection.
- No change to third-party WinGet sources, to WinGet's global settings, or to Windows security policy, and no instruction to disable a check.
- A built-in Windows capability is never displaced automatically.

## Result

PASS: a documented answer to questions 1–5 with commands and logs from the VM, and a proposed ADR for the Windows mapping. **Fallback:** if WinGet cannot use a local source without weakening its checks, Windows stays out of scope, and the read-only part (pinning, digest and Authenticode checks, MSI inspection) is considered only as a separate `pchi` verification command that does not install anything.
