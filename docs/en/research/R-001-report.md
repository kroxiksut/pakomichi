# R-001 report — APT/DNF: version, file instance, and publisher

**English** · [Русский](../../ru/research/R-001-report.md)

- **Date / performed by:** 2026-10-19, programming agent at the project owner's request; protocol: [R-001](R-001-source-selection.md).
- **Outcome:** **PASS** against the R-001 decision criterion. The selection mechanisms of APT 1.8 (Astra Linux 1.7), APT 2.6, APT 2.8, APT 3.0, APT 3.2, DNF4 (AlmaLinux 9 and 10, RED OS 7.3 and 8), and DNF5 for the tested conflicts are known and reproducible. No native manager guarantees which instance of an *equal* version stays installed, so the ADR-004 fallback (`observing/hold`, never publish the conflicting package in the active repo) is required, not optional. Several observations add requirements for P1-005 (see "Required decision changes"), including two distribution-specific ones: Astra Linux disables `apt upgrade`, and `dnf reinstall` on RED OS 7.3 and 8 does not follow repository priority.
- **Not proven:** that Pakomichi itself holds deterministically. That is a property of code that does not exist yet and must be tested with N-010 in the implementation.

## Environments

Each platform is a separate WSL2 distribution `pakomichi-r001-<platform>`, imported from the root filesystem layer of the official Docker Library image of that distribution, pinned by digest. A clean baseline is restored by importing the same verified layer again. Every run below started from a fresh import.

| Platform | Image (manifest digest) | Package manager | Other versions |
|---|---|---|---|
| Debian 12 | `debian:12@sha256:bc49dc19…` | APT 2.6.1, dpkg 1.21.23 | libc6 2.36-9+deb12u14, gpgv 2.2.40 |
| Debian 13 | `debian:13@sha256:bcf83fd8…` | APT 3.0.3, dpkg 1.22.22 | libc6 2.41-12+deb13u4, sqv (no gpgv) |
| Ubuntu 24.04.5 | `ubuntu:24.04@sha256:a2d43bff…` | APT 2.8.3, dpkg 1.22.6ubuntu6.6 | libc6 2.39-0ubuntu8.9, gpgv 2.4.4 |
| AlmaLinux 9.8 | `almalinux:9@sha256:dc973f4d…` | DNF 4.14.0, rpm 4.16.1.3 | glibc 2.34 |
| AlmaLinux 10.2 | `almalinux:10` (layer `sha256:aa40d510…`) | DNF 4.20.0, rpm 4.19.1.1 | glibc 2.39 |
| Fedora 44 | `fedora:44@sha256:be9d65e2…` | DNF5 5.4.3.0, rpm 6.0.2 | glibc 2.43 |

Full digests (index, manifest, layer, image creation time) are in `research/r-001/images.lock.json`. Kernel for all: `6.18.40.1-microsoft-standard-WSL2`, x86_64. AlmaLinux 10 was added to tell upstream DNF4 behavior from the RED OS 8 build (see below).

**Isolation and its limits.** The Windows host, its package sources, and the owner's personal WSL distribution were not touched. All distributions share the WSL2 kernel and one network namespace. R-001 measures package-manager decisions, which do not depend on the kernel; R-004 (systemd, power loss) needs a real VM and is not covered by this setup. Container base images are minimal: in the APT targets, the four `docker-*` files in `/etc/apt/apt.conf.d/` were removed during preparation because `docker-clean` deletes the package cache and would hide the cache scenarios. Each DNF target ran `dnf -y upgrade` once before the matrix. The project owner allowed WSL for R-001 on 2026-10-19.

### Shared targets

On the same day the project owner allowed runs on a dedicated test laptop and on existing VirtualBox VMs. These are installed systems, not disposable images, so they cannot be re-imported between runs and their distribution sources must not change.

| Platform | Host | Package manager | Other versions |
|---|---|---|---|
| Ubuntu 26.04 LTS | physical test laptop | APT 3.2.0, dpkg 1.23.7ubuntu1 | libc6 2.43-2ubuntu2.4, gpgv 2.4.8 |
| Astra Linux 1.8.6 | VirtualBox VM | APT 2.6.1.astra3, dpkg 1.21.22.astra.se7 | libc6 2.36-9+deb12u7.astra11, gpgv 2.2.40 |
| Astra Linux 1.7.6 | VirtualBox VM | APT 1.8.2.3 (`+astra27` build), dpkg 1.19.8.astra.se3 | libc6 2.28-10+deb10u4.astra19, gpgv 2.2.27 |
| RED OS 8.0.3 | VirtualBox VM | DNF 4.17.0, libdnf 0.71.0, libsolv 0.7.24, rpm 4.18.2 | glibc 2.36 |
| RED OS 7.3.3 | VirtualBox VM | DNF 4.2.23, libdnf 0.48.0, libsolv 0.7.17, rpm 4.17.0 | glibc 2.28 |

Both Astra Linux VMs run at the base security level (`astra-modeswitch getname`: `base(orel)`). The closed software environment, which checks ELF signatures, is off (`DIGSIG_ELF_MODE=0` in `/etc/digsig/digsig_initramfs.conf`), and so are mandatory integrity control and mandatory access control (`parsec.max_ilev=0 parsec.mac=0` on the kernel command line). The fixtures contain no executables either. R-001 therefore does not cover the protected levels of Astra Linux; they are the subject of [R-006](R-006-astra-protected-modes.md).

The same harness runs with `R001_ISOLATE=1`, which limits every change to the R-001 packages:

- APT: for the duration of the run, `/etc/apt/apt.conf.d/99pakomichi-r001-isolate` points `Dir::Etc::sourcelist` at the R-001 `.sources` file and disables `sourceparts`, so no APT client sees the distribution sources; `APT::Get::List-Cleanup "0"` keeps the distribution lists, and no full `apt-get update` runs.
- DNF: `reposdir=` in `dnf.conf` points at a directory holding only the R-001 `.repo` file; no `dnf upgrade` of the system runs.
- Every whole-system command (`upgrade`, `dist-upgrade`, `distro-sync`) is simulated first and refused if the transaction would touch any package other than `sampleapp*`. No cell was refused.
- On exit, the run removes its configuration, keys, lists, caches, and `/etc/hosts` lines, and the logs record that no `sampleapp*` package is left. Each target was checked afterwards.

**Validation of the isolation.** Debian 12 (APT 2.6.1), Ubuntu 24.04 (APT 2.8.3), and AlmaLinux 10 (DNF 4.20.0) were also run with `R001_ISOLATE=1` on fresh imports, and the results were compared cell by cell with the ordinary runs (`research/r-001/results/<platform>-isolated.tsv`). Every cell gives the same decision, instance, and payload, and no cell was refused. The differences are expected: in the ordinary runs the `simulated` downgrade plan also lists pending distribution updates, which the isolated runs cannot see, and parallel downloads appear in the log in a different order.

## Fixtures and repositories

- Fixtures are defined once in `research/r-001/fixtures.txt` and built outside the targets: DEB in `pakomichi-r001-build-deb` (Debian 12), RPM in `pakomichi-r001-build-rpm` (AlmaLinux 9, so the v4 packages are readable by rpm 4.16 and rpm 6). No package has maintainer scripts or scriptlets; the builders fail if one appears.
- `sampleapp` 0.9-1, 1.0-1 in variants **A** (publisher alpha), **B** (beta), and **S** (system), all with the same name, version, and architecture but a different payload marker and SHA-256; 1.1-1 requiring `sampleapp-helper (= 1.1-1)` and the namespaced virtual `pakomichi-test-virtual`, which the helper provides; `sampleapp-missingdep` with an unavailable namespaced dependency; N-008 `sampleapp-glibc` providing `libc6 (= 99.0)` / `glibc = 99.0`; N-009 `sampleapp-nextglibc` requiring `libc6 (>= 2.99)` / `glibc >= 2.99`.
- DEB builds are byte-identical on rebuild (`SOURCE_DATE_EPOCH`). RPMs carry a signing timestamp, so the checksums of the exact set used are recorded: `research/r-001/results/deb-fixtures.sha256`, `rpm-fixtures.sha256`.
- Three laboratory keys marked `TEST ONLY` (RSA 3072): alpha `D302E0E8243318BD32FFF45ACA78F6DEB3D17A98`, beta `115053254C1656F034A0228B4383D8BF768BEC6D`, system `FCEED6D0541230BBA13953DE774C6ACD60580880`. Private keys stay in ignored `.research-local/`.
- APT: one flat repository per source with distinct `Origin`/`Label`/`Suite`/`Codename` (`Pakomichi R-001 TEST ONLY <repo>`, `pakomichi-r001-<repo>`), signed `InRelease` and `Release.gpg`, `Signed-By` per source. DNF: repository IDs `pakomichi-r001-<repo>`, `gpgcheck=1`, `repo_gpgcheck=1`, signed `repomd.xml`; RPMs are signed by their publisher key, and every test repository lists all three test keys. DNF imported the keys under `-y` in the laboratory only.
- Layouts (`research/r-001/layouts.txt`) are served by `repo-server.py` on `127.0.0.1:18081` under distinct host names `alpha|beta|system.pakomichi.test`, so `Pin: origin` can tell them apart. The server logs the host and path of every request: this is the URI evidence for which instance was fetched.

## Execution

```powershell
python -I research/r-001/fetch-images.py .vm-local/r-001/images
powershell -NoProfile -File research/r-001/wsl-import.ps1 -Name pakomichi-r001-build-deb -Image debian12
powershell -NoProfile -File research/r-001/wsl-import.ps1 -Name pakomichi-r001-build-rpm -Image alma9
# builder tools: apt-get install dpkg-dev apt-utils gnupg python3 / dnf install rpm-build rpm-sign createrepo_c gnupg2
wsl -d pakomichi-r001-build-deb -u root --cd /tmp -- bash <checkout>/research/r-001/make-keys.sh
wsl -d pakomichi-r001-build-deb -u root --cd /tmp -- bash <checkout>/research/r-001/build-deb.sh
wsl -d pakomichi-r001-build-rpm -u root --cd /tmp -- bash <checkout>/research/r-001/build-rpm.sh
wsl -d pakomichi-r001-build-deb -u root --cd /tmp -- python3 -I <checkout>/research/r-001/repo-server.py <checkout>/.research-local/r-001/served <checkout>/.research-local/r-001/logs/http.log
powershell -NoProfile -File research/r-001/run-target.ps1 -Platform debian12   # also debian13, ubuntu2404, alma9, alma10, fedora44
powershell -NoProfile -File research/r-001/run-target.ps1 -Platform alma10 -Isolate   # also debian12, ubuntu2404; results in <platform>-isolated
```

Shared targets are run over SSH from a Linux shell that holds the SSH key. The target address and the sudo password file come only from the environment; neither is recorded in the repository:

```sh
R001_TARGET=<user>@<address> R001_SUDO_PASS_FILE=<local file> bash research/r-001/run-remote.sh astra186 apt
```

`run-remote.sh` packs the harness, fixtures, layouts, and the public test keys (never the private keys), copies them into a fresh `mktemp -d` directory on the target, and runs `remote-run.sh` there under `sudo -S`. `remote-run.sh` starts `repo-server.py` on the target's own loopback, runs the scenarios with `R001_ISOLATE=1`, and restores the system on exit, even after a failure. The cell logs and the server log are copied back to `.research-local/r-001/runs/<platform>/`, and the staging directory is removed. A platform name ending in `-noplugins` runs every DNF command with `--noplugins`.

`<checkout>` is the repository path as seen from WSL (`/mnt/<drive>/…`). `run-target.ps1` re-imports the target, copies the harness into it, and runs `apt-scenarios.sh` or `dnf-scenarios.sh` as root. Each cell resets the state (purges `sampleapp*`, removes our sources, lists, and cache), publishes one layout, and records separately: (1) the solver decision (`apt-cache policy`, simulation, or the DNF transaction table), (2) the SHA-256 of the file actually downloaded plus the fetched URI from the server log, and (3) the payload marker after installation. Per-cell results: `research/r-001/results/<platform>.tsv`. Raw per-cell logs stay in `.research-local/r-001/runs/`.

While the harness was being developed, every matrix ran at least twice from fresh imports, and the equal-version outcomes never differed between runs. Only the final runs, made with the committed harness, are the evidence; a repeatable choice is still not treated as a guarantee.

## Results: APT

A/B denote the installed payload; "first" is the order of stanzas in the `.sources` file.

| Scenario | Debian 12 (APT 2.6.1) | Ubuntu 24.04 (APT 2.8.3) | Debian 13 (APT 3.0.3) |
|---|---|---|---|
| Equal version, no pin | first source wins (A or B) | first source wins | first source wins |
| Equal version, `Pin: release o=` / `Pin: origin` 990 on beta | **A**: pin raises the merged version, the file still comes from the first source | **B** | **B** |
| `apt-get install sampleapp/pakomichi-r001-beta` | **A** | **B** | **B** |
| A installed, beta pinned 990 | no change | `dist-upgrade` plans A→B as a downgrade; `-y` refuses without `--allow-downgrades` | same as 2.8.3 |
| A installed, beta listed first, `apt-get clean`, `--reinstall` | **B** (instance switch) | **B** | **B** |
| A cached by download-only, beta listed first, install | cached **A** installed, B never fetched | cached **A** | cached **A** |
| System repo with equal S appears, listed first, clean + `--reinstall` | **S** | **S** | **S** |
| Lower version pinned 990 (fresh install) | lower version installed | same | same |
| Installed 1.0, lower version pinned 1001 | downgrade planned | same | same |
| A 1.0 installed, other source offers 1.1 + new dependency: `apt upgrade` | **1.1 from beta installed** (publisher changed) | same | same |
| same, `apt-get upgrade` | kept back (only because of the new dependency) | same | same |
| same, original source pinned 990 | stays on A | same | same |
| same, `apt-get dist-upgrade` | **1.1 from beta installed** | same | same |
| same, `dist-upgrade` with the original source pinned 990 | stays on A | same | same |
| Remove the family base package (`sampleapp-helper`) | dependent `sampleapp` removed too | same | same |
| Family dependency only in another source | resolved across sources silently | same | same |
| Source removed (404) | `apt-get update` exit 100 | exit 100 | exit 100 |
| Source offline (connection refused) | `apt-get update` exit **0**, warnings, old lists used | exit 0 | exit 0 |
| B installed, its source gone, clean + `--reinstall` | tries alpha, rejects `Hash Sum mismatch`, exit 100, B kept | fails on the beta URI, exit 100, B kept | same as 2.8.3 |
| N-008 `Provides: libc6 (= 99.0)` | installable (exit 0) | exit 0 | exit 0 |
| N-008 + N-009 together | `libc6 (>= 2.99)` **satisfied by the fake provider** | same | same |
| N-009 alone | unsatisfiable, exit 100 | exit 100 | exit 100 |
| Unavailable dependency | exit 100 | exit 100 | exit 100 |

APT 2.6.1 merges equal versions with different hashes into one version and warns `Sources disagree on hashes for supposedly identical version '1.0-1' of 'sampleapp:amd64'`. APT 2.8.3 and 3.0.3 keep them as two versions with the same version string and print no such warning.

### Additional APT platforms

- **Ubuntu 26.04 (APT 3.2.0):** every cell matches Ubuntu 24.04 (APT 2.8.3) and Debian 13 (APT 3.0.3).
- **Astra Linux 1.8.6 (APT 2.6.1.astra3) and 1.7.6 (APT 1.8.2.3):** every equal-version, pin, cache, removal, offline, and N-008/N-009 cell matches Debian 12 (APT 2.6.1). Both merge equal versions and print the same `Sources disagree on hashes` warning, so a pin selects only the version and source order selects the instance.
- **Astra Linux disables `upgrade`.** On both Astra versions, `apt upgrade` and `apt-get upgrade` exit 100 without a transaction: `E: 'apt-get upgrade' is disabled because it can leave system in a broken state.` The message recommends `apt-get dist-upgrade` and names the override `--enable-upgrade` or `APT::Get::EnableUpgrade`; the override was not tested. `apt-get dist-upgrade` behaves as on Debian: without a pin it installs 1.1 and its new dependency from beta (the publisher changes), and with a 990 pin on the original source it stays on A.

## Results: DNF

| Scenario | AlmaLinux 9 (DNF 4.14) | Fedora 44 (DNF5 5.4.3) |
|---|---|---|
| Equal NEVRA, equal priority | first section in the `.repo` file wins (observed) | beta in both orders (observed; basis not established) |
| `priority=10` on one repo, 90 on the other | the priority-10 instance, either way | same |
| `excludepkgs=sampleapp` on alpha / `includepkgs` without `sampleapp` on beta | the other repo's instance | same |
| `--disableexcludes=all` (DNF4) / `--setopt=disable_excludes=*` (DNF5) | exclusion lifted, priority applies again (A) | same |
| `--repo pakomichi-r001-beta` / `--disablerepo pakomichi-r001-alpha` | B | B |
| A installed, beta then preferred by priority | `upgrade`: A kept; `distro-sync` and `reinstall`: **B** | same |
| A kept in cache (`keepcache=1`), beta then preferred | B downloaded; caches are per repository | same |
| Lower version with priority 10 (fresh install) | lower version installed | same |
| Installed 1.0, lower version priority 10 | `upgrade` keeps 1.0; `distro-sync` plans 0.9 | same |
| A 1.0 (vendor alpha) installed, beta offers 1.1 (vendor beta): `dnf upgrade` | **1.1 vendor beta installed** (`allow_vendor_change=1` by default) | same |
| same with `allow_vendor_change=False`, priority on alpha, or `excludepkgs` on beta | stays on A | same |
| Remove the family base package | dependent `sampleapp` removed too | same |
| Family dependency only in another repo | resolved across repos | same |
| System repo with equal S, priority 99 (alpha 50) | A kept on reinstall | same |
| System repo with equal S, priority 10 | `reinstall` installs **S** | same |
| B installed, its repo removed (404) or offline | `skip_if_unavailable=0` by default: `makecache`/`upgrade`/`reinstall` exit 1, B kept | `skip_if_unavailable=1` by default: exit 0 and `reinstall` **silently installs A** |
| same with per-repo `skip_if_unavailable=False` | exit 1, B kept | exit 1, B kept |
| same with per-repo `skip_if_unavailable=True` | `reinstall` installs **A** | installs **A** |
| N-008 `Provides: glibc = 99.0` | resolvable | resolvable |
| N-008 + N-009 together | `glibc >= 2.99` **satisfied by the fake provider** | same |
| N-009 alone / unavailable dependency | unresolvable | unresolvable |

### Additional DNF platforms

- **AlmaLinux 10.2 (DNF 4.20.0):** every cell matches AlmaLinux 9 (DNF 4.14.0), both in the ordinary run and with `R001_ISOLATE=1`.
- **RED OS 8.0.3 (DNF 4.17.0) and RED OS 7.3.3 (DNF 4.2.23)** match AlmaLinux 9 in every cell except the following:

| Scenario | AlmaLinux 9 / 10 | RED OS 8.0.3 | RED OS 7.3.3 |
|---|---|---|---|
| Distribution `dnf.conf` | `skip_if_unavailable=False`, `best=True` | `skip_if_unavailable=True`, `best=False` | same as RED OS 8 |
| A installed (alpha priority 90), beta preferred by priority 10: `reinstall` | **B** (follows priority) | **A** from alpha (the worse priority) | **A** |
| System repo with equal S, priority 99 (alpha 50): `reinstall` | A kept | **S** installed | **S** |
| System repo with equal S, priority 10: `reinstall` | **S** installed | A kept | A kept |
| B installed, its repo removed (404) or offline | exit 1, B kept | exit 0, `reinstall` **silently installs A** | same as RED OS 8 |
| same with per-repo `skip_if_unavailable=False` | exit 1, B kept | exit 1, B kept | exit 1, B kept |
| A 1.0 installed, beta offers 1.1 from another vendor, `allow_vendor_change=False` | stays on A | stays on A | **1.1 vendor beta installed**: the option does not exist |

On RED OS, `reinstall` takes the instance from the repository with the *highest* priority number, which DNF treats as the *lowest* priority. Fresh installs and `distro-sync` follow priority as on AlmaLinux. On RED OS 8 the result was reproduced in a second full run and is the same with `--noplugins` (`redos80-noplugins`). RED OS 7.3 loads only the standard `dnf-plugins-core` plugins and behaves the same, so the plugins are not the cause. Upstream DNF 4.14 and 4.20 do not show it, so it comes from the RED OS builds of DNF/libdnf rather than from DNF 4 itself or from the isolation mode. The cause in the RED OS sources was not investigated.

DNF 4.2.23 (libdnf 0.48.0) on RED OS 7.3 has no `allow_vendor_change` option: `--setopt=allow_vendor_change=False` prints `Main config did not have a allow_vendor_change attr.`, and the option in `dnf.conf` is ignored. A priority on the original repository and `excludepkgs` on the other repository still keep A there. Its `repoquery` has no `from_repo` field, so the `from=` column is empty for RED OS 7.3; the fetched URI still shows which instance was downloaded.

## Conclusions

Observed and reproducible on the listed versions:

1. **APT cannot bind an equal version to one instance.** On APT 2.6 pins select only the version, so the instance depends on source order. On APT 2.8/3.0 a pin selects the instance for a fresh install, but the installed instance can still change through `--reinstall` after a cache clean (source order decides); `dist-upgrade` plans the A→B replacement as a downgrade, which `-y` refuses (an interactive confirmation was not tested); and a stale cached file is reused regardless of preference. This confirms the R-001 hypothesis for APT 2.6 and refines it for 2.8/3.0: the binding exists but is not stable over the package's life.
2. **DNF binds instances through priority and repository filters**, but `distro-sync` and `reinstall` move an installed package to the currently preferred instance, and with `skip_if_unavailable=True` (the Fedora 44 default) the disappearance of the instance's repository makes `reinstall` substitute another publisher's file without an error.
3. **Ordinary upgrades change the publisher** on every tested manager when another enabled source offers a higher version of the same name. Native protection exists: a 990 pin on the original source (APT), or priority, `excludepkgs`, or `allow_vendor_change=False` (DNF).
4. **Native managers accept a third-party `Provides` of the C library** (N-008) and then use it to satisfy versioned C-library requirements (N-009). No tested manager protects the system namespace; this must be a Pakomichi admission check.
5. **Offline is not an error for `apt-get update`** (exit 0 with warnings); a removed repository is (exit 100). DNF behavior depends on `skip_if_unavailable`.
6. **No silent substitution on the APT fetch path:** when the expected file is gone, APT rejects a same-named file from another source by hash.
7. **The ordinary update command differs by distribution.** Astra Linux 1.7 and 1.8 refuse `apt upgrade` and `apt-get upgrade` by default, so their ordinary path is `apt-get dist-upgrade`. That path also changes the publisher without a pin, and it never keeps back a package because of a new dependency.
8. **Distribution builds of DNF4 differ in instance selection, options, and defaults.** RED OS 7.3 and 8 enable `skip_if_unavailable` by default, as Fedora does, and their `reinstall` does not follow repository priority. DNF 4.2 on RED OS 7.3 has no `allow_vendor_change`. A DNF version number alone does not predict the behavior; every supported distribution build needs its own run.

Guaranteed by the native manager: only what each documented primitive selects at decision time (DNF priority/filters/explicit repo; APT ≥ 2.8 pins for a fresh install). Instance stability for equal versions is guaranteed by none.

## Required decision changes (input for P1-005)

- Keep ADR-004 as accepted: equal native version with different bytes → `observing/hold`, never publish the conflicting package in the active repo, on every platform. The results do not allow a weaker rule for APT 2.8+ or DNF.
- Treat a `Provides` (or a file/soname provide) of a system-namespace package such as `libc6`/`glibc` as an admission failure (Hold), because the native managers accept it.
- For every name Pakomichi publishes, the configuration must stop an implicit publisher change by another enabled source with a higher version: an origin pin (APT) and a repository priority plus `allow_vendor_change` awareness or `excludepkgs` (DNF). The concrete primitives and their interaction with distribution security updates need an ADR.
- DNF repository files written by Pakomichi should set `skip_if_unavailable=False` explicitly, so that a missing repository fails closed instead of letting `reinstall` substitute another publisher's package. Fedora 44, RED OS 7.3, and RED OS 8 enable the option by default.
- The offline and stale-source diagnostics cannot rely on the `apt-get update` exit status.
- The first vertical slice ("GitHub connection → verification → APT → ordinary `apt upgrade`") must define the ordinary update command per distribution: on Astra Linux it is `apt-get dist-upgrade`. Publisher protection must be shown under `dist-upgrade` too (the 990 origin pin holds there). Pakomichi must not require `APT::Get::EnableUpgrade` or any other change to the distribution's APT policy.
- R-001 covers Astra Linux only at the base security level. Until R-006 reports, no claim about Astra Linux may extend to the protected levels (closed software environment, mandatory integrity control, mandatory access control).
- On RED OS 7.3 and 8, repository priority does not keep the installed instance through `reinstall`. Priority can therefore never stand in for the ADR-004 hold there, and the DNF primitive chosen in P1-005 must be verified on each supported distribution build, not only on upstream DNF.
- The DNF protection against an implicit publisher change cannot rely on `allow_vendor_change` alone, because DNF 4.2 (RED OS 7.3) does not have it. Priority on the Pakomichi repository or `excludepkgs` on other repositories worked on every tested DNF.

## Negative cases

N-008: resolvable on every platform (expected at the Pakomichi level: Hold). N-009 without a provider: unresolvable on every platform (Hold). N-010 equal version with different SHA: no automatic switch during `upgrade` on any platform, but instance switches through `--reinstall`/`distro-sync` and source order (see above). No artificial epoch was introduced, no third-party or distribution source was changed or disabled, global `gpgcheck` stayed on, and the development host's package sources were not touched. On the shared targets the distribution sources were only hidden for the duration of a run, and afterwards each target had no R-001 package, source, key, or `/etc/hosts` entry left.

## Addendum (2026-10-22, P3-002a): `Pin: release` on one loopback host

ADR-022 point 3 required one check that R-001 did not make: R-001 served every source under its own host name, while ADR-007 serves every logical repository from one loopback host. Harness: `research/p3-002a/` (`build.sh` in the R-001 DEB builder with the R-001 TEST ONLY keys; `run.ps1` for WSL targets recreated from the digest-pinned R-001 images; `run-remote.sh` for a shared target). Raw logs: `.research-local/p3-002a/runs/`.

Four signed flat repositories are served by `repo-server.py` from `http://127.0.0.1:18082/p3002a/<repo>/`. **strict** (`Origin: Pakomichi TEST ONLY`, `Label: pakomichi-p3002a-strict`) has `sampleapp 1.0-1`, which depends on `sampleapp-helper (>= 1.0)`, and `sampleapp-helper 1.0-1`. **pinned** has the same Origin and `Label: pakomichi-p3002a-pinned`, as a second provenance level of one source would (ADR-027 point 6), and offers `sampleapp 1.2-1`. **other** is another publisher with `sampleapp 1.1-1` and `sampleapp-helper 1.1-1`. **distro** stands for a distribution update with `sampleapp-helper 1.3-1`. The family is installed from strict alone; then all four sources are listed, strict last so that source order cannot help it, and the distribution's ordinary update command runs with `-y`. APT sees only these sources during the run, as on the R-001 shared targets. Every cell starts from a purged state.

| Preferences for `sampleapp sampleapp-helper` | Priorities after `apt-get update` | Result of every ordinary command |
|---|---|---|
| none (control) | all 500 | `sampleapp 1.2-1` from pinned, `sampleapp-helper 1.3-1` from distro: the publisher changes |
| `Pin: release o=Pakomichi TEST ONLY,l=pakomichi-p3002a-strict` 990 | strict 1.0-1 at 990, others 500 | both stay at 1.0-1 from strict; nothing is downloaded after the installation |
| `Pin: release o=Pakomichi TEST ONLY` 990 (diagnostic) | strict 1.0-1 and pinned 1.2-1 at 990 | `sampleapp 1.2-1` from pinned: the Origin alone does not tell two levels apart |

The same three outcomes, with the same priorities, were observed on:

- Debian 12 (APT 2.6.1, dpkg 1.21.23) under `apt upgrade` and `apt full-upgrade`;
- Ubuntu 24.04 (APT 2.8.3) under `apt upgrade` and `apt full-upgrade`;
- Debian 13 (APT 3.0.3) under `apt upgrade` and `apt full-upgrade`;
- Astra Linux 1.8.6 (APT 2.6.1.astra3) under `apt-get dist-upgrade` and `apt full-upgrade`. This is the owner's VM under an exclusive lease. Its own `astra.pin.pref` stayed in place, and afterwards no P3-002a package, source, key, preference, or list was left.

Every command exited 0. The server log shows which repository each package file came from.

**Conclusion:** `Pin: release o=…,l=…` with `Pin-Priority: 990` holds the publisher of every activated family member when all logical repositories share one host and port, under the ordinary update command of each tested APT distribution. The `l=` term is required whenever two logical repositories can share an Origin. The control without a pin changes the publisher, as R-001 found.
