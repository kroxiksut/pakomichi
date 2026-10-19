# Isolated environments, VMs, and research secrets

**English** · [Русский](../../ru/process/test-environments.md)

## Boundary

APT/DNF, systemd, package installation, repository changes, root scenarios, and Pakomichi network integrations are tested only in a container or VM. The Windows development host is not a Linux test system and must not be modified to make a research task pass.

## Environment reproducibility

For each run, record:

- the R/task ID and the exact goal;
- the provider, image, digest/version, and architecture;
- the versions of the kernel, APT/DNF/RPM/systemd, and the verification tools;
- the commands for creation, preparation, execution, and recovery;
- the initial state of the repositories and the snapshot;
- the expected and actual result, including the negative scenario;
- SHA-256 of the synthetic packages, indexes, and verified files.

An image or snapshot is not evidence by itself. Evidence is a reproducible protocol and saved sanitized output.

## Local directories

- `.vm-local/`: VM disks, snapshots, SSH state, cloud-init with local values, and provider metadata.
- `.research-local/`: raw logs, temporary packages, keyrings, and intermediate results.
- `.env`: local paths and credentials; the public list of variable names is in `.env.example`.

These paths are excluded from Git. Durable evidence is moved into the related R report or a dedicated results directory only after removing secrets, personal data, internal addresses, and unnecessary host details.

## Credentials and keys

- Use the minimum necessary permissions and separate laboratory credentials.
- A GitHub token must not end up in a URL, command line, shell history, agent log, or saved HTTP trace.
- Do not use VM SSH keys as release/signing keys.
- For APT/RPM, create separate test keys explicitly marked `TEST ONLY`; the private key stays local.
- A public key or synthetic fixture may be committed only when its test purpose is obvious and its private counterpart is not used outside the laboratory.
- Before publishing logs, check HTTP headers, the environment, absolute paths, user names, addresses, and configuration contents.

## Run lifecycle

1. Create or restore a known clean environment.
2. Check the baseline before making changes.
3. Save a snapshot before a risky transition.
4. Run only the scenario of the related R/task; do not fix the image with system migrations to get a green result.
5. Run the negative scenario and verify that no third-party sources were changed.
6. Export the sanitized commands, versions, hashes, and output.
7. Restore or destroy the laboratory environment after the evidence has been saved.

If a VM cannot plausibly support the required capability, the result is `INCONCLUSIVE` and the designated fallback is used; the requirement is not weakened.
