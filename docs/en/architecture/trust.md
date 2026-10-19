# Trust and threat model

**English** · [Русский](../../ru/architecture/trust.md)

## What we trust

The user independently chooses a **specific** repository; we do not prove the publisher's honesty. Our goal is not to substitute the choice, not to accept bytes from another repo, and not to serve a corrupted artifact. We do not trust an arbitrary `owner/repo` string after an ownership change, an unsigned file name, `latest`, an RPM/DEB name, or HTTPS as evidence of the absence of malware.

## Strict

GitHub immutable release + cryptographically verified release attestation (with the required predicate type) + repository ID in the certificate/attestation + correspondence of release/assets + SHA-256 of the actual file. Verify the real fields/chain in R-003; the API `immutable=true` alone is insufficient to claim that the entire cryptographic procedure has been performed.

## Attested

The release may be mutable, but the specific file requires a cryptographically verified attestation with the expected source repository ID, workflow identity, predicate, and digest. After acceptance, `(release_id,asset_id,sha)` must not be overwritten with a new digest: a detected replacement must be blocked. The first observation does not prove the absence of changes before it.

## RPM

Repository metadata signing is **not** an embedded RPM signature. In the mode without RPM signatures, the presence of a verified attestation + a local verifier + explicit consent does not allow bypassing the system's enforced RPM policy. R-002.

## Local signing

We create a restricted local key for signing *our* APT/RPM indexes. We do not use it to re-sign third-party DEB/RPM files. A centralized key is a centralized point of trust: access permissions, recovery, and rotation are mandatory; `localhost` is not sufficient protection.

## Acceptable risk

A compromise of the publisher, its CI, or its keys is possible in any system. Pakomichi must provide blocking of specific versions/sources but does not promise an impossible one-hundred-percent prevention. A signature confirms provenance, not the usefulness of the program.

## Protection against transfers and forks

Repo rename events (same repo ID + owner) and owner transfer events (same repo ID, different owner) have different behavior. On a transfer/ID mismatch → suspension; never search all repos by owner. A Git project deleted and recreated at the same URL has a different repo ID → reject.

## Artifact substitution

If upstream content has disappeared, substituting a neighboring asset / new digest / fork is prohibited. Verify the byte stream before passing the package to the native package manager. Verify the cache contents against the hashes and references of the current snapshot.
