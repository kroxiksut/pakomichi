# R-002 — RPM: original signature, signed repodata, Attested

**English** · [Русский](../../ru/research/R-002-rpm-signatures.md)

The result of this protocol is required before implementing RPM repodata, signatures, and DNF policy.

## Hypothesis

DNF4 and DNF5 separate repository verification from package verification; system policy may require an embedded RPM signature. A separate GitHub attestation check **does not turn** an RPM into a signed RPM.

## Fixtures and matrix

2 test RPMs with identical contents (one signed with a test key and one unsigned), 1 RPM with a corrupted signature, 1 package with proven signed provenance for a test verifier, 1 RPM without confirmation. Repositories: metadata signed with a test key, and a deliberately invalid signature.

| DNF | RPM signature | Repo signature | Mandatory policy | Expected |
|---|---|---|---|---|
| 4 | valid | valid | requires | allow |
| 4 | none | valid | requires | block |
| 4 | none + verified attestation | valid | permits explicit mode | allow only after explicit consent |
| 5 | valid | valid | requires | allow |
| 5 | none | valid | requires | block |
| 5 | corrupted | valid | any | block |
| 4/5 | valid | invalid | repo check on | block |

Record the actual settings `gpgcheck`, `repo_gpgcheck`, `pkg_gpgcheck`, `gpgcheck_policy`, `%_pkgverify_level` and the syntax differences. Do not substitute commands that the specific DNF version does not support.

## Experiments

- Obtain the actual effective verification value under different configurations.
- Check that the local signer only signs `repomd.xml` and does not modify the RPM.
- Replace an RPM after the metadata is generated and make sure the package is not installed.
- Prohibit disabling the global policy and check for a correct refusal message.
- Check local key rotation for metadata and recovery after loss of the private key on a test host.

## Result

PASS only with a documented matrix in which an unsigned RPM is never accepted contrary to a mandatory OS policy. **Fallback:** on systems with a mandatory signature, only natively signed RPMs; Attested unsigned held.
