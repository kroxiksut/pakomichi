# Pakomichi security

Pakomichi verifies that a release artifact belongs to the **selected Git repository** and protects local indexes against substitution. It does **not** guarantee that the upstream project contains no malicious code, that its CI is flawless, or that every installation script in a third-party package is safe.

Mandatory safeguards: never transfer trust from one Git repository to another merely because their names match; verify repository identity and signatures or attestations; pin the accepted artifact's SHA-256; do not execute installation scripts during inspection; separate privileges; protect the local signing key; and never weaken global APT/DNF policy.

Verification of external content is not an endorsement of its publisher. When trust is violated, suspend the source; do not automatically remove applications that were installed earlier.

Before the repository becomes public, the project owner must publish a private vulnerability-reporting channel. Do not invent an email address or promise an SLA.
