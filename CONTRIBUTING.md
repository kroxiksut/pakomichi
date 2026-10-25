# Contributing to Pakomichi

Pakomichi is in the pre-alpha scaffold stage; no product behavior has been implemented yet. Start by reading [AGENTS.md](AGENTS.md), the [architecture overview](docs/en/architecture/overview.md), and the [decision records](docs/en/decisions/INDEX.md).

- For a new feature, provide its goal, boundary, relationship to v0.1, alternatives, and acceptance criteria.
- For a defect, provide a reproducible Linux environment, APT/DNF versions, logs without tokens or secrets, and the expected and actual behavior.
- For an architectural change, provide a new ADR and describe the consequences for security, data migrations, and backward compatibility.
- For research, provide a reproducible script or commands, pinned versions, a PASS/FAIL/INCONCLUSIVE result, and links to primary sources.

Do not include private keys, tokens, personal-machine data, or real internal server addresses in a pull request. Run package-manager tests in a VM or container with isolated package state.

Before submitting a source change, install Python 3, `cargo-deny` 0.19.0, and `cargo-nextest` 0.9.149 (`cargo install cargo-nextest --version 0.9.149 --locked`), then run `./scripts/quality.ps1`. Without cargo-nextest the script warns and runs the tests through `cargo test`. The script applies the repository's common secret-signature, formatting, lint, Rust and SQLite test, advisory, license, and source checks. The signature scan supplements review and proper secret handling; it does not prove that arbitrary credentials are absent.

## Contribution licensing

Unless agreed otherwise before a change is included, by submitting a contribution to Pakomichi, the author offers source code and code-like material under **MIT OR Apache-2.0**, and documentation prose and original diagrams under **CC-BY-4.0**, while retaining their copyright. Code-like material includes code blocks, commands, configuration examples, schemas, machine-readable examples, and test fixtures, including those embedded in documentation.

- Copyright assignment to the project owner is not required.
- No mandatory CLA is introduced without a separate decision by the project owner.
- Do not copy code or other material under incompatible terms. Identify the provenance and required notices for every third-party fragment.
- If a code contribution cannot be distributed under both offered software-license alternatives, or a documentation contribution cannot be distributed under CC BY 4.0, discuss the legal and architectural issue first; such a contribution must not be merged silently.
