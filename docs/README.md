# Pakomichi — Documentation

**English** · [Русский](README.ru.md)

| Section | Contents |
|---|---|
| [`product/`](en/product/) | Product problem, typical scenarios, 0.1 scope |
| [`architecture/`](en/architecture/overview.md) | Component layout, data model, states, families, policies, cache, and recovery |
| [`specifications/`](en/specifications/) | Exact GitHub, APT, DNF, CLI/API, and error contracts |
| [`decisions/`](en/decisions/INDEX.md) | Accepted ADRs: decision, rationale, alternatives, constraints |
| [`research/`](en/research/INDEX.md) | Blocking R-001…R-004, methods, and the evidence template |
| [`prototypes/`](en/prototypes/P0-004-stack.md) | Prototype reports backing ADRs (P0-004 for ADR-017) |
| [`testing/`](en/testing/) | Linux matrix, E2E, negative tests, alpha criteria |
| [`process/`](en/process/) | Agent operating procedure, isolated VMs/credentials, the Rust baseline (ADR-015), and the decision and evidence log |
| [`references.md`](en/references.md) | Primary APT, DNF, systemd, and GitHub documentation |
| [`roadmap.md`](en/roadmap.md) | Feature sequence and milestones |

## Repository-level documents

| File | Contents |
|---|---|
| [`README.md`](../README.md) | Project overview |
| [`AGENTS.md`](../AGENTS.md) | Mandatory rules for programming agents |
| [`LICENSING.md`](../LICENSING.md) | Code and documentation licensing |
| [`SECURITY.md`](../SECURITY.md) | Vulnerability reporting |

**Document state:** the set reflects the state as of 19 October 2026: ADR-001 through ADR-017 are accepted, and R-001 through R-004 have not been run. Every unverified mechanism is marked `RESEARCH_REQUIRED` or `ASSUMPTION` and tied to an R study. Do not present it as confirmed without a results protocol.

---

`docs/en/` is canonical; `docs/ru/` is a maintained localization with the same set of files. When editing a document, update its counterpart in the same change. A difference between the languages is a translation defect, not a change of decision.
