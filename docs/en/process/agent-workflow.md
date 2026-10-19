# Operating procedure for a programming agent

**English** · [Русский](../../ru/process/agent-workflow.md)

## Getting started

1. Read `AGENTS.md`, `docs/README.md`, the related entry in the local `TASKS_RU.md`, and the required ADRs.
2. Check the task's dependencies, the results of research tasks, and the branch state. The `R-001` document must not be treated as the research result itself.
3. Select an entry with an exact ID from `TASKS_RU.md`; if the work is carried out through an Issue, use the same ID and record the expected behavior, boundaries, and tests.
4. Work in a minimal vertical slice; do not start a broad infrastructure overhaul without an ADR.

## On every change

- Run unit and integration tests and, when required, an isolated apt/dnf VM test. For network/cryptographic modules, run negative tests.
- Update the documents that change as a consequence of actual behavior. If reality contradicts an ADR, record the research result and the newly proposed decision. Discuss it with the project owner.
- Leave a task only with technical evidence that its conditions are met. Maintain the log `docs/en/process/decisions-and-evidence.md` once real artifacts exist.

## Working statuses

Statuses are kept only in `TASKS_RU.md`: `TODO -> READY (dependencies met) -> IN_PROGRESS -> TESTING -> DONE`. `BLOCKED` is permitted with a reason and a fallback scenario. Integration work must not be completed on the strength of a single passing mock unit test instead of a native E2E test.

## Research principle

Research tasks have explicit PASS/FAIL/INCONCLUSIVE conditions and a fallback. If the chosen hypothesis is not confirmed, do not "fix" someone else's system for the sake of a test; instead, propose the agreed safe limited mode.

## Completion report

Briefly: ID; what was done; commands and output; negative tests; files; new risks; ADR; what remains; **confirmed or only assumed**.
