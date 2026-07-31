# Windows portability and toolchain parity

This document defines the Product Readiness Phase 4 portability boundary.

## Scope

Phase 4 closes `TJ-P1-TEST-PORT-001` and proves that the complete locked Python test suite behaves identically on the declared Linux and Windows toolchains. It does not start Live DataHub, browser E2E, release identity, repository cleanup, or PR #118 disposition work.

## Exact matrix

| Operating system | Python |
| --- | --- |
| Ubuntu 24.04 x64 | 3.11.15 and 3.12.13 |
| Windows Server 2025 x64 | 3.11.9 and 3.12.10 |

Every matrix cell consumes `uv.lock` through the Phase 3 bootstrap authority and runs the complete test suite through the same standard-library evidence wrapper.

## Security invariant

The proof-handoff constructor failure test identifies source frames by canonical real path rather than a POSIX-only suffix. Evidence is valid only when at least one real `toxicjoin.agent.proof_handoff` frame is inspected, the constructor frame is present, exception context and cause are absent, and the secret marker is absent from all target-frame locals.

A zero-frame inspection is a hard failure.

## Parity evidence

Each native cell emits:

- the exact commit and tree identity;
- operating-system and Python identity;
- complete pytest log and JUnit report;
- normalized test inventory and outcome hashes;
- real-frame traceback-redaction results;
- worktree-cleanliness results;
- `SHA256SUMS` for the evidence files.

The parity job downloads all four artifacts and compares Linux with Windows by Python minor. It fails closed when the Git tree, collected test inventory, normalized outcomes, result counts, traceback invariant, or worktree state differ.

## Declared boundary

macOS bootstrap remains covered by Phase 3. Phase 4's behavioral parity claim is specifically Linux versus Windows because `TJ-P1-TEST-PORT-001` was a Windows full-suite defect. No Live DataHub command is permitted in this workflow.
