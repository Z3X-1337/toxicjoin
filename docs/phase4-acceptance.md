# Phase 4 acceptance criteria

Phase 4 closes only when all of the following are proven on one exact head revision:

1. `TJ-P1-TEST-PORT-001` is fixed with canonical path matching.
2. The traceback-redaction test inspects at least one real `proof_handoff.py` frame and the constructor frame.
3. The complete locked test suite passes on Ubuntu 24.04 and Windows Server 2025 for the declared Python 3.11 and 3.12 patches.
4. Linux and Windows collect the same test inventory and produce the same normalized outcomes and result counts for each Python minor.
5. Exception context and cause remain detached and the secret marker is absent from every target-frame local set.
6. Evidence records exact commit, tree, operating system, Python version, pytest inventory/outcome hashes, worktree state, and SHA-256 checksums.
7. No Live DataHub, Phase 5, PR #118, PostgreSQL, Vercel, Devpost, release-tag, or repository-cleanup work is performed.
8. The pull request remains unmerged until explicit authorization tied to the exact final head SHA.
