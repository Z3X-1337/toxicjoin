# Phase 4 evidence schema

The native evidence file is `phase4-portability-evidence.json` with schema version `1.0`.

Required top-level sections are `git`, `environment`, `pytest`, `traceback_secret_redaction`, and `worktree`.

The parity comparison requires one Linux and one Windows record for each declared Python minor. It compares exact Git tree identity, normalized test inventory hash, normalized test outcome hash, result counts, suite return codes, real target-frame counts, traceback-redaction status, and clean-worktree status.

Every evidence directory includes a `SHA256SUMS` manifest covering its JSON, JUnit XML, and pytest log. The comparison artifact has its own checksum manifest.
