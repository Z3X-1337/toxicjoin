# ToxicJoin Judge Sample Outputs

This directory gives reviewers a compact, no-setup view of ToxicJoin's four core outcomes and the evidence behind them.

These examples are not hand-written mock outputs. They summarize deterministic scenarios and retained evidence that are already exercised by CI and documented in the repository.

## Start here

1. [`flagship-rewrite/`](flagship-rewrite/) — `REWRITE → ALLOW` after a verified minimum-subject threshold is added.
2. [`fail-closed-block/`](fail-closed-block/) — compositional re-identification risk is blocked before DuckDB execution.
3. [`low-risk-allow/`](low-risk-allow/) — benign aggregate work is allowed without unnecessary remediation.
4. [`datahub-writeback/`](datahub-writeback/) — real DataHub OSS metadata is read through MCP, a Decision is written, then a fresh MCP process reads it back.

## Full retained evidence

- [30-case benchmark](../docs/evidence/benchmark.md)
- [Machine-readable benchmark summary](../docs/evidence/benchmark-summary.json)
- [Real DataHub OSS evidence](../docs/evidence/datahub-live.md)
- [90-second judge testing guide](../docs/judge-testing.md)
- [Threat model](../docs/threat-model.md)

## Important scope

ToxicJoin's benchmark is a deterministic regression corpus for the declared supported SQL and policy profile. It is not a claim of universal privacy detection. Unsupported or ambiguous SQL fails closed.
