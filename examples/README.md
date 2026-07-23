# ToxicJoin Sample Outputs

These examples let judges inspect the supported safety behavior without running the project. They use only deterministic synthetic data.

## 1. Unsafe individual composition

- Input: [`unsafe-individual-export.sql`](unsafe-individual-export.sql)
- Expected initial decision: `BLOCK`
- Expected effective decision: `BLOCK`
- Expected reason: `COMPOSITIONAL_REIDENTIFICATION_RISK`
- Database called: **No**

The projected output combines a stable customer pseudonym, age band, precise area, and sensitive support category. ToxicJoin evaluates the composed output rather than treating each source dataset independently.

## 2. Sensitive grouped analysis requiring remediation

- Original input: [`regional-churn-original.sql`](regional-churn-original.sql)
- Generated safe SQL: [`regional-churn-safe.sql`](regional-churn-safe.sql)
- Expected initial decision: `REWRITE`
- Expected reason: `SMALL_GROUP_RISK`
- Expected final decision: `ALLOW`
- Required privacy boundary: `COUNT(DISTINCT c.customer_id) >= 20`
- Deterministic result: three region groups, each containing 40 distinct subjects

The safe query is reparsed, grounded, and passed through the same deterministic policy before execution. It is then independently verified against the complete DuckDB result.

## 3. Low-risk aggregate

- Input: [`public-order-counts.sql`](public-order-counts.sql)
- Expected initial decision: `ALLOW`
- Expected effective decision: `ALLOW`
- Expected reason: `NO_COMPOSITIONAL_RISK`

## Evidence

- [Measured 30-query benchmark](../docs/evidence/benchmark.md)
- [Machine-readable benchmark summary](../docs/evidence/benchmark-summary.json)
- [90-second judge testing guide](../docs/judge-testing.md)
- [Threat model](../docs/threat-model.md)
- [Live DataHub integration guide](../docs/datahub-live-integration.md)
- [Live DataHub evidence — pending verified run](../docs/submission/devpost-draft.md)

## Boundaries

ToxicJoin does not claim universal privacy detection or general SQL repair. The current rewrite is deliberately narrow: it adds or strengthens a minimum distinct-subject threshold on a supported already-grouped analytical query. Unsupported or ambiguous transformations fail closed.
