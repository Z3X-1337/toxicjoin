# Flagship: verified rewrite to safe execution

An analytics agent proposes a churn-risk aggregate grouped by region without a minimum distinct-subject threshold.

ToxicJoin returns `REWRITE` with `SMALL_GROUP_RISK`, adds:

```sql
HAVING COUNT(DISTINCT c.customer_id) >= 20
```

The rewritten SQL is then reparsed, grounded again in governed metadata, reevaluated, executed read-only only after the final decision becomes `ALLOW`, and independently verified.

Observed deterministic evidence:

- three result groups;
- 40 distinct subjects in every group;
- verification passed;
- the persisted receipt contains hashes, policy/governance evidence, and execution metadata, but no returned result rows.

See [`output.json`](output.json) for the compact sample and [`../../docs/judge-testing.md`](../../docs/judge-testing.md) for the reproducible 90-second path.
