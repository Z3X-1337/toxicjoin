# Low-risk aggregate: allow without unnecessary denial

This scenario is intentionally benign. It proves ToxicJoin is not a blanket blocker.

Expected deterministic outcome:

- initial decision: `ALLOW`;
- effective decision: `ALLOW`;
- reason: `NO_COMPOSITIONAL_RISK`;
- no rewrite is generated;
- the bounded query executes through the read-only path.

See [`output.json`](output.json) and [`../../docs/judge-testing.md`](../../docs/judge-testing.md).
