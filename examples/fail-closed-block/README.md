# Fail closed: block before execution

This scenario combines a stable pseudonym, two quasi-identifiers, and a sensitive support attribute at individual granularity.

ToxicJoin returns `BLOCK` with `COMPOSITIONAL_REIDENTIFICATION_RISK` before the database executor is called.

Expected retained evidence:

- initial decision: `BLOCK`;
- effective decision: `BLOCK`;
- verification: `null` because no execution is allowed;
- receipt execution metadata: `null`;
- DuckDB is not called.

This is the negative guarantee the demo is designed to prove: unsafe composition does not reach execution.

See [`output.json`](output.json) and the exact reproducible path in [`../../docs/judge-testing.md`](../../docs/judge-testing.md).
