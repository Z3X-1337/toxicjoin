# Integrating ToxicJoin in an AI Data Agent Workflow

ToxicJoin is designed to sit on the **execution boundary**, not inside the agent's free-form reasoning loop.

The integration rule is simple:

```text
agent proposes analytical SQL
        ↓
ToxicJoin evaluates governed context
        ↓
only effective ALLOW may produce accepted data
```

An agent or orchestration framework must never treat its own SQL generation, tool-selection reasoning, or confidence score as authorization.

## Recommended control-plane contract

For an external data agent, treat these HTTP endpoints as the public boundary:

| Endpoint | Purpose | Database execution |
|---|---|---:|
| `GET /api/health` | Confirm the configured runtime and receipt store are ready | No |
| `POST /api/analyze` | Preview the deterministic policy result and any supported safe rewrite | No |
| `POST /api/execute-safe` | Run the full policy → rewrite → re-evaluate → execute → verify path | Only after effective `ALLOW` |
| `GET /api/receipts/{receipt_id}` | Retrieve and integrity-check the persisted decision receipt | No |

The API contracts are strict Pydantic models with unknown fields rejected.

## Request contract

Both `/api/analyze` and `/api/execute-safe` accept the same request shape:

```json
{
  "task_purpose": "Find regions with elevated churn risk",
  "sql": "SELECT ...",
  "subject_key": {
    "dataset": "customers",
    "field_path": "customer_id",
    "alias": "c"
  },
  "dialect": "duckdb"
}
```

Required semantics:

- `task_purpose` describes the analytical intent;
- `sql` is the **proposed**, untrusted SQL;
- `subject_key` identifies the expected distinct subject used by threshold policy and verification;
- `dialect` defaults to `duckdb` in the current reference implementation.

The subject alias may be omitted when the physical binding is unambiguous. Ambiguity is a fail-closed condition, not a reason to guess.

## One-call execution pattern

For an autonomous agent, prefer `/api/execute-safe` over an `analyze → manually execute` pattern.

Example:

```bash
curl --fail-with-body \
  -H 'Content-Type: application/json' \
  -X POST http://127.0.0.1:8000/api/execute-safe \
  -d '{
    "task_purpose": "Find regions with elevated churn risk",
    "sql": "SELECT c.coarse_region, AVG(r.churn_score) AS average_churn, COUNT(DISTINCT c.customer_id) AS subject_count FROM customers c JOIN retention_scores r ON c.customer_id = r.customer_id GROUP BY c.coarse_region",
    "subject_key": {
      "dataset": "customers",
      "field_path": "customer_id",
      "alias": "c"
    },
    "dialect": "duckdb"
  }'
```

The caller should branch on `effective_decision` only:

```text
ALLOW   → the ToxicJoin-controlled execution path completed or was authorized;
          inspect verification before consuming an executed result.

BLOCK   → stop. Do not execute the original SQL through another tool.

REWRITE → do not execute outside ToxicJoin. A successful supported rewrite is
          reparsed and reevaluated by ToxicJoin; the accepted path must end in
          effective ALLOW before execution.
```

In the flagship path, the initial decision is `REWRITE`, but the effective decision becomes `ALLOW` only after the generated query passes the same parser, governed-context resolution, deterministic policy, and independent verification gates.

## Response contract

`POST /api/analyze` and `POST /api/execute-safe` return a stable `PipelineResponse` containing:

- `effective_decision` — the final authorization state;
- `initial_decision` — deterministic decision and reason evidence for the proposed SQL;
- `final_decision` — the reevaluated decision when a rewrite occurred;
- `safe_sql` — the supported rewritten SQL when available;
- `original_plan` and `final_plan` — parsed query evidence;
- `verification` — independent execution/result verification when execution occurred;
- `receipt` — the sanitized immutable decision receipt.

An orchestration layer should not infer success merely from the presence of `safe_sql`. The controlling conditions are the effective decision and, when execution occurred, the verification result.

## Agent-side pseudocode

```python
proposal = agent.propose_sql(task)

response = toxicjoin.execute_safe(
    task_purpose=task.purpose,
    sql=proposal.sql,
    subject_key=task.subject_key,
)

if response.effective_decision != "ALLOW":
    return agent.report_denial(response.initial_decision.reason_codes)

if response.verification is not None and not response.verification.passed:
    raise RuntimeError("ToxicJoin verification did not pass")

return agent.consume_verified_result(response)
```

The pseudocode illustrates orchestration semantics; it is not a separate SDK shipped by this repository.

## Critical anti-bypass rule

A platform integration is unsafe if it does this:

```text
ToxicJoin BLOCK
      ↓
agent retries the original SQL using another warehouse tool
```

The enforcement boundary only has value when **all protected analytical execution is routed through the guarded path**.

For a real deployment, the warehouse credential available to the autonomous agent should therefore be constrained so the agent cannot silently bypass the control plane. ToxicJoin's reference Docker path demonstrates the enforcement logic and read-only execution model; organization-specific identity, network, and warehouse authorization controls remain deployment responsibilities.

## Governance integration boundary

The zero-configuration packaged application starts in deterministic **fixture mode** for reproducible judging. It does not silently represent fixture metadata as live DataHub.

The stable live integration is proven separately against DataHub OSS and the official DataHub MCP Server. ToxicJoin's pipeline is built around a context-resolver boundary so governed context can be supplied independently of the policy engine.

A production integration should preserve these invariants:

1. parse SQL before governance lookup;
2. resolve every referenced physical dataset and field;
3. map DataHub governance only through deterministic configured classifications;
4. fail closed on missing, conflicting, incomplete, or ambiguous context;
5. never send raw sensitive warehouse rows to an LLM;
6. keep the deterministic policy as authorization authority;
7. write sanitized institutional memory back to DataHub only after the decision path is complete.

See:

- [architecture and trust boundaries](architecture.md);
- [live DataHub evidence](evidence/datahub-live.md);
- [governance-dependency evidence](evidence/governance-dependency.md);
- [Compositional Risk Review Agent Skill](../skills/compositional-risk-review/SKILL.md).

## Receipt handling

Every decision path creates a content-hashed receipt. Retrieve one with:

```bash
curl --fail-with-body http://127.0.0.1:8000/api/receipts/<receipt_id>
```

The receipt store verifies integrity when reading a receipt. A missing receipt returns `404`; an integrity failure returns `409`.

Returned warehouse rows are deliberately excluded from receipts.

## Operational readiness checks

Before allowing an agent to send protected work, require:

```bash
curl --fail-with-body http://127.0.0.1:8000/api/health
```

The runtime reports `ok` only when the configured database is present and the receipt store is writable. A deployment should treat a degraded enforcement service as unavailable and fail closed rather than routing around it.

## What this integration does not claim

The reference implementation does not claim:

- universal SQL support;
- universal re-identification detection;
- arbitrary SQL repair;
- a hosted multi-tenant production control plane;
- that the public deterministic Replay is live execution;
- that organization-specific IAM, warehouse credentials, or network enforcement are solved by the demo package.

Its contract is narrower: for the declared supported SQL and policy profile, an AI data agent can propose work, while governed deterministic authorization and verification remain outside the model's control.
