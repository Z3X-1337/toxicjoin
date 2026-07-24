# Threat-Model Delta — P1-C Output-Size Budgets

Date: 2026-07-24

## Change

ToxicJoin now bounds result release at two independent layers:

1. `DuckDBExecutor` limits each JSON-safe result cell and the cumulative serialized preview-row payload before constructing an `ExecutionResult`.
2. The HTTP API buffers `/api/*` response bodies and releases no response bytes until the complete serialized body is known to fit the configured API response budget.

These controls close TJ-SEC-018. They do not alter Policy v0.2 semantics or increase the set of queries permitted to execute.

## Default budgets

Execution output:

- per serialized cell: 64 KiB;
- cumulative execution preview payload: 256 KiB;
- nested list/map cell normalization: 32 levels.

HTTP API response:

- complete `/api/*` response body: 1 MiB.

Configuration:

- `TOXICJOIN_MAX_CELL_BYTES`
- `TOXICJOIN_MAX_RESULT_BYTES`
- `TOXICJOIN_MAX_RESPONSE_BYTES`

The execution configuration requires `max_cell_bytes <= max_result_bytes` and fails closed on invalid environment values.

## Threats reduced

- **Single-cell amplification:** one row can no longer return an arbitrarily large string, binary value, list, map, or fallback string representation through `ExecutionResult`.
- **Many-cell amplification inside a bounded row count:** the existing 50-row preview limit is now complemented by a serialized-byte budget.
- **Nested-value recursion:** deeply nested list/map cells are rejected before JSON-safe normalization can recurse without a product-defined bound.
- **Oversized API release:** large plans, receipts, verification structures, or result payloads cannot be partially streamed to a caller. The response gate buffers the complete API body and either releases it intact or replaces it with a small stable error.
- **Chunked-response bypass:** the HTTP budget accumulates all `http.response.body` chunks rather than trusting `Content-Length`.

## Enforcement behavior

Execution-budget violations raise `ExecutionError` with deterministic reason code `RESULT_SIZE_LIMIT`. The verifier therefore treats the execution as failed, exposes no `ExecutionResult`, and the pipeline persists a normal BLOCK receipt without row payloads.

HTTP response-budget violations return HTTP 422 with:

```json
{
  "detail": {
    "code": "RESPONSE_SIZE_LIMIT_EXCEEDED",
    "max_bytes": 1048576
  }
}
```

No byte from the oversized original response is sent before this replacement decision.

## Negative security tests

Coverage includes:

- one oversized cell produces a BLOCK with no released execution rows and no oversized marker in the result or persisted receipt;
- multiple individually valid cells exceed the cumulative execution payload budget and fail closed;
- an oversized pipeline response is replaced before release while preserving API no-store/security headers;
- a deliberately multi-chunk streaming API response cannot leak its first chunk before the total-size decision;
- ordinary small API responses remain unchanged;
- execution-output and API-response environment limits reject invalid values and impossible cell/result relationships.

## Residual risk and explicit non-goals

- DuckDB has already materialized the values returned by `fetchmany()` before ToxicJoin can measure their serialized size. P1-C controls normalization and release, not the database engine's internal allocation for producing one value. DuckDB query timeout, SQL complexity limits, process/container memory limits, and deployment-level resource controls remain required.
- FastAPI/Pydantic may construct an in-memory response object before ASGI response-body accounting sees its final bytes. The executor's 256 KiB row-payload limit and existing request/SQL budgets constrain the dominant untrusted structures, while the HTTP gate guarantees non-release of an oversized final body.
- The response middleware intentionally applies to all `/api/*` responses, including public health/benchmark/demo endpoints. Static web assets and SPA files are not buffered by this control.
- These limits are safety/availability bounds, not privacy budgets, billing quotas, or substitutes for the P2 cumulative-disclosure ledger.
