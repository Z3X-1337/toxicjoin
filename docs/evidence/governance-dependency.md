# ToxicJoin Governance Dependency Evaluation

**Gate:** PASS  
**Exact runtime candidate:** `e139fa99bd666505ed83a18188423722405695a2`  
**Policy version:** `0.2.0`  
**Unsafe effective allows under degraded governance:** 0

Exact-head provenance:

- workflow run `30140102647`;
- artifact ID `8614165940`;
- artifact digest `sha256:b9bf5e1770b19ad46a597da7ab743ab50536b349f46a7305f661b27687bfe7fb`;
- report SHA-256 `25c1b7c189a8ca248723138df2065ddb0669a9f4f46f6e7abe8f81b7b1a48d9f`.

The SQL request, deterministic synthetic warehouse, subject key, policy, parser, rewriter, executor, and independent verifier are fixed. Only the normalized governance state changes.

| Governance state | Initial | Effective | Executed? | Result |
|---|---:|---:|---:|---:|
| complete-governance | `REWRITE` | `ALLOW` | yes | PASS |
| unclassified-sensitive-field | `BLOCK` | `BLOCK` | no | PASS |
| missing-sensitive-field | `BLOCK` | `BLOCK` | no | PASS |
| missing-governed-dataset | `BLOCK` | `BLOCK` | no | PASS |

## Interpretation

Complete governed context produces the intended REWRITE -> ALLOW path and executes only after independent verification. Removing or degrading the governance required for the same analytical request fails closed before database execution.

This is a deterministic causality test over the normalized governance contract. It proves that governance changes the authorization result; it is not a second live DataHub deployment.

Real DataHub OSS connectivity, MCP acquisition, lineage normalization, Decision write-back, and fresh-process read-back are proven separately in [`datahub-live.md`](datahub-live.md).

This evaluation does not claim ToxicJoin can independently detect a confidently but incorrectly governed label without a separate source of truth.

For the complete release evidence, see [`release-candidate.md`](release-candidate.md).