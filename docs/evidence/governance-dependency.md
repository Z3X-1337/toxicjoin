# ToxicJoin Governance Dependency Evaluation

**Gate:** PASS  
**Exact release candidate:** `fe4f8da2579e09bdbfb1d998b92dfea86549733b`  
**Policy version:** `0.2.0`  
**Unsafe effective allows under degraded governance:** 0

Final provenance:

- workflow run `30136824433`;
- artifact ID `8613089999`;
- artifact digest `sha256:a73eafdd701019f36eac27a1fcc5a81df52f697bfe66e5961295ab77d6bcb690`;
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

For the complete exact-head release evidence, see [`release-candidate.md`](release-candidate.md).