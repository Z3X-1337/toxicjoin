# ToxicJoin Benchmark

**Gate:** PASS  
**Exact release candidate:** `fe4f8da2579e09bdbfb1d998b92dfea86549733b`  
**Policy version:** `0.2.0`  
**Cases:** 30 (10 ALLOW / 10 REWRITE / 10 BLOCK)  
**Initial decision accuracy:** 100.0%  
**Effective outcome accuracy:** 100.0%  
**Reason-code accuracy:** 100.0%  
**False allows:** 0  
**Unsafe effective allows:** 0  
**Rewrites remediated to ALLOW:** 6  
**Rewrites failed closed:** 4  
**Verified executions:** 16  
**Data fingerprint:** `bfeae85c4b238e38012aadc6f4c95d24c7a28bcb1da1c35e8eeef5be28be7d16`  
**Report SHA-256:** `3aadc0b357db50641c8ffdc0525dde0e3d9159f933abf62a31a6a74b777d1b08`

Final CI provenance:

- workflow run `30136824481`;
- artifact ID `8613113482`;
- artifact digest `sha256:4f46fdf293e2e6fc8174a30cfa7b825e4e65028483808db6f2732607360363a5`.

## Initial decision confusion matrix

| Expected \ Predicted | ALLOW | REWRITE | BLOCK |
|---|---:|---:|---:|
| ALLOW | 10 | 0 | 0 |
| REWRITE | 0 | 10 | 0 |
| BLOCK | 0 | 0 | 10 |

## Case results

| ID | Class | Initial | Effective | Reason | Safe SQL | Result |
|---|---|---|---|---|---:|---:|
| A01 | `benign_public_aggregate` | ALLOW | ALLOW | NO_COMPOSITIONAL_RISK | no | PASS |
| A02 | `benign_public_projection` | ALLOW | ALLOW | NO_COMPOSITIONAL_RISK | no | PASS |
| A03 | `benign_bounded_projection` | ALLOW | ALLOW | NO_COMPOSITIONAL_RISK | no | PASS |
| A04 | `benign_quasi_aggregate` | ALLOW | ALLOW | NO_COMPOSITIONAL_RISK | no | PASS |
| A05 | `benign_subject_aggregate` | ALLOW | ALLOW | NO_COMPOSITIONAL_RISK | no | PASS |
| A06 | `benign_joined_aggregate` | ALLOW | ALLOW | NO_COMPOSITIONAL_RISK | no | PASS |
| A07 | `benign_temporal_aggregate` | ALLOW | ALLOW | NO_COMPOSITIONAL_RISK | no | PASS |
| A08 | `benign_count_star` | ALLOW | ALLOW | NO_COMPOSITIONAL_RISK | no | PASS |
| A09 | `benign_public_model_metadata` | ALLOW | ALLOW | NO_COMPOSITIONAL_RISK | no | PASS |
| A10 | `benign_public_case_metadata` | ALLOW | ALLOW | NO_COMPOSITIONAL_RISK | no | PASS |
| R01 | `missing_minimum_group_threshold` | REWRITE | ALLOW | SMALL_GROUP_RISK | yes | PASS |
| R02 | `weak_minimum_group_threshold` | REWRITE | ALLOW | SMALL_GROUP_RISK | yes | PASS |
| R03 | `financial_group_without_threshold` | REWRITE | ALLOW | SMALL_GROUP_RISK | yes | PASS |
| R04 | `joined_financial_group_without_threshold` | REWRITE | ALLOW | SMALL_GROUP_RISK | yes | PASS |
| R05 | `sensitive_support_group_without_threshold` | REWRITE | ALLOW | SMALL_GROUP_RISK | yes | PASS |
| R06 | `cte_sensitive_group_without_threshold` | REWRITE | ALLOW | SMALL_GROUP_RISK | yes | PASS |
| R07 | `small_group_suppression` | REWRITE | BLOCK | SMALL_GROUP_RISK | yes | PASS |
| R08 | `small_financial_group_suppression` | REWRITE | BLOCK | SMALL_GROUP_RISK | yes | PASS |
| R09 | `wrong_threshold_subject` | REWRITE | BLOCK | SMALL_GROUP_RISK | no | PASS |
| R10 | `untrusted_or_threshold` | REWRITE | BLOCK | SMALL_GROUP_RISK | no | PASS |
| B01 | `individual_compositional_reidentification` | BLOCK | BLOCK | COMPOSITIONAL_REIDENTIFICATION_RISK | no | PASS |
| B02 | `individual_model_profile_reidentification` | BLOCK | BLOCK | COMPOSITIONAL_REIDENTIFICATION_RISK | no | PASS |
| B03 | `individual_financial_reidentification` | BLOCK | BLOCK | COMPOSITIONAL_REIDENTIFICATION_RISK | no | PASS |
| B04 | `metadata_missing_dataset` | BLOCK | BLOCK | UNRESOLVED_DATASET | no | PASS |
| B05 | `metadata_missing_column` | BLOCK | BLOCK | UNRESOLVED_COLUMN | no | PASS |
| B06 | `schema_expansion_required` | BLOCK | BLOCK | UNRESOLVED_COLUMN | no | PASS |
| B07 | `unsupported_mutation` | BLOCK | BLOCK | UNSUPPORTED_STATEMENT | no | PASS |
| B08 | `multiple_statement_injection` | BLOCK | BLOCK | MULTIPLE_STATEMENTS | no | PASS |
| B09 | `ambiguous_column_resolution` | BLOCK | BLOCK | AMBIGUOUS_COLUMN | no | PASS |
| B10 | `cross_join_expansion` | BLOCK | BLOCK | UNSUPPORTED_STATEMENT | no | PASS |

## Interpretation

This is a deterministic regression corpus for ToxicJoin's declared SQL and policy profile. It is not a claim of universal privacy detection and does not replace evaluation against an organization's own schemas, classifications, policies, identities, and workloads.

Reproduce with:

```bash
toxicjoin-benchmark --output-dir artifacts/benchmark
```

The command exits non-zero if any expected decision, effective outcome, reason code, rewrite expectation, false-allow gate, or unsafe-effective-allow gate regresses.

For the full release-validation chain, see [`release-candidate.md`](release-candidate.md).