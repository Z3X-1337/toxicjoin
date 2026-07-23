# External DataHub Failure 0002 — MCP snapshot verification

Status: **FAILED_UNDIAGNOSED**

The first fully progressed external DataHub run reached a real DataHub OSS instance, successfully seeded the frozen UCI stewardship metadata through the DataHub Python SDK, and then failed while verifying the same governed snapshot through the official DataHub MCP server.

Baseline:

- Workflow: `Research External DataHub Validation`
- Run: `30051723182`
- Job: `89355084740`
- Tested research head: `14ec5fedb3e858c04afcc7a8b3423f764952e27b`
- Failed step: `Verify governed snapshot through official DataHub MCP`

Stages that passed before the failure:

1. DataHub OSS quickstart started successfully.
2. DataHub GMS and frontend health checks passed.
3. The official UCI Diabetes archive was downloaded.
4. The typed external DuckDB profile was rebuilt from the official source.
5. The frozen stewardship map was seeded into the live DataHub instance through the DataHub SDK.
6. The failure occurred only when the official MCP verification attempted to read/normalize the governed snapshot.

All stable ToxicJoin gates on the same research head remained green, including normal CI, adversarial mutation evidence, compositional ablation, governance-dependency evidence, external source acquisition, and the proof-carrying authorization gate.

## Original expectations — frozen

The diagnostic rerun must not weaken these expectations based on observed output:

- 5 governed DataHub entities are returned by MCP;
- 59 governed schema fields are visible;
- normalized category counts are exactly:
  - `DIRECT_IDENTIFIER`: 5
  - `STABLE_PSEUDONYM`: 5
  - `QUASI_IDENTIFIER`: 3
  - `SENSITIVE_ATTRIBUTE`: 44
  - `PUBLIC_OR_LOW_RISK`: 2
- no governed field normalizes to `UNCLASSIFIED`;
- upstream lineage for flagship `outcomes.readmitted` is non-empty and reaches the raw external source lineage;
- no patient rows are retained in diagnostic evidence.

## Scientific handling

No stewardship category, expected count, or lineage expectation will be changed before the observed MCP payload is captured.

The next run is diagnostic only. It will persist safe metadata observed from the official MCP before evaluating the frozen expectations: entity URNs, field paths, field tags/glossary terms, normalized categories, discovered tool names, lineage relationship metadata, and any adapter error type/message. Raw patient rows are never included.

After the diagnostic artifact is inspected, the failure will be classified as one of:

- `MCP_CONTRACT_OR_PAYLOAD`
- `CLASSIFICATION_VISIBILITY`
- `LINEAGE_SEMANTICS`
- `TOXICJOIN_ADAPTER`
- `DATAHUB_SDK_SEED`
- `INFRASTRUCTURE`

Any fix must retain this baseline and report before/after behavior.
