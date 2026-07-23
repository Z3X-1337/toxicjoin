# External DataHub Failure 0002 — MCP snapshot verification

Status: **DIAGNOSED — `TOXICJOIN_ADAPTER / CLASSIFICATION_VISIBILITY`**

The first fully progressed external DataHub run reached a real DataHub OSS instance, successfully seeded the frozen UCI stewardship metadata through the DataHub Python SDK, and then failed while verifying the same governed snapshot through the official DataHub MCP server.

Baseline:

- Workflow: `Research External DataHub Validation`
- First failing run: `30051723182`
- First diagnostic run with observed metadata: `30052481732`
- Diagnostic job: `89357297982`
- Diagnostic artifact: `8581696049`
- Artifact digest: `sha256:8026010b0c6bc068548424ab6104ceeac8321230d994aeb4c0ce940433e54ff4`
- Original tested research head: `14ec5fedb3e858c04afcc7a8b3423f764952e27b`

## What the observed MCP run proved

The failure was narrower than the original error suggested:

- configured entities returned: **5/5**;
- schema fields returned: **59/59**;
- production `DataHubSnapshotLoader` completed entity/schema/lineage loading;
- flagship upstream lineage relationship count: **1**;
- raw external source lineage was observed;
- normalized categories: **59 `UNCLASSIFIED`**;
- every frozen expected classification count therefore remained unmet.

No stewardship category or expected count was changed after observing this result.

## Root cause

DataHub MCP v0.6.0 distinguishes system schema metadata from user-edited field metadata. Its response cleaner can expose curated field tags and glossary terms as `editedTags` and `editedGlossaryTerms` when they differ from system metadata.

DataHub's Python SDK `SchemaField.add_tag()` uses editable schema metadata outside ingestion attribution. ToxicJoin's live DataHub adapter, however, only parsed the `tags` and `glossaryTerms` response keys. It did not parse or merge the MCP `editedTags` / `editedGlossaryTerms` forms.

This means a legitimate governance annotation written through the SDK/UI-style editable metadata path could become invisible to ToxicJoin's classifier even though DataHub returned the dataset, schema, and lineage correctly.

Classification: `TOXICJOIN_ADAPTER / CLASSIFICATION_VISIBILITY`.

## Original expectations — still frozen

The fix is not allowed to weaken these expectations:

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

## Corrective action

1. Add regression coverage for the official MCP cleaned response forms `editedTags` and `editedGlossaryTerms`.
2. Merge system and edited classification metadata in the ToxicJoin adapter.
3. Preserve fail-closed behavior when merged metadata implies conflicting sensitivity categories.
4. Re-run the same live DataHub OSS + official MCP experiment against the unchanged UCI source, unchanged stewardship map, and unchanged 59-field expectations.

The corrective change is considered confirmed only if the real external DataHub run passes without changing the frozen governance map or expected category counts.
