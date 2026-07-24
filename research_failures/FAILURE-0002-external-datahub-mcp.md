# External DataHub Failure 0002 — MCP snapshot verification

Status: **CONFIRMED FIX — `TOXICJOIN_ADAPTER / CLASSIFICATION_VISIBILITY`**

The first fully progressed external DataHub run reached a real DataHub OSS instance, successfully seeded the frozen UCI stewardship metadata through the DataHub Python SDK, and then failed while verifying the same governed snapshot through the official DataHub MCP server.

Baseline:

- Workflow: `Research External DataHub Validation`
- First failing run: `30051723182`
- First diagnostic run with observed metadata: `30052481732`
- Diagnostic job: `89357297982`
- Diagnostic artifact: `8581696049`
- Diagnostic artifact digest: `sha256:8026010b0c6bc068548424ab6104ceeac8321230d994aeb4c0ce940433e54ff4`
- Original tested research head: `14ec5fedb3e858c04afcc7a8b3423f764952e27b`

## What the observed failing MCP run proved

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

This meant a legitimate governance annotation written through the SDK/UI-style editable metadata path could become invisible to ToxicJoin's classifier even though DataHub returned the dataset, schema, and lineage correctly.

Classification: `TOXICJOIN_ADAPTER / CLASSIFICATION_VISIBILITY`.

## Original expectations — never changed

The corrective run was required to satisfy the original expectations exactly:

- 5 governed DataHub entities returned by MCP;
- 59 governed schema fields visible;
- normalized category counts exactly:
  - `DIRECT_IDENTIFIER`: 5
  - `STABLE_PSEUDONYM`: 5
  - `QUASI_IDENTIFIER`: 3
  - `SENSITIVE_ATTRIBUTE`: 44
  - `PUBLIC_OR_LOW_RISK`: 2
- zero governed fields normalized to `UNCLASSIFIED`;
- upstream lineage for flagship `outcomes.readmitted` non-empty and reaching the raw external source lineage;
- no patient rows retained in diagnostic evidence.

## Corrective change

1. Added regression coverage for the official MCP cleaned response forms `editedTags` and `editedGlossaryTerms`.
2. Changed the ToxicJoin DataHub adapter to merge system and edited field governance metadata.
3. Preserved fail-closed behavior when merged metadata implies conflicting sensitivity categories.
4. Did not change the UCI source, external warehouse projection, frozen stewardship map, policy labels, or expected category counts.

## Confirmation run

The same real DataHub OSS + official MCP experiment passed after the adapter-only fix.

- Passing run: `30053590829`
- Tested head: `06b07627c6edfa377d7672bd57598792f5f965e6`
- Evidence artifact: `8582016987`
- Evidence artifact digest: `sha256:90a4b8f56f0c6bdd65ef4923af20a042b2990a9b2848fdaa86dbae4c0e26941e`
- Warehouse profile SHA-256: `d56cb3525915265d148c29ed299000ec2226e6c400a0eb9fcc31a1fe9ab76868`
- MCP observation report SHA-256: `74c5bfae416d603ae4e9af8082305c3843c278360692031380c6abc8c3e76227`
- Seed report SHA-256: `c9c9170c201d3ab0232866c5bd4261bf94b29d7bb8648619a058e646a9660c51`

Observed after the fix:

- entities: **5/5**;
- fields: **59/59**;
- `DIRECT_IDENTIFIER`: **5**;
- `STABLE_PSEUDONYM`: **5**;
- `QUASI_IDENTIFIER`: **3**;
- `SENSITIVE_ATTRIBUTE`: **44**;
- `PUBLIC_OR_LOW_RISK`: **2**;
- `UNCLASSIFIED`: **0**;
- lineage relationships for the flagship field: **1**;
- raw external upstream lineage observed: **true**;
- expectation failures: **0**;
- patient rows retained in evidence: **false**.

The full stable ToxicJoin CI suite also remained green on the fixed head, including Python 3.11/3.12 tests, frontend checks, benchmark evidence, and the hardened production-container flagship flow.

## Research conclusion

This failure was valuable: a live external DataHub workload exposed a real compatibility gap that the original deterministic fixture and earlier hackathon evidence did not reveal. The fix is supported by both contract-level regression tests and an unchanged live before/after experiment.
