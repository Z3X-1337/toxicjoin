---
name: compositional-risk-review
description: Review agent-generated analytical SQL for compositional privacy risk using DataHub governed context before execution. Use when a query joins stable pseudonyms, quasi-identifiers, sensitive attributes, model outputs, or requires a trusted minimum-subject threshold.
license: Apache-2.0
---

# Compositional Risk Review

Use this skill before an AI data agent executes analytical SQL that combines governed datasets.

The skill gathers evidence and explains risk. It does **not** own the final enforcement decision. ToxicJoin's deterministic policy engine remains the authority for `BLOCK`, `REWRITE`, or `ALLOW`.

## Inputs

Require all of the following:

- the user's analytical purpose;
- the proposed SQL;
- the expected subject key, such as `customers.customer_id`;
- the configured minimum distinct-subject threshold;
- access to DataHub governed metadata.

If the purpose, SQL, subject key, or governed metadata cannot be resolved, fail closed and do not authorize execution.

## Required DataHub tools

Use the governed DataHub interfaces represented by these MCP tools:

- `get_entities` — verify configured datasets exist and obtain governed entity context;
- `list_schema_fields` — resolve every referenced physical field and its governance metadata;
- `get_lineage` — inspect upstream relationships for sensitive or derived fields;
- `save_document` — persist the final sanitized decision as DataHub institutional memory;
- `grep_documents` — independently verify the persisted decision from a fresh MCP process.

Never infer that a missing tool succeeded. If a required tool, input contract, entity, field, classification, or pagination result is unavailable or ambiguous, fail closed.

## Procedure

### 1. Resolve physical query evidence

Use a real SQL parser before applying privacy logic. Resolve:

- physical source datasets;
- aliases and CTE source mappings;
- projected columns;
- all referenced governed columns;
- join keys;
- group-by keys;
- aggregate functions;
- any existing `COUNT(DISTINCT subject_key)` threshold.

Do not treat a CTE alias as a governed physical column. Trace it to the underlying source field.

### 2. Ground every referenced field in DataHub

For each physical dataset and field:

1. verify the dataset with `get_entities`;
2. fetch schema fields with `list_schema_fields` using bounded pagination;
3. collect relevant tags and glossary terms;
4. map governance labels only through the configured deterministic classification map.

Expected ToxicJoin categories are:

- `DIRECT_IDENTIFIER`;
- `STABLE_PSEUDONYM`;
- `QUASI_IDENTIFIER`;
- `SENSITIVE_ATTRIBUTE`;
- `PUBLIC_OR_LOW_RISK`;
- `UNCLASSIFIED`.

Conflicting categories or `UNCLASSIFIED` fields are fail-closed conditions.

### 3. Inspect lineage when derived sensitivity matters

Use `get_lineage` for sensitive model outputs or other derived fields when upstream context can change the privacy interpretation.

Treat missing or structurally invalid lineage as uncertainty. Do not fabricate upstream relationships.

### 4. Evaluate compositional risk

The deterministic ToxicJoin policy applies these core precedence rules:

1. `BLOCK` outranks `REWRITE` and `ALLOW`.
2. A direct identifier combined with a sensitive attribute at row level is blocked.
3. A stable pseudonym combined with multiple quasi-identifiers and a sensitive attribute is blocked at individual granularity.
4. A grouped sensitive result without a trusted minimum distinct-subject threshold is eligible for a constrained rewrite when the supported SQL profile permits it.
5. A threshold is trusted only when it counts the expected subject key, is at least the configured minimum, and is not weakened by an `OR` path.
6. Missing metadata, unsupported SQL, ambiguous source binding, rewrite failure, and verification failure are blocked.

Do not weaken these rules merely to make a query execute.

### 5. Rewrite only within the supported transformation profile

A supported rewrite may add or strengthen:

```sql
HAVING COUNT(DISTINCT <subject_key>) >= <minimum_group_size>
```

Only perform this transformation when the query is already a supported grouped analytical query and the subject binding is unambiguous.

Do not claim general anonymization, arbitrary SQL repair, location coarsening, differential privacy, identifier removal, or individual-to-grouped query synthesis unless a separately implemented and verified transformation exists.

### 6. Re-evaluate the rewritten SQL

Never trust generated SQL because the system produced it.

After any rewrite:

1. parse the rewritten SQL again;
2. resolve its governed fields again;
3. apply the same deterministic policy again;
4. require a final `ALLOW` before execution.

### 7. Verify execution independently

For an executable final query:

- use the hardened read-only database path;
- reject raw forbidden output fields;
- verify any required subject threshold;
- inspect the complete grouped result when group-size safety is part of the decision;
- confirm observed group sizes meet the configured minimum;
- fail closed if verification is incomplete or execution errors.

### 8. Persist sanitized institutional memory

Create a decision receipt containing governed evidence, SQL hashes, reason codes, verification checks, and execution summary metadata.

Do not persist raw result rows or secrets.

When DataHub write-back is enabled:

1. write a `Decision` document with `save_document`;
2. relate it to the governed assets used by the query;
3. close the MCP process that performed the write;
4. open a fresh MCP process;
5. verify the unique decision marker inside the persisted document content using `grep_documents`.

Do not treat an in-memory write response as persistence proof.

## Output contract

Return or record:

- initial decision: `BLOCK`, `REWRITE`, or `ALLOW`;
- deterministic reason codes;
- governed datasets and fields used as evidence;
- DataHub URNs for resolved assets;
- safe SQL when a supported rewrite succeeds;
- final decision after reevaluation;
- verification checks and bounded execution summary when execution occurs;
- immutable receipt identifier and content hash;
- DataHub Decision URN and independent read-back state when write-back is enabled.

## Safety and honesty constraints

- Never execute a `BLOCK` or unresolved `REWRITE` query.
- Never send raw sensitive warehouse rows to an LLM.
- Never convert unknown metadata into a permissive classification.
- Never describe deterministic Replay output as a live DataHub or warehouse execution.
- Never present the benchmark as universal privacy-detection accuracy.
- Never claim unsupported transformations.
- Preserve the distinction between evidence gathering and deterministic enforcement.

## Source of truth

The executable reference implementation, tests, benchmark, live DataHub evidence, and this skill are maintained at:

`https://github.com/Z3X-1337/toxicjoin`
