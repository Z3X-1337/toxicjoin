# Threat-Model Delta — P3-C DataHub Lineage Trust Closure

Date: 2026-07-25
Tracking: P3-C / DataHub lineage trust closure

## Scope

P3-C closes the trust gap where a materialized or derived DataHub field could be classified
only from its current field name and direct tags/glossary even though DataHub records upstream
column lineage to more sensitive governed sources.

This is a security correction, not a product feature.

## Threat

A field can look harmless at the final dataset boundary while still carrying sensitive lineage.
For example:

```sql
SELECT harmless_value FROM derived_customer_features
```

If `harmless_value` is materially derived from `customer_id`, `precise_area`, or a sensitive
attribute, evaluating only the direct metadata on `harmless_value` can understate disclosure
risk.

The same issue exists inside SQL expressions such as:

```sql
SELECT HASH(customer_id) AS harmless_value
```

SQL-local lineage is already preserved by ToxicJoin's semantic exposure plan. P3-C extends the
same principle across the physical DataHub boundary so materialization does not erase source
risk.

## Security objective

For every configured DataHub field, ToxicJoin must evaluate both:

```text
direct governed category
+
all recorded upstream column categories
```

No arbitrary single-category ranking is used. `DIRECT_IDENTIFIER`, `STABLE_PSEUDONYM`,
`QUASI_IDENTIFIER`, and `SENSITIVE_ATTRIBUTE` represent different risk dimensions rather than a
safe total order. Collapsing multiple upstream categories into one could hide a compositional
rule.

## Column-lineage acquisition

During live snapshot acquisition, ToxicJoin requests upstream column-level lineage for every
configured field.

The official DataHub MCP server groups column-level results by upstream dataset and exposes the
source columns in `lineageColumns`. ToxicJoin requests `max_hops=3`, which the supported
`mcp-server-datahub` lineage contract uses for the `3+` degree range, so recorded upstream
columns beyond two hops remain visible.

The loader retains the existing flagship lineage sample for evidence, but lineage is no longer
only a sample: every configured field receives governed upstream source bindings in the catalog.

## Governed lineage model

Each materialized field keeps its direct category and a set of upstream `LineageSource` records:

```text
ref.dataset
ref.field_path
category
datahub_urn
```

This preserves source identity and category multiplicity. The policy engine evaluates unique
source/category pairs rather than replacing the direct field with a synthetic "maximum" risk
category.

Example:

```text
retention_scores.churn_score
  direct: SENSITIVE_ATTRIBUTE
  upstream:
    orders.purchase_amount        SENSITIVE_ATTRIBUTE
    support_cases.case_category   SENSITIVE_ATTRIBUTE
    location_activity.precise_area QUASI_IDENTIFIER
    location_activity.activity_count PUBLIC_OR_LOW_RISK
```

The direct field remains a sensitive model output, while the upstream quasi-identifier remains
visible to compositional policy logic.

## Fail-closed lineage conditions

A field receives an `UNCLASSIFIED` lineage source and therefore fails closed when any of these
conditions occur:

- an upstream dataset is outside the configured DataHub asset map;
- an upstream column is absent from the normalized governed schema;
- a column-level relationship lacks a resolvable dataset or `lineageColumns` payload;
- DataHub reports `hasMore=true` for the bounded result page;
- DataHub reports token-budget truncation;
- a relationship reports truncated children.

This isolates the failure to the affected governed field instead of making unrelated datasets
unavailable, while any query that touches that field receives `UNCLASSIFIED_COLUMN`.

The configured flagship lineage is stricter: empty or incomplete flagship lineage aborts the
live snapshot load.

## Policy semantics

The policy engine now derives effective categories from source-unique entries:

```text
current field category
+
recorded upstream lineage source categories
```

The existing semantic exposure plan still controls whether a projected value is raw,
transformed raw, a group key, aggregate operand/value, filter-only, join-only, or nested scope.
Lineage expands the governed risk attached to those exposed values; it does not change SQL
exposure semantics.

This means a materialized field directly tagged `PUBLIC_OR_LOW_RISK` but derived from a stable
pseudonym can no longer behave as pure public data. When combined with a sensitive projected
attribute, the stable pseudonym remains visible and the existing compositional risk rule can
BLOCK the request.

## Canonical live metadata correction

P3-C also makes canonical category tags explicit for fixture fields whose category was previously
known only inside the fixture model. This includes `PUBLIC_OR_LOW_RISK` fields and
`customers.coarse_region`.

The correction matters because live DataHub classification intentionally trusts controlled
DataHub tags/glossary, not the fixture-only `category` property. The live seed and fixture model
therefore now encode the same category semantics.

## Receipt provenance

Receipt schema `1.3` records `lineage_sources` for every referenced governed column. The lineage
records participate in `content_sha256`.

A receipt can therefore answer both:

```text
What direct category did ToxicJoin use?
Which upstream governed columns contributed additional risk?
```

Changing lineage provenance after persistence invalidates the receipt content hash.

## Live evidence

The DataHub spike report schema is raised to `1.3` and records:

```text
lineage_bound_field_count
lineage_source_count
flagship_lineage_source_keys
flagship_lineage_categories
unclassified_lineage_source_count
```

The live spike rejects a snapshot if any recorded upstream lineage source remains unclassified or
incomplete. The existing read-only acquisition -> isolated save_document writer -> fresh
read-only readback sequence remains unchanged.

## Negative security evidence

Permanent regression coverage includes:

- SQL-local `HASH(customer_id) AS harmless_value` preserves `customer_id` lineage;
- a materialized public-looking field inherits stable-pseudonym upstream risk;
- that inherited pseudonym can combine with a sensitive value and trigger the existing
  compositional BLOCK;
- unknown upstream dataset/column -> affected field fails closed;
- truncated/paginated lineage -> affected field fails closed rather than trusting a partial graph;
- changing only governed upstream lineage changes the DataHub snapshot fingerprint.

## Concurrency and P3-B interaction

P3-C lineage is embedded in the `FixtureCatalog` stored inside `DataHubSnapshot`. Therefore the
lineage-bearing catalog is part of the deterministic snapshot SHA-256 introduced by P3-B.

A lineage change produces a different governance binding, so P3-B's existing drift checks cover
lineage changes between policy verification, authorization, and execution.

## Residual risks

### Missing upstream lineage in DataHub

ToxicJoin can only enforce lineage that the upstream governance authority records. If a derived
field has no DataHub lineage relationship at all, ToxicJoin cannot distinguish an intentionally
base field from an unregistered transformation solely from MCP output.

Mitigation: derived-data onboarding must treat DataHub lineage registration as a governance
control. This residual risk is explicitly not described as cryptographic proof of transformation
completeness.

### Compromised upstream authority

A compromised DataHub server or compromised MCP read process can return false metadata. P3-A
least privilege and process separation reduce blast radius but do not make an untrusted upstream
authoritative source truthful.

### Result-page bounds

The supported MCP call is bounded to 100 results. ToxicJoin does not silently accept overflow:
`hasMore`, token-budget truncation, or truncated children causes the affected field to fail
closed.

### Upstream contract drift

P3-C relies on the official column-level lineage response contract (`entity`, `lineageColumns`,
and completeness metadata). Runtime MCP contract discovery remains mandatory, and live DataHub
evidence is a merge gate for this phase.

## Merge gates

P3-C must not merge until the exact PR head passes:

```text
Python 3.11
Python 3.12
Web
Container
Governance Dependency Evidence
Adversarial Mutation Evidence
Compositional Ablation Evidence
Disclosure Sequence Evidence
Live DataHub Evidence
Frozen external 24-task replay
```

The external replay must identify the exact P3-C production candidate SHA. Devpost remains
Draft / NOT SUBMITTED throughout this phase.
