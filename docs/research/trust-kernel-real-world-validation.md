# ToxicJoin Trust Kernel — Real-World Validation Program

Status: experimental research branch; nothing here is promoted to `main` without passing the gates below.

## Research objective

Evolve ToxicJoin from a pre-execution SQL privacy firewall into a **proof-carrying trust kernel for data agents**.

The target system must mediate a real agent, real DataHub context, and a real warehouse. An LLM may propose plans or SQL, but it never receives execution authority directly. Execution is granted only after a deterministic, machine-checkable authorization path succeeds.

## Core hypothesis

A data agent can be made materially safer without making the LLM itself the policy authority if execution requires a verifiable proof derived from:

1. the exact proposed SQL/plan;
2. DataHub-governed metadata and lineage;
3. deterministic policy constraints;
4. rewrite and re-evaluation evidence when remediation is possible;
5. independent execution/result verification;
6. a content-addressed receipt that binds the decision to the context used.

This is not a claim of universal SQL safety or universal re-identification detection. The project will publish a supported contract and measure failures outside that contract separately.

## Target architecture

```text
Human / external trigger
        |
        v
Real LLM / data agent
        |
        | proposes intent + SQL / plan
        v
+-----------------------------+
|      ToxicJoin Trust Kernel |
|                             |
|  1. parse + physical lineage|
|  2. DataHub context read    |
|  3. context integrity gate  |
|  4. compositional policy    |
|  5. constrained remediation |
|  6. re-parse / re-ground    |
|  7. execution proof         |
+-----------------------------+
        |
        | only effective ALLOW
        v
Real warehouse executor
        |
        v
Independent verifier
        |
        v
Proof/receipt + DataHub write-back
```

## Non-negotiable validation gates

A feature or claim may not enter stable `main` based only on a test corpus created for it.

### Gate A — Real integration

The experiment must exercise actual external interfaces where the claim depends on them:

- DataHub OSS through the supported SDK/MCP surface;
- a real warehouse connection rather than a mocked executor for execution claims;
- a real model/provider invocation for agent-generation claims;
- actual DataHub write-back followed by an independent fresh-session/process read-back for persistence claims.

### Gate B — External / blind data

At least one evaluation dataset must originate outside the ToxicJoin repository and must not be generated to satisfy ToxicJoin policy assumptions.

Requirements:

- upstream source and license recorded;
- immutable source URL/version where possible;
- SHA-256 recorded after acquisition;
- transformation steps reproducible;
- evaluation expectations created independently from the policy implementation;
- no hand-editing inputs after observing ToxicJoin outputs.

### Gate C — Fault injection

The system must be tested under failures that a normal happy-path demo does not exercise, including as applicable:

- missing DataHub entity;
- stale or contradictory classification;
- incomplete lineage;
- MCP tool/schema drift;
- warehouse timeout / disconnect;
- receipt-store failure;
- invalid rewrite;
- verifier disagreement;
- LLM malformed or adversarial SQL;
- context changes between proposal and execution (TOCTOU).

The default outcome on unresolved authorization uncertainty must remain fail-closed.

### Gate D — Adversarial independence

Red-team inputs must include cases not authored by the same logic that defines the expected policy outcome.

Preferred sources, in order:

1. external benchmark / public workload;
2. independent human-authored challenge set;
3. separate-model adversarial generation with the target model hidden from the generator;
4. grammar/metamorphic fuzzing with invariants defined before execution.

A security claim must report failures, not only passing cases.

### Gate E — Reproducible evidence

Every promoted experiment should emit machine-readable evidence containing at minimum:

- source/data fingerprints;
- policy version;
- DataHub/context snapshot identity where available;
- model/provider/model-id for LLM experiments;
- SQL/plan hashes;
- decision and reason codes;
- whether execution occurred;
- verification outcome;
- report hash;
- explicit limitations.

## Phase 1 — External warehouse validation

Goal: prove that ToxicJoin can protect a warehouse whose dataset was not designed for ToxicJoin.

Plan:

1. Select a permissively licensed public relational dataset with multiple joinable tables and non-trivial quasi-identifying/sensitive semantics.
2. Pin and fingerprint the upstream files.
3. Load the unmodified source into a separate experimental warehouse profile.
4. Ingest its actual schema into DataHub OSS.
5. Add governance metadata as a separate, auditable stewardship step; do not alter the raw source to fit the policy.
6. Have a real agent generate analysis SQL from natural-language tasks.
7. Run all proposals through the Trust Kernel.
8. Independently label outcomes and compare them with ToxicJoin decisions.

Success is not “all tests pass”. Success is a defensible report of what the current kernel catches, misses, rewrites, or refuses.

## Phase 2 — Proof-carrying execution

Introduce an `ExecutionAuthorization` object that can be verified independently of the generating agent.

Proposed binding fields:

- canonical SQL hash;
- physical dataset/column lineage hash;
- DataHub governance/context fingerprint;
- policy version/hash;
- decision and reason codes;
- rewrite parent hash where applicable;
- expiry / context version constraints;
- verifier requirements;
- authorization content hash.

The executor must reject execution when the authorization does not match the exact SQL and context that were evaluated.

This is intended to reduce time-of-check/time-of-use drift between authorization and warehouse execution.

## Phase 3 — Agent-provider independence

Use a provider-neutral interface so multiple agents/models can propose work while sharing the same execution authority boundary.

The research question is not which model is best. It is whether **different model behaviors converge on the same deterministic safety boundary**.

Metrics include:

- proposal success rate;
- unsafe proposal rate;
- rewrite rate;
- block rate;
- verifier disagreement;
- context lookup failures;
- latency and token cost outside the kernel;
- kernel latency separately.

## Phase 4 — Continuous adversarial self-play

Add a separate attacker role that does not possess execution authority.

Its purpose is to discover bypasses by mutating intent and SQL while preserving an unsafe semantic objective. Any discovered bypass becomes a regression case only **after** it is found; it must not be used as proof that the discovery system itself is effective.

The attacker and defender evidence must remain separable so the benchmark does not become circular.

## Phase 5 — Trust Control Room

Build the UI only after the real execution path is stable.

The UI should expose evidence, not decorative telemetry:

- original user intent;
- agent/model and generated proposal;
- DataHub entities, classifications, lineage and context freshness;
- compositional risk explanation;
- ALLOW / REWRITE / BLOCK decision;
- exact constrained rewrite diff;
- independent verification;
- execution authorization fingerprint;
- warehouse execution state;
- receipt and DataHub write-back/read-back state.

## Promotion rule

Experimental work is promoted to `main` only when:

1. the experiment has a clearly defined threat/validity model;
2. CI and existing ToxicJoin gates remain green;
3. external-data evidence is retained or reproducibly fetchable;
4. failures and limitations are documented;
5. the feature improves at least one hackathon judging dimension without weakening another;
6. no claim depends on representing replay/mock/fixture behavior as live external execution.

## Immediate next experiment

Build the external-dataset ingestion and blind-evaluation harness first. Do **not** start with the Control Room or multi-agent UI. The external validation result will determine what the next architecture actually needs.
