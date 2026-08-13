# ToxicJoin — Canonical Product Architecture

Status: **Normative product-architecture authority**  
Baseline reviewed: `1aead67c339c218f5858a9eb9de05868cdc3a0e5`

This document is the single normative authority for ToxicJoin product architecture and claim boundaries. It describes what is canonical, executable, staged, historical, or off-main. It does not upgrade a capability merely because code, tests, roadmap material, or retained evidence exists for it.

## 1. Document authority

The repository documentation hierarchy is:

1. `docs/architecture.md` — normative product architecture and surface map.
2. `docs/security-architecture.md` — detailed security implementation and migration constraints, subordinate to this document.
3. `docs/threat-model.md` — threats, controls, and residual risks.
4. `docs/deployment.md` — deployment procedures and topology-specific claims.
5. Judge, evidence, replay, vNext, and submission documents — revision-bound or audience-specific views that may not override this architecture.

When documents conflict, this product architecture controls. Evidence remains authoritative only for the exact revision, environment, commands, and outputs it records.

## 2. Core invariant

```text
An agent may propose.
DataHub supplies governed context.
ToxicJoin alone authorizes execution.
Uncertainty fails closed.
```

The AI or Governed Agent is proposal-only. It does not own policy authority, disclosure state, authorization keys, database connections, result release, or DataHub mutation authority.

## 3. Canonical HTTP runtime

The current executable product path is:

```text
authenticated caller
  -> FastAPI authentication and scope enforcement
  -> request identity binding
  -> SQL analysis
  -> fixture or governed context resolution
  -> deterministic PolicyEngine
       -> BLOCK
       -> ALLOW
       -> constrained REWRITE
            -> reparse
            -> reground
            -> reevaluate
  -> pipeline-owned ExecutionAuthorizer
  -> exact-state, short-lived, single-use execution capability
  -> hardened read-only DuckDB
  -> quarantined result
  -> independent post-execution verification
  -> disclosure state RELEASED or ABORTED when required
  -> sanitized authenticated receipt without raw rows
```

The current HTTP pipeline does not supply the strict vNext privacy-proof capsule and has not completed migration to the strict proof-bound authorizer.

## 4. Fixture mode

Fixture mode is a current executable judge path. It uses deterministic synthetic governance, a real read-only DuckDB execution path, SQLite disclosure state when enabled, verification, and receipts.

Fixture mode does not claim:

- a live external DataHub session;
- production multi-tenancy;
- horizontally shared disclosure state;
- distributed replay or rate-limit state.

## 5. Live DataHub integration

The stable DataHub path uses real DataHub OSS and the official MCP Server:

```text
SDK / read-only MCP
  -> governed entities, fields, tags, glossary terms, and lineage
isolated writer MCP
  -> ToxicJoin allowlist exposes only save_document
fresh read-only MCP
  -> independent persisted Decision read-back
```

Credential roles are distinct:

- SDK token;
- MCP read token;
- MCP write token;
- fresh read-back uses read authority in a separate process.

The retained tested launcher contract is pinned to `mcp-server-datahub==0.6.0`.

The repository retains exact-revision live evidence. It does **not** currently possess Live DataHub evidence executed on final `main` `1aead67c339c218f5858a9eb9de05868cdc3a0e5`. Retained evidence proves its recorded revision; unchanged-source applicability arguments are not equivalent to an exact-final-SHA live rerun.

## 6. Public Render surface

The public site and API are served together by one Render Docker Web Service. It executes the real
fixture pipeline with synthetic data and temporary single-node state. It is not a Live DataHub
environment, a durable audit store, or evidence of multi-replica support.

Render is the only supported public hosting target. Exact deployment identity comes from the Render
deployment record plus external verification; repository configuration alone does not prove which
commit is live.

## 7. Runtime failure boundary

The browser interface depends on the same-origin API for health, scenarios, benchmark evidence, and
decisions. If that API is unavailable, the interface fails explicitly and offers reconnection. No
static scenario result is substituted into a production session.

## 8. Historical evidence

Evidence documents prove only their recorded revision, environment, commands, and outputs. Historical evidence may support provenance but cannot establish current repository identity.

## 9. vNext staged architecture

The repository contains implemented and tested staged components including:

- Evidence Layer;
- Disclosure Digital Twin;
- Future Action Grammar;
- bounded PPMC;
- CPCC;
- Privacy Proof Capsule;
- authenticated proof and proposal handoffs;
- Governed Agent authority separation;
- strict proof-bound execution primitives.

These are real staged components. They are not a claim that the canonical HTTP runtime has completed the entire vNext chain.

## 10. PostgreSQL staged backend

Draft PR #118 contains an off-main PostgreSQL shared-authoritative disclosure backend and dedicated evidence workflow.

It is not:

- present on current `main`;
- a current HTTP runtime capability;
- a production-supported backend;
- evidence of distributed receipt, key, replay, or transaction topology.

The current public disclosure authority remains SQLite and explicitly single-node.

## 11. Future roadmap

Roadmap and ADR material may describe intended migrations. A roadmap does not change current behavior or claimability. A capability becomes canonical only after implementation, integration into the product path, exact-head evidence, and an explicit architecture update.

## 12. Claim-control rule

No README text, UI label, deployment guide, Devpost answer, video narration, or evidence document may upgrade a fixture, historical, replay, staged, off-main, or roadmap surface into a current canonical capability.
