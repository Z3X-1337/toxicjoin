# Phase 5 — Exact-final-SHA Live DataHub evidence

This document defines the Product Readiness Phase 5 boundary.

## Goal

Phase 5 proves the stable ToxicJoin integration against a real ephemeral DataHub OSS deployment and the official pinned DataHub MCP server on one exact candidate source revision.

## Exact source rule

For pull requests, the workflow checks out `github.event.pull_request.head.sha` explicitly rather than GitHub's synthetic merge ref. The evidence preflight and final binder both require `git rev-parse HEAD` to equal that candidate SHA and record the exact Git tree.

A head change invalidates prior evidence and requires a fresh run.

## Locked toolchain

- runner: Ubuntu 24.04 x64;
- Python: 3.11.15;
- uv: 0.8.4;
- DataHub SDK: `acryl-datahub==1.6.0.15`;
- official MCP server: `mcp-server-datahub==0.6.0` launched through `uvx`;
- project dependencies: committed `uv.lock` consumed with `uv sync --frozen --extra datahub`.

The SDK, read-only MCP, and isolated writer use three separate environment-variable channels with distinct credential values. Values are never serialized into evidence.

## Required live proof

The gate fails closed unless all of the following are verified:

1. real DataHub OSS GMS and frontend services become healthy;
2. the SDK seeds five synthetic datasets, 19 governed fields, ten tags, seven glossary terms, and four lineage writes;
3. a read-only MCP process loads the governed entities, schema fields, classifications, and column lineage with no mutation-shaped tools;
4. Agent discovery independently retains live field tags, glossary terms, schema, and lineage while remaining non-authoritative and mutation-free;
5. an isolated writer is constrained by ToxicJoin to the effective tool surface `["save_document"]`;
6. the writer process exits before a fresh read-only MCP process verifies the persisted Decision marker;
7. a live semantic policy decision built only from a read-only DataHub snapshot blocks the compositional re-identification case;
8. every sanitized report passes its reproducible content hash;
9. no SDK, read, or write credential value appears in any retained evidence file;
10. one content-addressed index and `SHA256SUMS` bind reports, raw diagnostics, source-contract files, tool versions, candidate SHA, and tree.

## Evidence outputs

The successful Artifact is named `phase5-exact-sha-live-datahub-evidence` and contains:

- `preflight.json`;
- `document-bootstrap.json`;
- `datahub-seed.json`;
- `datahub-spike.json`;
- `agent-discovery.json`;
- `live-policy-decision.json`;
- `phase5-live-datahub-evidence.json`;
- `SHA256SUMS`;
- version records, service health, container/image inventory, and raw execution logs.

The reports are sanitized. Raw diagnostics may contain local ephemeral service identifiers, but the final binder scans every retained file for the exact credential values and fails on any reflection.

## Explicit non-scope

Phase 5 does not start browser E2E, alter PR #118 or PostgreSQL work, change public hosting, mutate Devpost, create a tag or release, configure repository rulesets, clean historical refs, or merge its own pull request.
