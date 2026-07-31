# Phase 7 Evidence Schema

The candidate and release manifests use schema `2.0`.

Each gate records the exact workflow run, required successful jobs, required artifact metadata,
verified claims derived from artifact contents, and status `verified`. The top-level identity records
mode, source SHA, checked-out SHA, head branch, current `main`, and base `main`. The manifest includes
a canonical SHA-256 over all fields except `manifest_sha256` itself.

An empty `missing`, `stale`, `skipped`, and `inapplicable` set is required for acceptance.
