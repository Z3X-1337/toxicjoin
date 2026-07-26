# Day 13 Slice 2 — DataHub Governance Trust Binding

## Scope

This slice converts the replay-validated DataHub evidence already bound by `TrustedAgentProposalEvaluation` into an authorization-facing **governance trust** artifact.

It does not add Disclosure Twin state, PPMC/CPCC execution for this proposal, proof construction, execution authorization, disclosure-state mutation, or DataHub decision write-back.

## Trust-layer separation

The following statements are intentionally distinct:

1. **DataHub derivation replay validated** — ToxicJoin deterministically reconstructed the expected DataHub evidence bundle from the exact trusted snapshot/source binding and verified the canonical claims/root.
2. **EvidenceTrust resolved** — the required governance facts were evaluated under a versioned security-owned Evidence Policy and resolved to an authorization-facing trust state.
3. **GovernanceTrustBinding positive** — every governance fact required by the exact grounded context resolved `TRUSTED` and matched the security-owned expected value.
4. **Prospective privacy safe** — not established by this slice.
5. **Execution authorized** — not established by this slice.

A successful derivation replay therefore does **not** imply `TRUSTED` by itself.

## Evidence Policy

The general `default_evidence_policy()` remains conservative and does **not** trust `DATAHUB_MCP + EXPLICIT_MAPPING` evidence.

Slice 2 uses a narrow package-owned policy, `datahub-governance-v1`, only inside `DataHubGovernanceTrustAuthority`. Its eligible pairs are:

- `DATAHUB_MCP + RUNTIME_OBSERVED`
- `DATAHUB_MCP + EXPLICIT_MAPPING`

The dedicated policy is not exported as a top-level convenience API. The emitted binding embeds the exact policy and commits it by hash, and model validation rejects substitution with another self-consistent policy.

Agent/fuzzy evidence remains unable to establish authority.

## Positive binding requirements

A positive `GovernanceTrustBinding` requires exact, trusted values for the governance facts used by the grounded query context, including:

- DataHub snapshot root commitment;
- catalog version;
- referenced dataset logical-name mappings;
- field tags and glossary-term observations;
- field sensitivity classifications;
- positive lineage transport/governance completeness facts;
- grounded lineage source refs, categories, and DataHub URNs;
- upstream lineage dataset logical-name mappings and upstream field sensitivity classifications.

Missing claims, wrong values, `UNKNOWN`, `STALE`, `INCOMPLETE`, `CONTESTED`, `AGENT_ASSERTED`, evidence from the future, validation from the future, or a non-DataHub governance source fail closed.

Dangling evidence support references also fail closed.

## Snapshot and freshness binding

The trust authority requires the governance binding and evidence bundle to agree on the relevant DataHub catalog/freshness window, in addition to the snapshot commitments already enforced by `TrustedAgentProposalEvaluation`.

The authority samples a security-owned clock:

- before trust resolution;
- immediately before constructing the positive binding;
- after complete binding model/hash validation, immediately before return.

Evidence that expires at either issuance boundary fails with `GOVERNANCE_TRUST_STALE_AT_ISSUE`.

The authority retains the last accepted clock sample and rejects rollback across calls.

## What a positive binding means

`governance_trusted=true` means:

> Under the exact embedded `datahub-governance-v1` Evidence Policy, at the recorded issuance time, every governance fact declared by this binding resolved `TRUSTED` and matched the exact expected value derived from the security-owned grounded evaluation.

It does **not** mean:

- DataHub metadata is objectively true in the real world;
- the source system cannot be malicious or incorrectly administered;
- prospective compositional privacy safety has been proved;
- PPMC found no counterexample;
- CPCC selected a safe remediation;
- execution is authorized.

A trusted-but-wrong DataHub authority remains a residual trust risk. This slice makes that trust decision explicit and auditable; it does not eliminate the organizational/source-of-truth assumption.

## Integrity is not authority

`binding_sha256` is a canonical content-integrity commitment only. It is not a signature, MAC, bearer credential, execution capability, remote attestation, or independently authenticated authorization token.

A later F6/PPMC consumer must not accept an arbitrary serialized `GovernanceTrustBinding` merely because its local model/hash validation succeeds. The consumer must receive the binding through a security-owned path and rebind it to the exact `TrustedAgentProposalEvaluation`, including at least the evaluation, governance, snapshot, evidence-root, policy, requirements/resolutions, and freshness commitments required by that stage.

## Error boundary

`DataHubGovernanceTrustAuthority.bind()` exposes stable fail-closed error codes. Invalid/tampered input is revalidated before trust resolution, and underlying exception chains are detached before crossing the public boundary.

## Claim boundary for Day 13

This slice may set:

- `governance_trusted=true`
- `evidence_trust_resolved=true`

It fixes:

- `prospective_privacy_checked=false`
- `execution_authorized=false`

The next integration slice must use this positive binding to clear F6 only inside the security-owned prospective-privacy path; it must not reinterpret this artifact as execution authority.
