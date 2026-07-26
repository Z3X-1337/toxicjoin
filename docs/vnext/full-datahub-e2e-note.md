# Full real-DataHub E2E — Day-13 integration contract

Day 13 connects the already-proven vNext components without collapsing their trust boundaries.
The legacy `main` runtime remains the rollback-safe baseline; this work is stacked on the Day-12
Agent/DataHub discovery PR until that PR is independently approved and merged.

## Required end-to-end story

```text
sanitized AgentDataContext
  -> trusted in-process planner adapter / untrusted model output
  -> AgentProposal (security_authoritative=false)
  -> exact DataHub snapshot pin
  -> independent SQL reparse + governance reground
  -> replay-validated DataHub evidence
  -> local PolicyEngine baseline
  -> authorization-facing evidence resolution
  -> Disclosure Digital Twin
  -> PPMC
  -> CPCC only when required
  -> independent candidate revalidation
  -> PreExecutionPrivacyProof
  -> exact proof-bound authorization
  -> verifier
  -> quarantine / execution / release
  -> disclosure ledger
  -> isolated DataHub Decision writeback + independent readback
```

No step may accept a policy decision, evidence trust state, Twin state, PPMC result, CPCC safety
claim, proof validity bit, authorization token, or execution result authored by the Agent.

## Slice 1: trusted proposal intake

`DataHubAgentProposalAuthority` is the first Day-13 bridge. It deliberately stops before evidence
trust resolution and before the Disclosure Twin. Construction binds one exact DataHub snapshot,
provenance-valid read path, evidence bundle/derivation replay, and policy configuration. Each
planning-only `AgentProposal` evaluation then:

1. samples the trusted clock and rejects future/stale evidence immediately;
2. takes one validated immutable `PolicyConfig` snapshot and requires it to equal the configuration
   bound at authority construction;
3. revalidates the proposal, exact goal, sanitized context, and subject key;
4. requires the proposal's goal/context commitments to match the trusted inputs;
5. requires the context's source snapshot commitment to equal the exact trusted `DataHubSnapshot`;
6. accepts the authorization-facing task purpose independently from trusted request authority and
   requires the Agent-authored planning purpose to match it exactly;
7. reparses SQL independently and requires the QueryPlan commitment to match the proposal;
8. regrounds all referenced fields through `DataHubSnapshotContextResolver`;
9. runs a local `PolicyEngine` built from the immutable policy snapshot over a typed, committed
   `PolicyInput`;
10. samples the trusted clock again immediately before issuance and rechecks governance/evidence
    freshness;
11. emits a canonical `TrustedAgentProposalEvaluation` for the next security-owned stage.

## Credential/source retention boundary

The live read credential exists only during authority construction. It is used to:

- verify authority-registry provenance;
- derive the redacted `datahub_source_identity` commitment;
- build the exact `DataHubEvidenceBundle`;
- independently replay-validate that bundle against the exact snapshot/source/freshness policy.

After construction the authority retains only the already-redacted source identity and immutable
evidence artifacts. It does **not** retain `DataHubMcpSettings`, the bearer, raw GMS endpoint,
launcher command arguments, or other credential-bearing configuration. This is stronger than merely
replacing the bearer with a placeholder because endpoint userinfo/query credentials and launcher
flags can themselves contain secrets.

## Evidence validation binding

`TrustedAgentProposalEvaluation` does not accept an evidence root match alone as proof that the
validation belongs to the embedded bundle. Its validator requires exact alignment of:

- evidence root;
- snapshot commitment;
- redacted source identity;
- observation and expiry timestamps;
- freshness-policy lifetime;
- the complete `RUNTIME_OBSERVED` claim-ID partition;
- the complete `EXPLICIT_MAPPING` claim-ID partition.

This prevents a separately self-consistent `DataHubDerivationValidation` from being rebound to a
different source, freshness window, or claim partition.

## What Slice 1 does not prove

Successful `DataHubDerivationValidation` proves that the evidence candidate exactly replays from the
locally trusted snapshot/source/freshness policy. It does **not** change `EvidencePolicy`, does not
turn every DataHub claim into authorization-facing `TRUSTED` evidence, and does not authorize
execution.

Accordingly `TrustedAgentProposalEvaluation` fixes these states to false:

- `evidence_trust_resolved=false`;
- `prospective_privacy_checked=false`;
- `execution_authorized=false`.

`security_authoritative=true` means only that the bindings and local PolicyEngine result were
produced by security-owned code. The later evidence-resolution stage must deterministically derive
an actual governance trust binding before PPMC/proof construction can proceed.

## Fail-closed bindings

The intake fails closed for:

- unregistered or mutated read credential provenance;
- malformed/non-canonical request-purpose text;
- Agent-authored purpose escalation;
- goal/proposal/context hash mismatch;
- context/trusted-snapshot mismatch;
- SQL reparse failure;
- QueryPlan commitment mismatch;
- incomplete/stale governance resolution;
- future/stale evidence at evaluation start;
- expiry crossed while the evaluation is running;
- evidence-bundle/derivation-validation rebinding;
- PolicyConfig drift from the configuration bound at authority construction;
- PolicyEngine evaluation failure;
- trusted-clock rollback.

Errors crossing this boundary use finite stable codes and suppress external exception chains where
untrusted or secret-bearing data could otherwise escape.

## Remaining Day-13 slices

After Slice 1 passes exact-head review and tests:

- resolve authorization-facing governance evidence from validated claims under the security-owned
  `EvidencePolicy`; do not synthesize `trusted=true` directly;
- build an atomic disclosure-ledger snapshot, candidate semantic release, Disclosure Twin, and PPMC;
- route `PROSPECTIVE_UNSAFE` through a security-owned finite CPCC remediation space;
- recompile, reparse, reground, reevaluate and re-run PPMC for the selected cut;
- build the exact `PreExecutionPrivacyProof`;
- carry that proof through existing proof-bound authorization and verification;
- preserve two-phase disclosure-ledger semantics;
- write the final Decision through the isolated DataHub mutation role and verify it through a fresh
  read-only process.

The implementation must reuse the already-proven components rather than introduce parallel policy,
proof, ledger, evidence-trust, or execution semantics.
