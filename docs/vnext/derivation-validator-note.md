# DataHub Derivation Validator — P0 Boundary Note

This slice introduces deterministic replay validation for DataHub evidence without changing authorization.

The validator consumes trust inputs whose roles remain distinct:

- a `DataHubEvidenceBundle` candidate, which is untrusted until replay succeeds;
- the locally trusted `DataHubSnapshot` used as the replay source;
- local `DataHubMcpSettings` used to recompute the committed source identity;
- a trusted freshness policy (`max_age_seconds`, default 300 seconds).

The candidate is not allowed to select or extend any of those trust anchors. Validation succeeds only when the candidate is current under the trusted freshness policy, binds the exact snapshot and source configuration, contains the same semantic claim set as deterministic replay, and every claim has the exact canonical content hash and claim id produced by replay.

A successful `DataHubDerivationValidation` commits the evidence observation/expiry window, freshness policy, evidence root, snapshot, source identity, and exact observed/mapped claim-id partitions. It is a machine-checkable local commitment, not remote attestation, does not make DataHub objectively truthful, does not change `EvidencePolicy`, and does not authorize execution.

The validation artifact is self-hashed but is not an authenticated capability. The next authorization-facing slice, if justified by evidence, must explicitly define how a validated derivation commitment is consumed without allowing an Agent or serialized claim to choose the trusted snapshot, source configuration, freshness policy, or validator result.
