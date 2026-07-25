# DataHub Derivation Validator — P0 Boundary Note

This slice introduces deterministic replay validation for DataHub evidence without changing authorization.

The validator consumes three caller-supplied objects whose trust roles remain distinct:

- a `DataHubEvidenceBundle` candidate;
- the locally trusted `DataHubSnapshot` used as the replay source;
- local `DataHubMcpSettings` used only to recompute the committed source identity.

Validation succeeds only when the candidate is fresh, binds the exact snapshot and source configuration, contains the same semantic claim set as deterministic replay, and every claim has the exact canonical content hash and claim id produced by replay.

A successful `DataHubDerivationValidation` is a machine-checkable local commitment. It is not remote attestation, does not make DataHub objectively truthful, does not change `EvidencePolicy`, and does not authorize execution.

The next authorization-facing slice, if justified by evidence, must explicitly define how a validated derivation commitment is consumed without allowing an Agent or serialized claim to choose the trusted snapshot, source configuration, or validator result.
