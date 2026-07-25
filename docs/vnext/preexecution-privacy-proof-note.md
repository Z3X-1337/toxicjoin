# Pre-Execution Privacy Proof — P0 Boundary Note

This slice adds a machine-verifiable `PreExecutionPrivacyProof`. It does not authorize or execute SQL. The existing single-use `ExecutionAuthorization` remains unchanged in this PR; binding `privacy_proof_sha256` into that capability is the following Day-11 slice.

## What the proof commits

The proof contains commitments, not raw warehouse rows, raw governance payloads, prompts, credentials, or HMAC keys. It binds:

- authenticated `RequestIdentity`;
- exact task purpose and the Twin purpose commitment;
- exact subject key;
- exact final SQL and freshly analyzed `QueryPlan`;
- full normalized `ContextResolution` including lineage;
- exact `GovernanceContextBinding`;
- DataHub evidence root plus the independent DataHub derivation-validation commitment;
- exact Disclosure Digital Twin state and warehouse snapshot;
- exact PolicyEngine configuration and freshly recomputed ALLOW decision;
- exact Future Action Grammar;
- PPMC config, forbidden-policy commitment, trusted-governance binding, search transcript, result, bound, and state budget;
- optional selected CPCC repair result/candidate/validation/generated-SQL commitments.

A proof can be built only when PPMC returns `NO_COUNTEREXAMPLE_WITHIN_BOUND`. `PROSPECTIVE_UNSAFE` and `FAIL_CLOSED` are not proof-eligible states.

## Construction checks

The builder receives typed trusted artifacts rather than caller-selected security hashes. Before issuance it:

1. normalizes and revalidates all strict artifacts;
2. requires fresh DataHub governance and evidence at issuance time;
3. requires the DataHub evidence bundle and independent derivation validation to bind the same evidence root and snapshot as governance;
4. reparses the exact final SQL;
5. recomputes the local PolicyEngine decision from the supplied governed context and requires `ALLOW` with no rewrite requirement;
6. verifies principal/agent privacy scope, subject, purpose, governance, and evidence commitments against the Twin;
7. verifies the Future Action Grammar is bound to that same Twin;
8. requires a trusted PPMC governance binding and requires the PPMC result to match the exact Twin and grammar;
9. if CPCC repair commitments are present, requires `REPAIR_FOUND`, the exact selected candidate, an `ELIGIBLE_SAFE` selected validation, and matching SQL/plan/governance/evidence/policy/state/PPMC commitments.

The CPCC artifacts are still trusted in-process outputs in P0. This proof slice does not attempt to make arbitrary serialized CPCC search transcripts independently re-executable. Day-11 integration must pass the actual internal CPCC outputs directly; agent/user JSON must never be accepted as authoritative repair evidence.

## Content commitment and authenticity

`privacy_proof_sha256` is SHA-256 over deterministic sorted compact JSON excluding the content-hash and HMAC fields themselves.

`integrity_hmac_sha256` authenticates the full proof including `privacy_proof_sha256` using HMAC-SHA256 and the explicit domain separator:

`toxicjoin:preexecution-privacy-proof:v1\0`

The integrity key must contain at least 32 bytes. It is never serialized into the proof.

This is symmetric integrity for an authorized verifier possessing the key. It is not public verifiability, PKI, remote attestation, or a digital signature.

## Lifetime

A proof lifetime is capped at 60 seconds and is shortened to the earliest DataHub governance/evidence expiry. A proof cannot be issued after the governed/evidence state is stale.

The independent verifier checks:

- strict schema;
- `privacy_proof_sha256`;
- domain-separated HMAC;
- not-yet-valid time;
- expiry.

It returns stable failure codes instead of treating malformed or tampered proof JSON as trusted objects.

## CLI verifier

The package exposes:

`toxicjoin-proof-verify <proof.json>`

The authorized verifier supplies `TOXICJOIN_PRIVACY_PROOF_HMAC_KEY` with at least 32 UTF-8 bytes. The CLI emits one compact machine-readable JSON result and uses exit code `0` for valid, `1` for invalid proof, and `2` for verifier/file/configuration errors. The key is never printed.

## Security boundary

A valid P0 pre-execution proof means only that an authorized verifier can authenticate the committed artifact and that the trusted builder accepted the exact artifacts under the declared bounded model at issuance time.

It does **not** mean:

- universal or formal privacy for arbitrary future SQL;
- Differential Privacy;
- objective truth of external metadata;
- globally optimal repair;
- public verifiability;
- permission to execute.

Execution remains forbidden until Day-11 binds the exact `privacy_proof_sha256` into the existing short-lived, single-use execution authorization and the existing verifier independently rechecks current runtime state.
