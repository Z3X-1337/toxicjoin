# Phase 11 — Future Action Grammar Hardening

Status: **staged vNext PPMC hardening; not canonical HTTP/product runtime wiring**.

## Proven gap

Phase 11 started with a test-only TDD head against the public PPMC trust boundary.

The internal PPMC engine canonical-revalidated a supplied `FutureActionGrammar` by serializing it
through `grammar.model_dump()` and validating those bytes. The bounded BFS then continued to read
`grammar.actions` from the original caller-supplied object rather than from the canonical model that
had just been validated.

A malicious `FutureActionGrammar` subclass could therefore:

1. override `model_dump()` to serialize a legitimate security-owned grammar;
2. retain the legitimate `grammar_sha256` commitment;
3. expose a different runtime `actions` tuple to the BFS;
4. remove every declared action from the actual search universe.

The Phase 11 red test proved the security consequence directly. The polymorphic grammar passed the
existing canonical revalidation, the BFS considered zero actions, and PPMC returned
`NO_COUNTEREXAMPLE_WITHIN_BOUND`. The full Python 3.12 suite reported **1 failed, 812 passed** with
the explicit regression failure:

`PPMC accepted a polymorphic grammar and certified an empty search universe`

This is a prospective-safety false negative caused by a type-confusion / virtual-serialization split
between the validated grammar and the grammar actually searched.

## Fix

The public `toxicjoin.prospective.ppmc.check_prospective_privacy()` trust boundary now rejects a
polymorphic Future Action Grammar before invoking the internal search engine.

The exact-type gate validates the security-owned model universe without calling virtual
serialization on untrusted subclasses. It requires exact types for:

- `FutureActionGrammar`;
- `FutureActionGrammarContext`;
- every `FutureAction`;
- declared snapshot transitions;
- base/action `DisclosureSemanticRelease` values;
- `DisclosureComposition` values;
- semantic outputs and every governed column reachable from the grammar context or actions.

Only after this gate succeeds does the existing internal canonical revalidation and deterministic
bounded BFS run. Exact model instances built through unsafe construction paths are still checked by
the existing Pydantic canonical revalidation, so the change complements rather than replaces the
content-integrity validation.

## Why the gate is on the public PPMC boundary

The security-owned Agent PPMC authority imports `check_prospective_privacy` from
`toxicjoin.prospective.ppmc`. That public module is the trust boundary into the internal
`ppmc_search` engine. Keeping the exact-type gate there avoids duplicating the BFS implementation or
expanding the trusted computing base with a second search path.

`ppmc_search` remains an internal deterministic engine; callers requiring the supported security
contract must enter through the public PPMC API.

## Adversarial regressions

Phase 11 covers:

- root `FutureActionGrammar` subclass with legitimate virtual serialization but an empty runtime
  action universe;
- nested `FutureActionGrammarContext` subclass rejected before virtual serialization;
- nested `FutureAction` subclass rejected before virtual serialization;
- nested `DisclosureSemanticRelease` subclass rejected before virtual serialization.

The positive Python 3.11/3.12, balanced benchmark, PPMC hard-gate, Agent proof chain, and hardened
container suites remain the regression baseline.

## Claim boundary

Phase 11 does **not**:

- make bounded PPMC a proof of all possible future behavior;
- change the configured PPMC bound or state budget;
- add arbitrary SQL/literal synthesis to the grammar;
- change PolicyEngine, disclosure history, DataHub behavior, or Agent privileges;
- make proof-bound execution canonical;
- wire the Governed Agent or PPMC into the current HTTP/product execution path;
- change the current canonical legacy `ExecutionAuthorizer` behavior.

`docs/security-architecture.md` remains the canonical current-runtime truth until a later explicit
migration phase changes product wiring.
