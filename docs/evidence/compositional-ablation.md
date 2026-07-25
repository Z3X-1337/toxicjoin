# ToxicJoin Compositional Interaction Ablation

**Gate:** PASS  
**Exact runtime candidate:** `e139fa99bd666505ed83a18188423722405695a2`  
**Policy version:** `0.2.0`  
**Evaluation version:** `2.0`  
**Unsafe mutation cases:** 144  
**Benign/remediable controls:** 20  
**Full ToxicJoin policy blocks unsafe mutations:** 144/144  
**Interaction-ablated policy allows unsafe mutations:** 144/144  
**Unsafe decisions changed by the ablation:** 144/144  
**ALLOW/REWRITE controls preserved:** 20/20

Exact-head provenance:

- workflow run `30140102635`;
- artifact ID `8614165227`;
- artifact digest `sha256:36a54ac332ab18a343742090fb3c04559b84813d5434d8171500b64972874d1e`;
- report SHA-256 `14d7fb64be2c838966fffe0e8f20273cba3877255da767e99f04df980f4f5cdf`.

## What was ablated

This is an internal ablation study, not a competitor comparison.

Both sides use the same ToxicJoin parser, governed metadata resolver, deterministic `PolicyEngine`, and all unrelated policy branches. The ablated side removes final-output semantic exposure evidence from the `QueryPlan` and raises the legacy quasi-identifier threshold so the declared non-grouped compositional interaction cannot fire in this finite evaluation.

## Interpretation

The shipped policy blocks every one of the 144 unsafe individual profiles. When only the targeted compositional interaction is removed, all 144 become ALLOW while the 20 ALLOW/REWRITE controls remain unchanged.

That isolates the causal contribution of ToxicJoin's compositional reasoning rather than comparing against another product or changing the parser, data, or general fail-closed behavior.

This does not claim every possible column-local policy would behave identically. It is a bounded internal causal evaluation over the declared suite.

For the full validation chain, see [`release-candidate.md`](release-candidate.md).