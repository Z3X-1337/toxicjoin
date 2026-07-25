# ToxicJoin Compositional Interaction Ablation

**Gate:** PASS  
**Exact release candidate:** `fe4f8da2579e09bdbfb1d998b92dfea86549733b`  
**Policy version:** `0.2.0`  
**Evaluation version:** `2.0`  
**Unsafe mutation cases:** 144  
**Benign/remediable controls:** 20  
**Full ToxicJoin policy blocks unsafe mutations:** 144/144  
**Interaction-ablated policy allows unsafe mutations:** 144/144  
**Unsafe decisions changed by the ablation:** 144/144  
**ALLOW/REWRITE controls preserved:** 20/20

Final provenance:

- workflow run `30136824435`;
- artifact ID `8613091689`;
- artifact digest `sha256:b89575b68e927cc5edb7c7072bfbed926c0e3feeb511d4b2ff53ddd63e247fcf`;
- report SHA-256 `14d7fb64be2c838966fffe0e8f20273cba3877255da767e99f04df980f4f5cdf`.

## What was ablated

This is an internal ablation study, not a competitor comparison.

Both sides use the same ToxicJoin parser, governed metadata resolver, deterministic `PolicyEngine`, and all unrelated policy branches. The ablated side removes final-output semantic exposure evidence from the `QueryPlan` and raises the legacy quasi-identifier threshold so the declared non-grouped compositional interaction cannot fire in this finite evaluation.

## Interpretation

The shipped policy blocks every one of the 144 unsafe individual profiles. When only the targeted compositional interaction is removed, all 144 become ALLOW while the 20 ALLOW/REWRITE controls remain unchanged.

That isolates the causal contribution of ToxicJoin's compositional reasoning rather than comparing against another product or changing the parser, data, or general fail-closed behavior.

This does not claim every possible column-local policy would behave identically. It is a bounded internal causal evaluation over the declared suite.

For the full exact-head validation chain, see [`release-candidate.md`](release-candidate.md).