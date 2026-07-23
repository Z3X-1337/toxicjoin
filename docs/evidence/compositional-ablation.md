# ToxicJoin Compositional Interaction Ablation Evidence

## Result

The compositional interaction ablation passed in GitHub Actions on **July 23, 2026**.

- Workflow: `Compositional Ablation Evidence`
- GitHub Actions run: https://github.com/Z3X-1337/toxicjoin/actions/runs/30047247527
- Tested branch commit: `21a68d2850397654fc54a9f5be55836937faeb18`
- Artifact: `toxicjoin-compositional-ablation`
- Artifact ID: `8579602510`
- Artifact digest: `sha256:0e7d2769d28b9f19b7cf7fe07d86103122569664eeda49f64eea286b8b9932e9`
- Generated report SHA-256: `98c83efb95f0b7feec89a87233ab3e015dd73428c2eaaafe9f5ad9cdad9b8959`

## Measured result

| Metric | Result |
|---|---:|
| Unsafe adversarial mutations | **144** |
| Full ToxicJoin policy blocks unsafe mutations | **144 / 144** |
| Interaction-ablated policy allows unsafe mutations | **144 / 144** |
| Unsafe decisions changed by removing the interaction | **144 / 144** |
| ALLOW/REWRITE benchmark controls | **20** |
| Control decisions preserved by the ablation | **20 / 20** |
| Gate failures | **0** |

## What was ablated

This is an **internal ablation study**, not a competitor comparison.

Both sides use:

- the same ToxicJoin SQL parser;
- the same governed metadata catalog and context resolver;
- the same deterministic `PolicyEngine` implementation;
- the same policy configuration for all other branches.

The ablated run changes one configuration dimension: the quasi-identifier interaction threshold is raised beyond the maximum possible in this finite evaluation. That prevents the declared non-grouped interaction

```text
stable pseudonym + quasi-identifiers + sensitive attribute
```

from firing, while fail-closed metadata handling, direct-identifier handling, and grouped sensitive-threshold logic remain active.

## Evaluation design

The unsafe side reuses the complete **144-case adversarial mutation matrix**. Those queries vary aliases, JOIN spelling, predicates, and bounded ordering while preserving the same individual-level sensitive composition.

The control side uses all **20** non-BLOCK initial-decision cases from the balanced benchmark:

- 10 expected `ALLOW` cases;
- 10 expected `REWRITE` cases.

The shipped ToxicJoin policy blocks every unsafe mutation. When only the cross-column interaction is disabled, every one of those 144 mutations becomes `ALLOW`, while all 20 ALLOW/REWRITE controls keep their expected initial decision.

## Interpretation

On this declared evaluation, the security difference is attributable to ToxicJoin's **compositional interaction rule**, rather than to SQL parsing, metadata lookup, or a blanket-deny policy.

This supports the project's central design claim: fields that are acceptable in isolation can form a materially different privacy risk when combined, so authorization must reason across the composition rather than only over independent field labels.

## Scope and limitation

This does **not** claim that every possible column-local policy would behave exactly like the ablated configuration, and it does not compare ToxicJoin against DataHub or any competing product.

It is a controlled internal ablation measuring the causal contribution of one ToxicJoin policy interaction on the declared 144 unsafe cases and 20 controls.

## Reproduce

```bash
python -m pip install -e '.[dev]'
toxicjoin-ablation --output-dir artifacts/compositional-ablation
```

The command exits non-zero if the shipped policy fails to block the declared unsafe set, if the targeted ablation no longer isolates the interaction on that set, or if any ALLOW/REWRITE control changes unexpectedly.
