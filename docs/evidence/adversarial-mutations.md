# ToxicJoin Adversarial Mutation Evidence

## Result

The adversarial mutation gate passed in GitHub Actions on **July 23, 2026**.

- Workflow: `Adversarial Mutation Evidence`
- GitHub Actions run: https://github.com/Z3X-1337/toxicjoin/actions/runs/30046801748
- Tested branch commit: `0e156ff7d9132743d3a73e4761a6a37503ddc364`
- Artifact: `toxicjoin-adversarial-mutations`
- Artifact ID: `8579435638`
- Artifact digest: `sha256:991f2727dc7e60e13f96553e132c4dde1daa4b796f42cafb963b23aeea535e64`
- Generated report SHA-256: `5ae8de95c67ba22f06dfdfd92a405de40252aa0b2b2d9867fd28d6935d51119c`

## Measured result

| Metric | Result |
|---|---:|
| Generated adversarial mutations | **144** |
| Initial `BLOCK` | **144 / 144** |
| Effective `BLOCK` | **144 / 144** |
| `COMPOSITIONAL_REIDENTIFICATION_RISK` detected | **144 / 144** |
| Unexpected database executions | **0** |
| Unsafe initial allows | **0** |
| Unsafe effective allows | **0** |

The suite covers three individual-level unsafe composition families:

| Family | Mutations |
|---|---:|
| Churn/model-score profile | 48 |
| Financial profile | 48 |
| Sensitive support profile | 48 |

Each family is crossed with:

- four alias profiles;
- two equivalent JOIN spellings (`JOIN` / `INNER JOIN`);
- three predicate forms;
- two ordering/limit forms.

This produces `3 × 4 × 2 × 3 × 2 = 144` generated SQL cases.

## Security invariant

Every generated query remains an individual-level composition containing:

1. a stable pseudonymous subject key;
2. two quasi-identifiers (`age_band` and `precise_area`);
3. one governed sensitive attribute.

A mutation counts as PASS only when all of the following are true:

- initial decision is `BLOCK`;
- effective decision is `BLOCK`;
- the initial reason includes `COMPOSITIONAL_REIDENTIFICATION_RISK`;
- DuckDB execution never occurs.

This deliberately prevents parser rejection from being counted as a successful adversarial result: the generated mutations are valid supported `SELECT` statements and must reach the intended compositional policy rule.

## Why this matters

The main 30-case benchmark is balanced across ALLOW, REWRITE, and BLOCK behavior. This suite answers a different question: **does superficial SQL variation change the security decision for known-unsafe individual compositions?**

On the declared 144-mutation matrix, it did not. All mutations reached the intended compositional-risk rule and failed before database execution.

## Scope and limitation

This is a declared metamorphic security evaluation over three unsafe composition families and the listed mutation dimensions. It is not a claim of universal SQL coverage, universal re-identification detection, or proof against every possible adversarial query.

The suite uses only ToxicJoin's deterministic synthetic warehouse and governed fixture. No real personal data is involved.

## Reproduce

```bash
python -m pip install -e '.[dev]'
toxicjoin-adversarial --output-dir artifacts/adversarial-mutations
```

The command exits non-zero on any mutation that is not blocked for the intended compositional-risk reason, on any unsafe initial/effective allow, or if any mutation reaches database execution.
