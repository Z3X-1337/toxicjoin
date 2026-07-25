# ToxicJoin Adversarial Mutation Suite

**Gate:** PASS  
**Exact final security head:** `536c37c34de7b36495d33f63095585f72e5f4b46`  
**Landed main merge commit:** `ee4991a93070c148e41dd158c952d5f1e9a6ed2c`  
**Policy version:** `0.2.0`  
**Cases:** 144  
**Initial BLOCK:** 144/144  
**Effective BLOCK:** 144/144  
**Intended compositional-risk reason:** 144/144  
**Unexpected database executions:** 0  
**Unsafe initial allows:** 0  
**Unsafe effective allows:** 0

Exact-head provenance:

- workflow run `30143510877`;
- artifact ID `8615253422`;
- artifact digest `sha256:83db3f416957f9cc7b16c75d6c8aac51ae83e889a7af7572b2623e3192f2ffb1`;
- report SHA-256 `86011fc74ef6ca03e7b83d21e8770037fb32ddb22d41b750abc09aeabe443565`.

## Mutation matrix

Three known-unsafe individual-composition families are mutated across four alias profiles, two JOIN spellings, three predicate forms, and two ordering/limit forms.

| Family | Cases |
|---|---:|
| churn-profile | 48 |
| financial-profile | 48 |
| support-profile | 48 |

Every generated query remains a valid supported SELECT containing a stable pseudonym, two quasi-identifiers, and one governed sensitive attribute. A case passes only when ToxicJoin reaches the intended `COMPOSITIONAL_REIDENTIFICATION_RISK` rule, returns BLOCK, and never invokes DuckDB.

Parser rejection alone does not count as a successful adversarial result.

## Interpretation

This suite asks whether superficial SQL variation changes the security outcome for declared known-unsafe individual compositions. On this 144-case matrix it did not.

This is a bounded metamorphic security evaluation, not a claim of universal SQL coverage or universal re-identification detection.

For the full validation chain, see [`release-candidate.md`](release-candidate.md).
