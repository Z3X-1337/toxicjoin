# Trust Kernel Failure 0001 — First authorization-boundary run

Status: **DIAGNOSED — `TEST_ASSUMPTION`**

The first GitHub Actions execution of the proof-carrying authorization tests failed before any corrective change was made.

Baseline:

- Workflow: `Research Trust Kernel Authorization`
- First failing run: `30051530275`
- Diagnostic rerun: `30051609029`
- Diagnostic artifact: `8581227309`
- Artifact digest: `sha256:46c0217a575f78e051437d34e5afb5c5d06df1c96364be9a916d1918efaf4c6f`
- Failed step: `Run proof-carrying authorization attacks`

## Observed failures

Two assertions expected more failed checks than the authorization contract actually requires:

1. Appending `LIMIT 1` changed the exact SQL bytes but did not change ToxicJoin's current structural `QueryPlan`, because `QueryPlan` does not model LIMIT. Verification still failed closed on the `sql` binding exactly as intended.
2. Changing `task_purpose` did not change the deterministic `PolicyDecision`, because the current policy engine does not use task purpose as a decision variable. Verification still failed closed on the independent `task_purpose` binding exactly as intended.

The diagnostic run therefore produced two test failures while the authorization verifier itself rejected both tampered requests.

## Root-cause classification

`TEST_ASSUMPTION`

No authorization implementation change is required for these two observations.

## Corrective action

- Remove assertions that require a `query_plan` mismatch for a LIMIT-only mutation.
- Remove the assertion that task-purpose mutation must also alter `policy_decision`.
- Add a separate structural SQL mutation that genuinely changes the parsed plan and require both `sql` and `query_plan` mismatches there.

This preserves the first failure and distinguishes exact-query binding from structural-plan binding instead of conflating them.
