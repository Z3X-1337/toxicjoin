# Trust Kernel Failure 0001 — First authorization-boundary run

Status: **FAILED — root cause not yet classified**

The first GitHub Actions execution of the proof-carrying authorization tests failed before any corrective change was made.

- Workflow: `Research Trust Kernel Authorization`
- Run: `30051530275`
- Job: `89354450101`
- Tested branch: `research/trust-kernel-realworld`
- Tested head at trigger: `83350f7046f02268ad22ed03082261ff95983a8e`
- Failed step: `Run proof-carrying authorization attacks`

## Scientific handling

This failure is intentionally retained. The authorization implementation and test assertions are not being changed until the exact failing assertion/exception is captured.

The next change is diagnostic only: persist pytest output as an artifact. After diagnosis, the root cause will be classified as one of:

- `AUTHORIZATION_DESIGN`
- `TEST_ASSUMPTION`
- `CORE_REGRESSION`
- `INFRASTRUCTURE`

Any corrective change will retain this baseline and record before/after behavior.
