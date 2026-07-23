# ToxicJoin Hosted Replay Evidence

## Public URL

https://toxicjoin-replay.vercel.app/

The public site is intentionally a **deterministic Replay**. It does not claim live DuckDB execution or a live DataHub write. The executable product path remains the Docker/FastAPI service, and the real DataHub integration is documented separately in `datahub-live.md`.

## Verification result

The hosted Replay passed an external Chrome verification gate on **July 23, 2026**.

- GitHub Actions run: https://github.com/Z3X-1337/toxicjoin/actions/runs/29980181195
- Verification Artifact: `toxicjoin-hosted-replay-verification`
- Artifact ID: `8552895947`
- Artifact digest: `sha256:2b493d0da06df547c598db686014d5862130fdb2666ebd79bf029c91f1da90bd`
- Machine-readable retained result: [`hosted-replay-verification.json`](hosted-replay-verification.json)

## Artifact provenance

The public page loads the exact judge-interface bundle produced by the green CI run for PR #7.

- Source workflow run: `29968713188`
- Source commit: `bd8085c300a0065cc714d6e86f62f657df2d84c9`
- Source Artifact ID: `8548808025`
- Source Artifact digest: `sha256:93c8773c931ece44f0963a0b19e839430e2e49f31fcfcb380a4a6f4c9cf382a7`

The JavaScript and CSS are requested through immutable commit-pinned jsDelivr URLs. The Vercel root document contains the source provenance at `/provenance.json`.

## Browser assertions

Google Chrome loaded the public URL at two profiles:

### Desktop

- viewport: 1440 × 1000;
- full-page screenshot: 1440 × 2756;
- document HTTP status: 200;
- two immutable JavaScript/CSS assets returned successfully;
- three expected `/api/*` HTTP 404 responses caused the application to enter Replay mode;
- Replay disclosure was visible;
- initial `REWRITE` and effective `ALLOW` were present;
- the safe SQL contained the minimum distinct-subject threshold;
- the result preview showed three rows with forty subjects per region;
- benchmark displayed thirty queries and zero false allows;
- no horizontal overflow;
- no unexpected console error;
- no JavaScript page error;
- no failed request.

Screenshot SHA-256:

```text
bedd09cd4f15a25136d6e5a40e758e1bc4994dba08a3933586608a33fb4d96e6
```

### Mobile

- viewport: 390 × 844;
- full-page screenshot: 390 × 5696;
- document HTTP status: 200;
- the same immutable JavaScript/CSS assets loaded successfully;
- the full Replay disclosure remained visible even though the compact header chip is hidden responsively;
- the same REWRITE → ALLOW, SQL, verification, result, receipt, and benchmark evidence rendered;
- no horizontal overflow;
- no unexpected console error;
- no JavaScript page error;
- no failed request.

Screenshot SHA-256:

```text
f65ee0b163bfb3ec5f6e6af16ba878a6a8386706b6ba404c485ce6962c93bf8a
```

## Expected network signals

The hosted Replay intentionally has no executable `/api` backend. During bootstrap, the frontend requests:

- `/api/health`;
- `/api/demo/scenarios`;
- `/api/benchmark/summary`.

Each returns HTTP 404. The application then enters its explicit Replay path and displays:

> API unavailable. Showing a clearly labeled deterministic replay; no live execution or DataHub write is being claimed.

The verification gate treats only these three expected 404 signals as acceptable. Any failed static asset, JavaScript exception, additional failed request, unexpected console error, missing disclosure, or layout overflow fails the workflow.

## Claim boundary

This evidence supports the following statement:

> Judges can open a public deterministic Replay that accurately demonstrates the declared ToxicJoin interface and evidence without requiring local setup.

It does **not** support statements that the public site performs live SQL execution, live DataHub mutation, or dynamic API processing. Those capabilities belong to the executable Docker/FastAPI path and the separately retained live DataHub evidence.
