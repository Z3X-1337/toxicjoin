# ToxicJoin Hosted Replay Evidence

## Evidence status

The public replay remains available, functional, and explicitly labeled as a deterministic replay. It is **not current-main release evidence**.

Phase 0 revalidated the live deployment against exact repository state `25a18b872d21ed91abdec3ad1893c07b5f424621` and classified it as:

```text
HISTORICAL_VERIFIED_DIVERGED_LINEAGE_WITH_PROVENANCE_SHAPE_DRIFT
```

The original July 23 evidence below is retained as historical provenance. The July 27 Phase 0 validation is the newer statement about the public deployment's relationship to the repository.

## Public URL

https://toxicjoin-replay.vercel.app/

The public site is intentionally a **Deterministic Replay**. It does not claim live DuckDB execution or a live DataHub write. The executable product path remains the Docker/FastAPI service, and real DataHub integration is documented separately in `datahub-live.md`.

## Phase 0 revalidation — July 27, 2026

Validation-only PR #100 audited the public site without changing or redeploying it. The validation branch was closed without merge.

Freshness/provenance run `30243934947`: **PASS**.

- artifact ID: `8644271435`;
- artifact digest: `sha256:1d2e2ba308bb31a1899fce7661acbaf2bdbc700802cee4879f9e458935618afe`;
- report SHA-256: `1393ffd548ce4c41c8d9b49dbc695d180b61089eece57e5eb03c2f36e2ce293c`;
- validation target: `25a18b872d21ed91abdec3ad1893c07b5f424621`.

The live document and live `/provenance.json` both returned HTTP `200`.

### Provenance identity and shape

The live provenance preserves the critical source identity fields from the committed replay provenance:

- schema version `1.0`;
- source workflow run `29968713188`;
- source PR `7`;
- source commit `bd8085c300a0065cc714d6e86f62f657df2d84c9`;
- source artifact ID `8548808025`;
- source artifact digest `sha256:93c8773c931ece44f0963a0b19e839430e2e49f31fcfcb380a4a6f4c9cf382a7`.

The live deployment changes the provenance shape:

- committed field `artifact_name` is absent from the live provenance;
- live provenance adds `materialized_commit`;
- live `materialized_commit` is `183571534a35be6a5ae85ed9d75308ada6eba41e` and matches the immutable commit embedded in both live jsDelivr asset URLs.

The materialization commit's committed `public/replay/provenance.json` does not itself contain that exact shape transformation. Phase 0 therefore records this as **provenance shape drift** rather than silently treating the two representations as identical.

### Git relationship to the validated repository state

Neither replay provenance source is an ancestor of the Phase 0 validation target.

Source commit `bd8085c300a0065cc714d6e86f62f657df2d84c9`:

- relationship: `DIVERGED`;
- merge base: `0865cc2e326e1c8fedcc8275ee6cb412ea2f815a`;
- source-only commits versus validation target: `46`;
- validation-target-only commits versus source: `659`.

Materialized asset commit `183571534a35be6a5ae85ed9d75308ada6eba41e`:

- relationship: `DIVERGED`;
- merge base: `5ed1ae40b5d118d4b2143c89062d3a793436036e`;
- materialization-only commits versus validation target: `8`;
- validation-target-only commits versus materialization: `656`.

These are verified side lineages, not a current-main or ancestor release chain.

### Immutable asset integrity

A separate direct-byte diagnostic on final validation head `8916dc849029f8b486ed689b21563e66076308b2` passed in run `30243934933`.

- diagnostic artifact ID: `8644262861`;
- digest: `sha256:d69667cdee57aadec9b473631c4c961b10430288da4f16485334a2224e9891bc`.

JavaScript `index-CIeiud0i.js`:

- HTTP `200`;
- remote/local bytes: `224022 / 224022`;
- remote/local SHA-256: `754f7b3b3df0e69a5bc3faf86c419e3061b3367941ff282a20f4d693022af0a0`.

CSS `index-C9DIVvrs.css`:

- HTTP `200`;
- remote/local bytes: `22790 / 22790`;
- remote/local SHA-256: `6c4d2f602ccb50b8da1803873ee4fed6aa1db1099c41813d75c56b54289fc335`.

The Git blobs at the materialized commit also exactly match the retained replay files in the Phase 0 validation target:

- JavaScript blob: `7df47f2c7ffb4edad2b902616326829d03641691`;
- CSS blob: `c55ddc61c47081c044326e443f4ab046940582b6`.

### Current browser assertions from Phase 0

Google Chrome loaded the public URL at two profiles.

Desktop:

- viewport: `1440 × 1000`;
- document HTTP status: `200`;
- two immutable JavaScript/CSS assets returned HTTP `200`;
- three expected `/api/*` HTTP `404` responses caused Replay fallback;
- no horizontal overflow;
- zero unexpected console errors;
- zero JavaScript page errors;
- zero failed requests.

Mobile:

- viewport: `390 × 844`;
- document HTTP status: `200`;
- the same two immutable assets returned HTTP `200`;
- the same three expected Replay fallback API responses were observed;
- no horizontal overflow;
- zero unexpected console errors;
- zero JavaScript page errors;
- zero failed requests.

The disclosure remained explicit:

> API unavailable. Showing a clearly labeled deterministic replay; no live execution or DataHub write is being claimed.

## Original hosted verification — July 23, 2026

The hosted Replay passed an external Chrome verification gate on **July 23, 2026**.

- GitHub Actions run: `29980181195`;
- verification artifact: `toxicjoin-hosted-replay-verification`;
- artifact ID: `8552895947`;
- artifact digest: `sha256:2b493d0da06df547c598db686014d5862130fdb2666ebd79bf029c91f1da90bd`;
- machine-readable retained result: [`hosted-replay-verification.json`](hosted-replay-verification.json).

### Original artifact provenance

The public page was built from the judge-interface artifact produced by the green CI run for PR #7.

- source workflow run: `29968713188`;
- source commit: `bd8085c300a0065cc714d6e86f62f657df2d84c9`;
- source artifact ID: `8548808025`;
- source artifact digest: `sha256:93c8773c931ece44f0963a0b19e839430e2e49f31fcfcb380a4a6f4c9cf382a7`.

The JavaScript and CSS are requested through immutable commit-pinned jsDelivr URLs. The Vercel root document exposes deployment provenance at `/provenance.json`.

### Original browser assertions

Desktop profile:

- viewport: 1440 × 1000;
- full-page screenshot: 1440 × 2756;
- document HTTP status: 200;
- two immutable JavaScript/CSS assets returned successfully;
- three expected `/api/*` HTTP 404 responses caused Replay mode;
- Replay disclosure was visible;
- initial `REWRITE` and effective `ALLOW` were present;
- the safe SQL contained the minimum distinct-subject threshold;
- the result preview showed three rows with forty subjects per region;
- benchmark displayed thirty queries and zero false allows;
- no horizontal overflow;
- no unexpected console error;
- no JavaScript page error;
- no failed request.

Desktop screenshot SHA-256:

```text
bedd09cd4f15a25136d6e5a40e758e1bc4994dba08a3933586608a33fb4d96e6
```

Mobile profile:

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

Mobile screenshot SHA-256:

```text
f65ee0b163bfb3ec5f6e6af16ba878a6a8386706b6ba404c485ce6962c93bf8a
```

## Expected network signals

The hosted Replay intentionally has no executable `/api` backend. During bootstrap, the frontend requests:

- `/api/health`;
- `/api/demo/scenarios`;
- `/api/benchmark/summary`.

Each returns HTTP 404. The application then enters its explicit Replay path and displays the deterministic Replay disclosure. The browser gate treats only these three expected fallback signals as acceptable. Any failed static asset, JavaScript exception, additional failed request, unexpected console error, missing disclosure, or layout overflow fails verification.

## Claim boundary

This evidence supports the following bounded statement:

> Judges can open a public deterministic Replay whose retained immutable interface assets have been externally revalidated and whose fallback behavior remains functional.

It does **not** support claiming that the public Replay is generated from current `main`, that its source commits are ancestors of current `main`, that it performs live SQL execution, that it performs live DataHub mutation, or that it is dynamic API processing.

The executable Docker/FastAPI path and separately retained DataHub evidence must be cited for those capabilities.