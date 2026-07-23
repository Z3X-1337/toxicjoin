import fs from "node:fs";
import path from "node:path";
import { chromium } from "playwright-core";

const baseUrl = process.env.TOXICJOIN_UI_URL ?? "http://127.0.0.1:18000";
const browserExecutable = process.env.BROWSER_EXECUTABLE;
const outputDirectory =
  process.env.TOXICJOIN_RUNTIME_CAPTURE_DIR ?? "artifacts/runtime-video-captures";

if (!browserExecutable || !fs.existsSync(browserExecutable)) {
  throw new Error(
    `BROWSER_EXECUTABLE is missing or invalid: ${browserExecutable ?? "unset"}`,
  );
}

fs.mkdirSync(outputDirectory, { recursive: true });
const rawVideoDirectory = path.join(outputDirectory, "raw-video");
fs.mkdirSync(rawVideoDirectory, { recursive: true });

const browser = await chromium.launch({
  headless: true,
  executablePath: browserExecutable,
  args: ["--no-sandbox", "--disable-dev-shm-usage"],
});

const context = await browser.newContext({
  viewport: { width: 1920, height: 1080 },
  screen: { width: 1920, height: 1080 },
  deviceScaleFactor: 1,
  reducedMotion: "reduce",
  recordVideo: {
    dir: rawVideoDirectory,
    size: { width: 1920, height: 1080 },
  },
});

const page = await context.newPage();
const video = page.video();
const pageErrors = [];
const consoleErrors = [];
const failedRequests = [];
const executeSafeResponses = [];
const captured = [];

page.on("pageerror", (error) => pageErrors.push(String(error)));
page.on("console", (message) => {
  if (message.type() === "error") consoleErrors.push(message.text());
});
page.on("requestfailed", (request) => {
  failedRequests.push({
    url: request.url(),
    error: request.failure()?.errorText ?? "unknown",
  });
});
page.on("response", (response) => {
  if (response.url().includes("/api/execute-safe")) {
    executeSafeResponses.push({
      url: response.url(),
      status: response.status(),
      ok: response.ok(),
    });
  }
});

const sleep = (milliseconds) =>
  new Promise((resolve) => setTimeout(resolve, milliseconds));

async function requestJson(relativePath) {
  const response = await context.request.get(`${baseUrl}${relativePath}`);
  if (!response.ok()) {
    throw new Error(
      `runtime evidence request failed: ${relativePath} -> ${response.status()}`,
    );
  }
  return response.json();
}

async function assertApiBackedFixtureMode() {
  const replayNotice = page.getByText("Deterministic replay", { exact: true });
  if (await replayNotice.isVisible({ timeout: 750 }).catch(() => false)) {
    throw new Error("runtime capture fell back to deterministic replay");
  }

  const fixtureMode = page.getByText("Fixture execution", { exact: true });
  await fixtureMode.waitFor({ state: "visible", timeout: 30_000 });

  const modeNotice = page.locator(".mode-notice");
  if (await modeNotice.isVisible({ timeout: 750 }).catch(() => false)) {
    throw new Error(`unexpected mode notice: ${await modeNotice.innerText()}`);
  }
}

async function waitForOutcome(initialDecision, effectiveDecision) {
  await page
    .locator(".journey-step")
    .filter({ hasText: "Initial policy" })
    .filter({ hasText: initialDecision })
    .waitFor({ state: "visible", timeout: 30_000 });
  await page
    .locator(".decision-display strong")
    .filter({ hasText: effectiveDecision })
    .waitFor({ state: "visible", timeout: 30_000 });

  if (initialDecision === "REWRITE") {
    await page
      .getByText("Verified rewrite applied", { exact: true })
      .waitFor({ state: "visible", timeout: 30_000 });
    await page
      .getByText("All checks passed", { exact: true })
      .waitFor({ state: "visible", timeout: 30_000 });
  }

  if (effectiveDecision === "BLOCK") {
    await page
      .getByText("Execution intentionally skipped", { exact: true })
      .waitFor({ state: "visible", timeout: 30_000 });
  }
}

async function scrollTo(selector) {
  const target = page.locator(selector).first();
  await target.waitFor({ state: "visible", timeout: 20_000 });
  await target.scrollIntoViewIfNeeded();
  await page.evaluate(() => window.scrollBy({ top: -92, behavior: "auto" }));
  await sleep(850);
}

async function captureCurrent(name, evidence = {}) {
  await sleep(900);
  const fileName = `${name}.png`;
  await page.screenshot({
    path: path.join(outputDirectory, fileName),
    fullPage: false,
  });
  captured.push({
    name,
    file: fileName,
    url: page.url(),
    evidence,
  });
  await sleep(1_100);
}

async function selectScenarioByTitle(title) {
  const button = page.locator("button.scenario-button").filter({ hasText: title }).first();
  await button.waitFor({ state: "visible", timeout: 15_000 });
  await button.click();
}

let captureError = null;
let health = null;
let scenarios = [];
let benchmark = null;

try {
  health = await requestJson("/api/health");
  if (health?.status !== "ok" || health?.mode !== "fixture") {
    throw new Error(`unexpected production fixture health: ${JSON.stringify(health)}`);
  }

  const scenarioPayload = await requestJson("/api/demo/scenarios");
  scenarios = scenarioPayload?.scenarios ?? [];
  benchmark = await requestJson("/api/benchmark/summary");
  if (benchmark?.corpus?.total !== 30 || benchmark?.metrics?.false_allow_count !== 0) {
    throw new Error("runtime benchmark summary does not match the frozen judge contract");
  }

  const flagship = scenarios.find(
    (scenario) => scenario.scenario_id === "rewrite-churn-regions",
  );
  const blocked = scenarios.find(
    (scenario) => scenario.expected_initial_decision === "BLOCK",
  );
  const allowed = scenarios.find(
    (scenario) => scenario.expected_initial_decision === "ALLOW",
  );
  if (!flagship || !blocked || !allowed) {
    throw new Error("runtime demo scenarios are incomplete");
  }

  await page.goto(baseUrl, {
    waitUntil: "domcontentloaded",
    timeout: 60_000,
  });
  await page.getByText("ToxicJoin", { exact: true }).first().waitFor({
    state: "visible",
    timeout: 30_000,
  });
  await assertApiBackedFixtureMode();

  // The UI auto-runs the flagship scenario after API bootstrap.
  await waitForOutcome("REWRITE", "ALLOW");
  await page.evaluate(() => window.scrollTo({ top: 0, behavior: "auto" }));
  await captureCurrent("01-flagship-rewrite-to-allow", {
    scenario_id: flagship.scenario_id,
    initial: "REWRITE",
    effective: "ALLOW",
    source_mode: "api",
  });

  await scrollTo(".evidence-panel");
  await captureCurrent("02-governed-composition-evidence", {
    scenario_id: flagship.scenario_id,
    proof: "governed-composition",
  });

  await scrollTo(".sql-panel");
  await captureCurrent("03-verified-sql-rewrite", {
    scenario_id: flagship.scenario_id,
    proof: "reparsed-and-verified-rewrite",
  });

  await scrollTo(".verification-panel");
  await captureCurrent("04-independent-verification", {
    scenario_id: flagship.scenario_id,
    proof: "verification-passed",
  });

  await scrollTo(".receipt-panel");
  await captureCurrent("05-immutable-receipt", {
    scenario_id: flagship.scenario_id,
    proof: "receipt-without-raw-rows",
  });

  await page.evaluate(() => window.scrollTo({ top: 0, behavior: "auto" }));
  await sleep(700);
  await selectScenarioByTitle(blocked.title);
  await waitForOutcome("BLOCK", "BLOCK");
  await page.evaluate(() => window.scrollTo({ top: 0, behavior: "auto" }));
  await captureCurrent("06-fail-closed-block", {
    scenario_id: blocked.scenario_id,
    initial: "BLOCK",
    effective: "BLOCK",
    proof: "database-execution-skipped",
  });

  await scrollTo(".verification-panel");
  await captureCurrent("07-block-execution-skipped", {
    scenario_id: blocked.scenario_id,
    proof: "execution-intentionally-skipped",
  });

  await page.evaluate(() => window.scrollTo({ top: 0, behavior: "auto" }));
  await sleep(700);
  await selectScenarioByTitle(allowed.title);
  await waitForOutcome("ALLOW", "ALLOW");
  await page.evaluate(() => window.scrollTo({ top: 0, behavior: "auto" }));
  await captureCurrent("08-low-risk-allow", {
    scenario_id: allowed.scenario_id,
    initial: "ALLOW",
    effective: "ALLOW",
    proof: "no-unnecessary-denial",
  });

  if (executeSafeResponses.length < 3 || executeSafeResponses.some((item) => !item.ok)) {
    throw new Error(
      `expected three successful browser /api/execute-safe responses, got ${JSON.stringify(executeSafeResponses)}`,
    );
  }
  if (pageErrors.length) {
    throw new Error(`runtime UI page errors: ${pageErrors.join(" | ")}`);
  }
} catch (error) {
  captureError = error;
  await page
    .screenshot({
      path: path.join(outputDirectory, "capture-failure.png"),
      fullPage: false,
    })
    .catch(() => {});
  fs.writeFileSync(
    path.join(outputDirectory, "capture-failure.html"),
    await page.content().catch(() => ""),
    "utf8",
  );
} finally {
  await page.close().catch(() => {});
  await context.close().catch(() => {});
  await browser.close().catch(() => {});
}

let finalVideo = null;
if (video) {
  const recordedPath = await video.path().catch(() => null);
  if (recordedPath && fs.existsSync(recordedPath)) {
    finalVideo = path.join(outputDirectory, "toxicjoin-runtime-capture.webm");
    fs.copyFileSync(recordedPath, finalVideo);
  }
}

const report = {
  schema_version: "1.0",
  created_at: new Date().toISOString(),
  status: captureError ? "failed" : "captured",
  resolution: "1920x1080",
  browser_executable: browserExecutable,
  product_url: baseUrl,
  runtime_health: health,
  scenario_contract: scenarios.map((scenario) => ({
    scenario_id: scenario.scenario_id,
    title: scenario.title,
    expected_initial_decision: scenario.expected_initial_decision,
    expected_effective_decision: scenario.expected_effective_decision,
  })),
  benchmark_contract: benchmark
    ? {
        total: benchmark.corpus?.total ?? null,
        false_allow_count: benchmark.metrics?.false_allow_count ?? null,
        gate_failures: benchmark.gate_failures ?? null,
      }
    : null,
  execute_safe_responses: executeSafeResponses,
  captured,
  screenshots: captured.map((entry) => entry.file),
  raw_video: finalVideo ? path.basename(finalVideo) : null,
  page_error_count: pageErrors.length,
  page_errors: pageErrors,
  console_error_count: consoleErrors.length,
  console_errors: consoleErrors,
  failed_request_count: failedRequests.length,
  failed_requests: failedRequests,
  failure: captureError ? String(captureError?.stack ?? captureError) : null,
};

fs.writeFileSync(
  path.join(outputDirectory, "capture-report.json"),
  `${JSON.stringify(report, null, 2)}\n`,
  "utf8",
);
console.log(JSON.stringify(report, null, 2));

if (captureError) throw captureError;
if (!finalVideo) throw new Error("Playwright did not produce a reusable runtime video");
