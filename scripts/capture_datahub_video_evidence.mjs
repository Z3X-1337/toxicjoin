import fs from "node:fs";
import path from "node:path";
import { chromium } from "playwright-core";

const baseUrl = process.env.DATAHUB_UI_URL ?? "http://127.0.0.1:9002";
const browserExecutable = process.env.BROWSER_EXECUTABLE;
const manifestPath =
  process.env.TOXICJOIN_CAPTURE_MANIFEST ?? ".toxicjoin/video-capture-manifest.json";
const outputDirectory =
  process.env.TOXICJOIN_CAPTURE_DIR ?? "artifacts/video-captures";

if (!browserExecutable || !fs.existsSync(browserExecutable)) {
  throw new Error(
    `BROWSER_EXECUTABLE is missing or invalid: ${browserExecutable ?? "unset"}`,
  );
}

const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
const datasetUrn = manifest.flagship_dataset_urn;
const decisionUrn = manifest.decision_document_urn;
if (!datasetUrn?.startsWith("urn:li:dataset:")) {
  throw new Error("capture manifest is missing a valid flagship dataset URN");
}
if (!decisionUrn?.startsWith("urn:li:document:")) {
  throw new Error("capture manifest is missing a valid Decision document URN");
}

fs.mkdirSync(outputDirectory, { recursive: true });
const videoDirectory = path.join(outputDirectory, "raw-video");
fs.mkdirSync(videoDirectory, { recursive: true });

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
    dir: videoDirectory,
    size: { width: 1920, height: 1080 },
  },
});

const page = await context.newPage();
const video = page.video();
const pageErrors = [];
const consoleErrors = [];
const failedRequests = [];
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

const sleep = (milliseconds) =>
  new Promise((resolve) => setTimeout(resolve, milliseconds));

const entityUrl = (entityType, urn) =>
  `${baseUrl}/${entityType}/${encodeURIComponent(urn)}/`;

async function waitForAnyText(candidates, timeout = 30_000) {
  const deadline = Date.now() + timeout;
  let lastError;
  while (Date.now() < deadline) {
    for (const candidate of candidates) {
      try {
        const locator = page.getByText(candidate, { exact: false }).first();
        if (await locator.isVisible({ timeout: 750 })) return candidate;
      } catch (error) {
        lastError = error;
      }
    }
    await sleep(400);
  }
  throw (
    lastError ??
    new Error(
      `none of the expected text values became visible: ${candidates.join(", ")}`,
    )
  );
}

async function writePageDiagnostics(prefix, error = null) {
  const diagnostic = {
    schema_version: "1.0",
    stage: prefix,
    url: page.url(),
    title: await page.title().catch(() => ""),
    error: error ? String(error?.stack ?? error) : null,
    page_errors: pageErrors,
    console_errors: consoleErrors,
    failed_requests: failedRequests,
  };
  fs.writeFileSync(
    path.join(outputDirectory, `${prefix}.json`),
    `${JSON.stringify(diagnostic, null, 2)}\n`,
    "utf8",
  );
  fs.writeFileSync(
    path.join(outputDirectory, `${prefix}.html`),
    await page.content().catch(() => ""),
    "utf8",
  );
  fs.writeFileSync(
    path.join(outputDirectory, `${prefix}.txt`),
    await page.locator("body").innerText().catch(() => ""),
    "utf8",
  );
  await page
    .screenshot({
      path: path.join(outputDirectory, `${prefix}.png`),
      fullPage: false,
    })
    .catch(() => {});
}

async function captureCurrent(name, expectedText) {
  const matchedText = await waitForAnyText(expectedText, 45_000);
  await sleep(1_600);
  await page.screenshot({
    path: path.join(outputDirectory, `${name}.png`),
    fullPage: false,
  });
  captured.push({
    name,
    url: page.url(),
    matched_text: matchedText,
  });
  await sleep(1_600);
}

async function capture(name, url, expectedText) {
  const response = await page.goto(url, {
    waitUntil: "domcontentloaded",
    timeout: 60_000,
  });
  if (response && response.status() >= 400) {
    throw new Error(`${name}: HTTP ${response.status()} for ${url}`);
  }
  await captureCurrent(name, expectedText);
}

async function loginAsQuickstartAdmin() {
  const loginUrl = `${baseUrl}/login`;
  await page.goto(loginUrl, {
    waitUntil: "domcontentloaded",
    timeout: 60_000,
  });

  const username = page.getByTestId("username");
  const password = page.getByTestId("password");
  const signIn = page.getByTestId("sign-in");
  await username.waitFor({ state: "visible", timeout: 30_000 });
  await password.waitFor({ state: "visible", timeout: 30_000 });
  await signIn.waitFor({ state: "visible", timeout: 30_000 });

  await username.fill(process.env.DATAHUB_ADMIN_USERNAME ?? "datahub");
  await password.fill(process.env.DATAHUB_ADMIN_PASSWORD ?? "datahub");
  await signIn.click();
  await page.waitForURL((url) => !url.pathname.includes("login"), {
    waitUntil: "networkidle",
    timeout: 45_000,
  });
  await page.evaluate(() => localStorage.setItem("skipWelcomeModal", "true"));
  await sleep(1_200);
}

async function clickEntityTab(testId, fallbackName) {
  const byTestId = page.getByTestId(testId);
  if (await byTestId.isVisible({ timeout: 8_000 }).catch(() => false)) {
    await byTestId.click();
    return;
  }
  const byText = page.getByText(fallbackName, { exact: true }).first();
  await byText.waitFor({ state: "visible", timeout: 15_000 });
  await byText.click();
}

let captureError = null;
try {
  await loginAsQuickstartAdmin();

  await capture(
    "01-dataset-overview",
    entityUrl("dataset", datasetUrn),
    ["retention_scores", "retention scores", "Retention Scores"],
  );

  await clickEntityTab("schema-tab", "Schema");
  await captureCurrent(
    "02-governed-schema",
    ["churn_score", "customer_id", "Schema"],
  );

  await clickEntityTab("lineage-tab", "Lineage");
  await captureCurrent(
    "03-column-lineage",
    ["Lineage", "Upstream", "retention_scores"],
  );

  await capture(
    "04-toxicjoin-decision",
    entityUrl("document", decisionUrn),
    [
      "ToxicJoin Decision",
      "Flagship Rewrite Verified",
      "SMALL_GROUP_RISK",
      "Decision",
    ],
  );

  if (pageErrors.length) {
    throw new Error(`DataHub UI page errors: ${pageErrors.join(" | ")}`);
  }
} catch (error) {
  captureError = error;
  await writePageDiagnostics("capture-failure", error);
} finally {
  await page.close().catch(() => {});
  await context.close().catch(() => {});
  await browser.close().catch(() => {});
}

let finalVideo = null;
if (video) {
  const recordedPath = await video.path().catch(() => null);
  if (recordedPath && fs.existsSync(recordedPath)) {
    finalVideo = path.join(outputDirectory, "datahub-ui-capture.webm");
    fs.copyFileSync(recordedPath, finalVideo);
  }
}

const report = {
  schema_version: "1.0",
  created_at: new Date().toISOString(),
  status: captureError ? "failed" : "captured",
  resolution: "1920x1080",
  browser_executable: browserExecutable,
  datahub_ui_url: baseUrl,
  flagship_dataset_urn: datasetUrn,
  decision_document_urn: decisionUrn,
  captured,
  screenshots: captured.map((entry) => `${entry.name}.png`),
  raw_video: finalVideo ? path.basename(finalVideo) : null,
  page_error_count: pageErrors.length,
  console_error_count: consoleErrors.length,
  failed_request_count: failedRequests.length,
  failure: captureError ? String(captureError?.stack ?? captureError) : null,
};
fs.writeFileSync(
  path.join(outputDirectory, "capture-report.json"),
  `${JSON.stringify(report, null, 2)}\n`,
  "utf8",
);
console.log(JSON.stringify(report, null, 2));

if (captureError) {
  throw captureError;
}
if (!video || !finalVideo) {
  throw new Error("Playwright did not produce a reusable video recording");
}
