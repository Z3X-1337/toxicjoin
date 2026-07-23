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

const entityUrl = (entityType, urn, tab = "") => {
  const suffix = tab ? `/${tab}` : "/";
  return `${baseUrl}/${entityType}/${encodeURIComponent(urn)}${suffix}`;
};

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

async function capture(name, url, expectedText) {
  const response = await page.goto(url, {
    waitUntil: "domcontentloaded",
    timeout: 60_000,
  });
  if (response && response.status() >= 400) {
    throw new Error(`${name}: HTTP ${response.status()} for ${url}`);
  }
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

let captureError = null;
try {
  await page.goto(baseUrl, {
    waitUntil: "domcontentloaded",
    timeout: 60_000,
  });

  const usernameCandidates = [
    page.getByTestId("username"),
    page.locator('input[name="username"]'),
    page.locator('input[placeholder*="username" i]'),
  ];
  let username = null;
  for (const candidate of usernameCandidates) {
    if (await candidate.isVisible({ timeout: 2_000 }).catch(() => false)) {
      username = candidate;
      break;
    }
  }

  if (username) {
    await username.fill("datahub");
    const passwordCandidates = [
      page.getByTestId("password"),
      page.locator('input[name="password"]'),
      page.locator('input[type="password"]'),
    ];
    let password = null;
    for (const candidate of passwordCandidates) {
      if (await candidate.isVisible({ timeout: 2_000 }).catch(() => false)) {
        password = candidate;
        break;
      }
    }
    if (!password) {
      throw new Error("DataHub login page was visible but no password field was found");
    }
    await password.fill("datahub");
    await password.press("Enter");
    await waitForAnyText(["DataHub", "Search", "Home"], 45_000);
    await sleep(1_200);
  }

  await capture(
    "01-dataset-overview",
    entityUrl("dataset", datasetUrn),
    ["retention_scores", "retention scores", "Retention Scores"],
  );

  await capture(
    "02-governed-schema",
    entityUrl("dataset", datasetUrn, "Schema"),
    ["churn_score", "customer_id", "Schema"],
  );

  await capture(
    "03-column-lineage",
    entityUrl("dataset", datasetUrn, "Lineage"),
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
