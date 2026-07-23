import fs from "node:fs";
import path from "node:path";
import { chromium } from "playwright-core";

const baseUrl = process.env.DATAHUB_UI_URL ?? "http://127.0.0.1:9002";
const browserExecutable = process.env.BROWSER_EXECUTABLE;
const manifestPath = process.env.TOXICJOIN_CAPTURE_MANIFEST ?? ".toxicjoin/video-capture-manifest.json";
const outputDirectory = process.env.TOXICJOIN_CAPTURE_DIR ?? "artifacts/video-captures";

if (!browserExecutable || !fs.existsSync(browserExecutable)) {
  throw new Error(`BROWSER_EXECUTABLE is missing or invalid: ${browserExecutable ?? "unset"}`);
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
page.on("pageerror", (error) => pageErrors.push(String(error)));

const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));
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
  throw lastError ?? new Error(`none of the expected text values became visible: ${candidates.join(", ")}`);
}

async function capture(name, url, expectedText) {
  const response = await page.goto(url, { waitUntil: "domcontentloaded", timeout: 60_000 });
  if (response && response.status() >= 400) {
    throw new Error(`${name}: HTTP ${response.status()} for ${url}`);
  }
  await waitForAnyText(expectedText, 45_000);
  await sleep(1_600);
  await page.screenshot({
    path: path.join(outputDirectory, `${name}.png`),
    fullPage: false,
  });
  await sleep(1_600);
}

try {
  await page.goto(baseUrl, { waitUntil: "domcontentloaded", timeout: 60_000 });

  const username = page.getByTestId("username");
  if (await username.isVisible({ timeout: 10_000 }).catch(() => false)) {
    await username.fill("datahub");
    const password = page.getByTestId("password");
    await password.fill("datahub");
    await password.press("Enter");
    await waitForAnyText(["DataHub", "Search"], 45_000);
    await sleep(1_200);
  }

  await capture(
    "01-dataset-overview",
    entityUrl("dataset", datasetUrn),
    ["retention_scores", "retention scores"],
  );

  await capture(
    "02-governed-schema",
    entityUrl("dataset", datasetUrn, "Schema"),
    ["churn_score", "customer_id"],
  );

  await capture(
    "03-column-lineage",
    entityUrl("dataset", datasetUrn, "Lineage"),
    ["Lineage", "Upstream"],
  );

  await capture(
    "04-toxicjoin-decision",
    entityUrl("document", decisionUrn),
    ["ToxicJoin", "Decision", "Compositional Privacy"],
  );

  if (pageErrors.length) {
    throw new Error(`DataHub UI page errors: ${pageErrors.join(" | ")}`);
  }
} finally {
  await page.close();
  await context.close();
  await browser.close();
}

if (!video) {
  throw new Error("Playwright did not create a video recorder");
}
const recordedPath = await video.path();
const finalVideo = path.join(outputDirectory, "datahub-ui-capture.webm");
fs.copyFileSync(recordedPath, finalVideo);

const report = {
  schema_version: "1.0",
  created_at: new Date().toISOString(),
  resolution: "1920x1080",
  browser_executable: browserExecutable,
  datahub_ui_url: baseUrl,
  flagship_dataset_urn: datasetUrn,
  decision_document_urn: decisionUrn,
  screenshots: [
    "01-dataset-overview.png",
    "02-governed-schema.png",
    "03-column-lineage.png",
    "04-toxicjoin-decision.png",
  ],
  raw_video: "datahub-ui-capture.webm",
  page_error_count: 0,
};
fs.writeFileSync(
  path.join(outputDirectory, "capture-report.json"),
  `${JSON.stringify(report, null, 2)}\n`,
  "utf8",
);
console.log(JSON.stringify(report, null, 2));
